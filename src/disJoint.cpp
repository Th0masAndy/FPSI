#include "protocol.h"
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <format>
#include <iostream>
#include <thread>
#include <vector>
#include "OKVS.h"
#include "SiOPRF.h"
#include "SoOPPRF.h"
#include "common.h"
#include "filter.h"
#include "genData.h"
#include "mux.h"
#include "param.h"
#include "secure-join/Prf/AltModPrf.h"
#include "utils.h"

using namespace secJoin;

namespace {

struct FuzzyMapContext {
    const FpsiConfig &config;
    const PointSet &sendSet;
    const PointSet &recvSet;
    const std::vector<block> &sendPid;
    const std::vector<block> &recvPid;
    const std::vector<block> &sendOkvs;
    const std::vector<block> &recvOkvs;
    std::array<coproto::AsioSocket, 2> &sockets;
    std::array<coproto::AsioSocket, 2> &siOprfSockets;
    oc::Timer &timer;
};

struct FuzzyMapPrefixParams {
    const std::vector<u64> &prefixLengths;
    int prefixCount;
};

} // namespace

// to be fixed
void LocalMap(PointSet &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    PRNG prng(ZeroBlock);

    u64 m = inputs.size();
    u64 d = inputs[0].size();

    pid.resize(m);

    std::vector<std::vector<std::pair<u64, u64>>> intervals(d);

    std::vector<block> randR(m * d);
    prng.get<block>(randR.data(), randR.size());

    u64 maxInter = 0;

    // Merge overlapping intervals
    for (u64 i = 0; i < d; i++) {
        std::vector<std::pair<u64, u64>> interval;
        interval.reserve(m);

        // get interval [a_i - radius, a_i + radius]
        for (u64 j = 0; j < m; ++j) {
            interval.push_back({ inputs[j][i] - delta, inputs[j][i] + delta });
        }

        // Sort points by x-coordinate; if equal, sort by y-coordinate
        std::sort(interval.begin(), interval.end());

        for (auto [start, end] : interval) {
            // If intervals overlap, merge them
            // If no overlap, add the new interval
            if (!intervals[i].empty() && start <= intervals[i].back().second) {
                intervals[i].back().second = max(intervals[i].back().second, end);
            } else {
                intervals[i].emplace_back(start, end);
            }
            maxInter = max(intervals[i].back().second - intervals[i].back().first, maxInter);
        }
    }

    // gen Local ID

    auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
        return a.second < value; // Find the first interval where value <= interval.second
    };

    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < m; j++) {
            auto elem = inputs[j];

            auto it = std::lower_bound(intervals[i].begin(), intervals[i].end(), elem[i], compare_lambda);

            if (it != intervals[i].end() && it->first <= elem[i] && elem[i] <= it->second) {
                auto interval_index = distance(intervals[i].begin(), it);
                pid[j] ^= randR[i * m + interval_index];
            } else {
                std::cout << i << " " << elem[i] << std::endl;
                throw runtime_error("recv getID random error");
            }
        }
    }

    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < intervals[i].size(); j++) {
            auto [start, end] = intervals[i][j];
            for (u64 k = start; k <= end; k++) {
                block key = block(i, k);
                block val = randR[i * m + j];
                listKey.push_back(key);
                listVal.push_back(val);
            }
        }
    }

    if (listKey.size() > d * m * (2 * delta + 1)) {
        throw runtime_error("something wrong in LocalMap");
    }
    while (listKey.size() < d * m * (2 * delta + 1)) {
        listKey.push_back(prng.get<block>());
        listVal.push_back(prng.get<block>());
    }
    Hash(listKey);
}

void fuzzyMap(
    const FuzzyMapContext &context,
    std::vector<block> &recvIds,
    std::vector<block> &sendIds,
    const AltModPrf::KeyType &k0,
    const AltModPrf::KeyType &k1)
{
    const u64 n = context.config.n;
    const size_t d = context.config.dimension;
    const int delta = context.config.delta;
    const auto &sendSet = context.sendSet;
    const auto &recvSet = context.recvSet;
    const auto &sendPid = context.sendPid;
    const auto &recvPid = context.recvPid;
    const auto &sendOkvs = context.sendOkvs;
    const auto &recvOkvs = context.recvOkvs;
    auto &sockets = context.sockets;
    auto &siOprfSockets = context.siOprfSockets;
    auto &timer = context.timer;

    std::vector<block> rand_R_j(n);
    std::vector<block> rand_S_j(n);

    std::vector<block> reverseQueryKeys(n * d);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            reverseQueryKeys[i * d + j] = block(j, sendSet[i][j]);
        }
    }
    Hash(reverseQueryKeys);

    std::vector<block> reverseRecvShares(reverseQueryKeys.size());
    std::vector<block> reverseSendShares(reverseQueryKeys.size());
    runSoOpprf(
        recvOkvs,
        n * d * (2 * delta + 1),
        reverseQueryKeys,
        reverseRecvShares,
        reverseSendShares,
        sockets,
        true);

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            rand_S_j[i] ^= reverseSendShares[i * d + j];
            rand_R_j[i] ^= reverseRecvShares[i * d + j];
        }
        rand_S_j[i] ^= sendPid[i];
    }

    timer.setTimePoint("soOPRF Reverse done");

    std::thread sendSiOPRFReverse([&] {
        SiOPRFRecver siRecv(n, 1, false, &sockets[0], &siOprfSockets[0], k0);

        std::vector<block> share_S(n);

        siRecv.OPRF(rand_S_j, share_S);

        std::vector<block> share_R(n);

        coproto::sync_wait(sockets[0].recv(share_R));

        for (int i = 0; i < n; i++) {
            sendIds[i] = share_R[i] ^ share_S[i];
        }
    });

    std::thread recvSiOPRFReverse([&] {
        SiOPRFSender siSend(n, 1, false, &sockets[1], &siOprfSockets[1], k1);

        std::vector<block> share_R(n);

        siSend.OPRF(rand_R_j, share_R);

        coproto::sync_wait(sockets[1].send(share_R));
    });

    sendSiOPRFReverse.join();
    recvSiOPRFReverse.join();

    timer.setTimePoint("siOPRF Reverse done");

    rand_R_j = std::vector<block>(n, ZeroBlock);
    rand_S_j = std::vector<block>(n, ZeroBlock);

    std::vector<block> forwardQueryKeys(n * d);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            forwardQueryKeys[i * d + j] = block(j, recvSet[i][j]);
        }
    }
    Hash(forwardQueryKeys);

    std::vector<block> forwardRecvShares(forwardQueryKeys.size());
    std::vector<block> forwardSendShares(forwardQueryKeys.size());
    runSoOpprf(
        sendOkvs,
        n * d * (2 * delta + 1),
        forwardQueryKeys,
        forwardRecvShares,
        forwardSendShares,
        sockets);

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            rand_S_j[i] ^= forwardSendShares[i * d + j];
            rand_R_j[i] ^= forwardRecvShares[i * d + j];
        }
        rand_R_j[i] ^= recvPid[i];
    }

    timer.setTimePoint("soOPRF done");

    std::thread sendSiOPRF([&] {
        SiOPRFSender siSend(n, 1, false, &sockets[0], &siOprfSockets[0], k0);

        std::vector<block> share_S(n);

        siSend.OPRF(rand_S_j, share_S);

        coproto::sync_wait(sockets[0].send(share_S));
    });

    std::thread recvSiOPRF([&] {
        SiOPRFRecver siRecv(n, 1, false, &sockets[1], &siOprfSockets[1], k1);

        std::vector<block> share_R(n);

        siRecv.OPRF(rand_R_j, share_R);

        std::vector<block> share_S(n);

        coproto::sync_wait(sockets[1].recv(share_S));

        for (int i = 0; i < n; i++) {
            recvIds[i] = share_R[i] ^ share_S[i];
        }
    });

    sendSiOPRF.join();
    recvSiOPRF.join();

    timer.setTimePoint("siOPRF done");
}

void fuzzyPsiL0(const FpsiConfig &config)
{
    const u64 n = config.n;
    const size_t d = config.dimension;
    const int delta = config.delta;
    const bool verbose = config.verbose;
    const int numTry = config.trials;

    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(config, prng);
    auto &sendSet = testCase.sendSet;
    auto &recvSet = testCase.recvSet;
    const auto &interIndices = testCase.expectedOutputIndices;

    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    std::thread sendLocalMap([&] { LocalMap(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMap(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(n * d * (2 * delta + 1));
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);
    // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); i++) {
        sendListVal[i] = sendListVal[i] ^ senderPrfVals[i];
        recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto s = time.setTimePoint("offline preprocess OKVS done");

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();

    FuzzyMapContext fuzzyMapContext {
        config,
        sendSet,
        recvSet,
        sendPid,
        recvPid,
        senderOKVS,
        recverOKVS,
        sock,
        sock2,
        time,
    };

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        fuzzyMap(fuzzyMapContext, ID_R, ID_S, k0, k1);

        // fmap finish
        time.setTimePoint("fmap done");

        FilterContext filterContext { config, sendSet, recvSet, ID_S, ID_R, sock };
        NormalFilterL0 filter(filterContext);
        auto choiceBit = filter.run();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;
        transferElements(sendSet, choiceBit, matches, sock);

        if (verbose) {
            correctCheck(choiceBit, interIndices);
            std::cout << time << std::endl;
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    printFpsiResult("normal", "both", "disJoin", 0, d, delta, n, comm, comp);
}

void fuzzyPsiLp(const FpsiConfig &config)
{
    const u64 n = config.n;
    const size_t d = config.dimension;
    const int delta = config.delta;
    const int lp = config.metric;
    const bool verbose = config.verbose;
    const int numTry = config.trials;

    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(config, prng);
    auto &sendSet = testCase.sendSet;
    auto &recvSet = testCase.recvSet;
    const auto &interIndices = testCase.expectedOutputIndices;

    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    std::thread sendLocalMap([&] { LocalMap(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMap(recvSet, recvPid, recvListKey, recvListVal, delta); });

    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(n * d * (2 * delta + 1));
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);
    // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); i++) {
        sendListVal[i] = sendListVal[i] ^ senderPrfVals[i];
        recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto s = time.setTimePoint("offline preprocess OKVS done");

    auto sock = coproto::AsioSocket::makePair();
    auto sock2 = coproto::AsioSocket::makePair();

    FuzzyMapContext fuzzyMapContext {
        config,
        sendSet,
        recvSet,
        sendPid,
        recvPid,
        senderOKVS,
        recverOKVS,
        sock,
        sock2,
        time,
    };

    for (int tryIdx = 0; tryIdx < numTry; tryIdx++) {
        std::vector<block> ID_R(n);
        std::vector<block> ID_S(n);

        AltModPrf RO(prng.get());
        auto key = RO.mExpandedKey;
        AltModPrf::KeyType k1 = prng.get();
        AltModPrf::KeyType k0 = k1 ^ key;

        fuzzyMap(fuzzyMapContext, ID_R, ID_S, k0, k1);

        // fmap finish
        time.setTimePoint("fmap done");

        FilterContext filterContext { config, sendSet, recvSet, ID_S, ID_R, sock };
        NormalFilterLp filter(filterContext);
        auto choiceBit = filter.run();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;
        transferElements(sendSet, choiceBit, matches, sock);

        if (verbose) {
            correctCheck(choiceBit, interIndices);
            std::cout << time << std::endl;
        }
    }

    auto e = time.setTimePoint("OT done");

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent() + sock2[0].bytesReceived() + sock2[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    printFpsiResult("normal", "both", "disJoin", lp, d, delta, n, comm, comp);

}

// to be fixed
void LocalMapPrefix(PointSet &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    PRNG prng(sysRandomSeed());

    u64 m = inputs.size();
    u64 d = inputs[0].size();
    int prefixNum = prefixNumMap.at(2 * delta);
    auto U = prefixLenMap.at(2 * delta);

    pid.resize(m);

    std::vector<std::vector<std::pair<u64, u64>>> intervals(d);

    std::vector<block> randR(m * d);
    prng.get(randR.data(), randR.size());

    u64 maxInter = 0;

    // Merge overlapping intervals
    for (u64 i = 0; i < d; i++) {
        std::vector<std::pair<u64, u64>> interval;
        interval.reserve(m);

        // get interval [a_i - radius, a_i + radius]
        for (u64 j = 0; j < m; ++j) {
            interval.push_back({ inputs[j][i] - delta, inputs[j][i] + delta });
        }

        // Sort points by x-coordinate; if equal, sort by y-coordinate
        std::sort(interval.begin(), interval.end());

        for (auto [start, end] : interval) {
            // If intervals overlap, merge them
            // If no overlap, add the new interval
            if (!intervals[i].empty() && start <= intervals[i].back().second) {
                intervals[i].back().second = max(intervals[i].back().second, end);
            } else {
                intervals[i].emplace_back(start, end);
            }
            maxInter = max(intervals[i].back().second - intervals[i].back().first, maxInter);
        }
    }

    // gen Local ID

    auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
        return a.second < value; // Find the first interval where value <= interval.second
    };

    for (u64 j = 0; j < m; j++) {
        auto elem = inputs[j];
        for (u64 i = 0; i < d; i++) {
            auto it = std::lower_bound(intervals[i].begin(), intervals[i].end(), elem[i], compare_lambda);

            if (it != intervals[i].end() && it->first <= elem[i]) {
                auto interval_index = distance(intervals[i].begin(), it);
                pid[j] ^= randR[i * m + interval_index];
            } else {
                std::cout << i << " " << elem[i] << std::endl;
                throw runtime_error("recv getID random error");
            }
        }
    }

    // build listKey and listVal
    for (u64 i = 0; i < d; i++) {
        for (u64 j = 0; j < intervals[i].size(); j++) {
            auto [start, end] = intervals[i][j];
            auto randR_i_j = randR[i * m + j];
            u32 segNum = static_cast<u32>(std::ceil((end - start + 1) / double(2 * delta + 1))); // every sub interval at most length of (2*delta+1)
            for (u64 k = 0; k < segNum; k++) {
                u64 segStart = start + k * (2 * delta + 1);
                u64 segEnd = std::min(end, segStart + (2 * delta));
                auto prefixes = getIntervalPrefixSet(segStart, segEnd, U);
                for (auto &p : prefixes) {
                    block key = block(i << 32, 0) ^ p;
                    block val = ZeroBlock;
                    listKey.push_back(key);
                    listVal.push_back(val);
                    key = block((1 << 16) | (i << 32), 0) ^ p;
                    val = randR_i_j;
                    listKey.push_back(key);
                    listVal.push_back(val);
                }
            }
        }
    }

    if (listKey.size() > prefixNum * d * m * 2) {
        throw runtime_error("something wrong in LocalMapPrefix");
    }

    while (listKey.size() < prefixNum * d * m * 2) {
        listKey.push_back(prng.get<block>());
        listVal.push_back(prng.get<block>());
    }
    Hash(listKey);
}

void fuzzyMapPrefix(
    const FuzzyMapContext &context,
    const FuzzyMapPrefixParams &prefix,
    std::vector<block> &recvIds,
    std::vector<block> &sendIds,
    const AltModPrf::KeyType &k0,
    const AltModPrf::KeyType &k1)
{
    const u64 n = context.config.n;
    const size_t d = context.config.dimension;
    const int prefixLength = static_cast<int>(prefix.prefixLengths.size());
    const int prefixCount = prefix.prefixCount;
    const auto &prefixLengths = prefix.prefixLengths;
    const auto &sendSet = context.sendSet;
    const auto &recvSet = context.recvSet;
    const auto &sendPid = context.sendPid;
    const auto &recvPid = context.recvPid;
    const auto &sendOkvs = context.sendOkvs;
    const auto &recvOkvs = context.recvOkvs;
    auto &sockets = context.sockets;
    auto &siOprfSockets = context.siOprfSockets;
    auto &timer = context.timer;

    std::vector<block> rand_R_j(n);
    std::vector<block> rand_S_j(n);
    const u64 muxInputCount = n * d * prefixLength;
    const u64 opprfQueryCount = 2 * muxInputCount;
    const u64 numKeyValues = 2 * n * d * prefixCount;

    std::vector<block> reverseQueryKeys(opprfQueryCount);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            auto prefixes = getPrefixSet(sendSet[i][j], prefixLengths);
            for (int k = 0; k < prefixLength; ++k) {
                reverseQueryKeys[i * d * prefixLength + j * prefixLength + k] =
                    block(j << 32, 0) ^ prefixes[k];
                reverseQueryKeys[(n + i) * d * prefixLength + j * prefixLength + k] =
                    block((1 << 16) | (j << 32), 0) ^ prefixes[k];
            }
        }
    }
    Hash(reverseQueryKeys);

    std::vector<block> reverseRecvShares(reverseQueryKeys.size());
    std::vector<block> reverseSendShares(reverseQueryKeys.size());
    runSoOpprf(
        recvOkvs,
        numKeyValues,
        reverseQueryKeys,
        reverseRecvShares,
        reverseSendShares,
        sockets,
        true);

    std::vector<block> reverseSendU(reverseSendShares.begin(), reverseSendShares.begin() + muxInputCount);
    std::vector<block> reverseSendV(reverseSendShares.begin() + muxInputCount, reverseSendShares.end());
    std::vector<block> reverseRecvU(reverseRecvShares.begin(), reverseRecvShares.begin() + muxInputCount);
    std::vector<block> reverseRecvV(reverseRecvShares.begin() + muxInputCount, reverseRecvShares.end());
    std::vector<block> reverseSendSelected(n * d);
    std::vector<block> reverseRecvSelected(n * d);

    std::thread reverseSendMux([&] {
        MuxSender mux(muxInputCount, &sockets[0]);
        mux.EqSel(reverseSendU, reverseSendV, reverseSendSelected, prefixLength);
    });
    std::thread reverseRecvMux([&] {
        MuxRecver mux(muxInputCount, &sockets[1]);
        mux.EqSel(reverseRecvU, reverseRecvV, reverseRecvSelected, prefixLength);
    });
    reverseSendMux.join();
    reverseRecvMux.join();

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            rand_S_j[i] ^= reverseSendSelected[i * d + j];
            rand_R_j[i] ^= reverseRecvSelected[i * d + j];
        }
        rand_S_j[i] ^= sendPid[i];
    }

    timer.setTimePoint("soOPRF Reverse done");

    std::thread sendSiOPRFReverse([&] {
        SiOPRFRecver siRecv(n, 1, false, &sockets[0], &siOprfSockets[0], k0);

        std::vector<block> share_S(n);

        siRecv.OPRF(rand_S_j, share_S);

        std::vector<block> share_R(n);

        coproto::sync_wait(sockets[0].recv(share_R));

        for (int i = 0; i < n; i++) {
            sendIds[i] = share_R[i] ^ share_S[i];
        }
    });

    std::thread recvSiOPRFReverse([&] {
        SiOPRFSender siSend(n, 1, false, &sockets[1], &siOprfSockets[1], k1);

        std::vector<block> share_R(n);

        siSend.OPRF(rand_R_j, share_R);

        coproto::sync_wait(sockets[1].send(share_R));
    });

    sendSiOPRFReverse.join();
    recvSiOPRFReverse.join();

    timer.setTimePoint("siOPRF Reverse done");

    rand_R_j = std::vector<block>(n, ZeroBlock);
    rand_S_j = std::vector<block>(n, ZeroBlock);

    std::vector<block> forwardQueryKeys(opprfQueryCount);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            auto prefixes = getPrefixSet(recvSet[i][j], prefixLengths);
            for (int k = 0; k < prefixLength; ++k) {
                forwardQueryKeys[i * d * prefixLength + j * prefixLength + k] =
                    block(j << 32, 0) ^ prefixes[k];
                forwardQueryKeys[(n + i) * d * prefixLength + j * prefixLength + k] =
                    block((1 << 16) | (j << 32), 0) ^ prefixes[k];
            }
        }
    }
    Hash(forwardQueryKeys);

    std::vector<block> forwardRecvShares(forwardQueryKeys.size());
    std::vector<block> forwardSendShares(forwardQueryKeys.size());
    runSoOpprf(
        sendOkvs,
        numKeyValues,
        forwardQueryKeys,
        forwardRecvShares,
        forwardSendShares,
        sockets);

    std::vector<block> forwardSendU(forwardSendShares.begin(), forwardSendShares.begin() + muxInputCount);
    std::vector<block> forwardSendV(forwardSendShares.begin() + muxInputCount, forwardSendShares.end());
    std::vector<block> forwardRecvU(forwardRecvShares.begin(), forwardRecvShares.begin() + muxInputCount);
    std::vector<block> forwardRecvV(forwardRecvShares.begin() + muxInputCount, forwardRecvShares.end());
    std::vector<block> forwardSendSelected(n * d);
    std::vector<block> forwardRecvSelected(n * d);

    std::thread forwardSendMux([&] {
        MuxSender mux(muxInputCount, &sockets[0]);
        mux.EqSel(forwardSendU, forwardSendV, forwardSendSelected, prefixLength);
    });
    std::thread forwardRecvMux([&] {
        MuxRecver mux(muxInputCount, &sockets[1]);
        mux.EqSel(forwardRecvU, forwardRecvV, forwardRecvSelected, prefixLength);
    });
    forwardSendMux.join();
    forwardRecvMux.join();

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            rand_S_j[i] ^= forwardSendSelected[i * d + j];
            rand_R_j[i] ^= forwardRecvSelected[i * d + j];
        }
        rand_R_j[i] ^= recvPid[i];
    }

    timer.setTimePoint("soOPRF done");

    std::thread sendSiOPRF([&] {
        SiOPRFSender siSend(n, 1, false, &sockets[0], &siOprfSockets[0], k0);

        std::vector<block> share_S(n);

        siSend.OPRF(rand_S_j, share_S);

        coproto::sync_wait(sockets[0].send(share_S));
    });

    std::thread recvSiOPRF([&] {
        SiOPRFRecver siRecv(n, 1, false, &sockets[1], &siOprfSockets[1], k1);

        std::vector<block> share_R(n);

        siRecv.OPRF(rand_R_j, share_R);

        std::vector<block> share_S(n);

        coproto::sync_wait(sockets[1].recv(share_S));

        for (int i = 0; i < n; i++) {
            recvIds[i] = share_R[i] ^ share_S[i];
        }
    });

    sendSiOPRF.join();
    recvSiOPRF.join();

    timer.setTimePoint("siOPRF done");
}

void fuzzyPsiPrefixL0(const FpsiConfig &config)
{
    const u64 n = config.n;
    const size_t d = config.dimension;
    const int delta = config.delta;
    const bool verbose = config.verbose;
    const int numTry = config.trials;

    auto prefixLengths = prefixLenMap.at(2 * delta);
    const int prefixCount = prefixNumMap.at(2 * delta);

    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(config, prng);
    auto &sendSet = testCase.sendSet;
    auto &recvSet = testCase.recvSet;
    const auto &interIndices = testCase.expectedOutputIndices;

    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    std::thread sendLocalMap([&] { LocalMapPrefix(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMapPrefix(recvSet, recvPid, recvListKey, recvListVal, delta); });
    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(2 * n * d * prefixCount);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);

    oc::Timer time;
    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); ++i) {
        sendListVal[i] ^= senderPrfVals[i];
        recvListVal[i] ^= recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);
    auto start = time.setTimePoint("offline preprocess OKVS done");

    auto sockets = coproto::AsioSocket::makePair();
    auto mapSockets = coproto::AsioSocket::makePair();
    FuzzyMapContext fuzzyMapContext {
        config,
        sendSet,
        recvSet,
        sendPid,
        recvPid,
        senderOKVS,
        recverOKVS,
        sockets,
        mapSockets,
        time,
    };
    FuzzyMapPrefixParams fuzzyMapPrefixParams { prefixLengths, prefixCount };
    PrefixFilterParams filterParams { prefixLengths, static_cast<u64>(prefixCount) };

    for (int tryIndex = 0; tryIndex < numTry; ++tryIndex) {
        std::vector<block> receiverIds(n);
        std::vector<block> senderIds(n);

        AltModPrf randomOracle(prng.get());
        auto key = randomOracle.mExpandedKey;
        AltModPrf::KeyType key1 = prng.get();
        AltModPrf::KeyType key0 = key1 ^ key;

        fuzzyMapPrefix(
            fuzzyMapContext, fuzzyMapPrefixParams,
            receiverIds, senderIds, key0, key1);

        time.setTimePoint("fmap-prefix done");

        FilterContext filterContext { config, sendSet, recvSet, senderIds, receiverIds, sockets };
        PrefixFilterL0 filter(filterContext, filterParams);
        auto choiceBits = filter.run();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;
        transferElements(sendSet, choiceBits, matches, sockets);

        if (verbose) {
            correctCheck(choiceBits, interIndices);
            std::cout << time << std::endl;
        }
    }

    auto end = time.setTimePoint("OT done");
    auto communication = (sockets[0].bytesReceived() + sockets[0].bytesSent()
                             + mapSockets[0].bytesReceived() + mapSockets[0].bytesSent())
        / 1024.0 / 1024.0;
    auto computation = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
        / double(1000 * 1000);

    computation /= numTry;
    communication /= numTry;
    printFpsiResult("prefix", "both", "disJoin", 0, d, delta, n, communication, computation);
}

void fuzzyPsiPrefixLp(const FpsiConfig &config)
{
    const u64 n = config.n;
    const size_t d = config.dimension;
    const int delta = config.delta;
    const int lp = config.metric;
    const bool verbose = config.verbose;
    const int numTry = config.trials;

    auto mapPrefixLengths = prefixLenMap.at(2 * delta);
    const int mapPrefixCount = prefixNumMap.at(2 * delta);
    auto filterPrefixLengths = prefixLenMap.at(delta);
    const int filterPrefixCount = 2 * prefixNumMap.at(delta);

    std::vector<block> sendPid;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;

    PRNG prng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(config, prng);
    auto &sendSet = testCase.sendSet;
    auto &recvSet = testCase.recvSet;
    const auto &interIndices = testCase.expectedOutputIndices;

    std::vector<block> recvPid;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;

    std::thread sendLocalMap([&] { LocalMapPrefix(sendSet, sendPid, sendListKey, sendListVal, delta); });
    std::thread recvLocalMap([&] { LocalMapPrefix(recvSet, recvPid, recvListKey, recvListVal, delta); });
    sendLocalMap.join();
    recvLocalMap.join();

    auto preOKVS = OKVS(2 * n * d * mapPrefixCount);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey);

    oc::Timer time;
    time.setTimePoint("begin");

    std::vector<block> senderPrfVals(sendListKey.size());
    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(sendListKey, senderPrfVals);
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); ++i) {
        sendListVal[i] ^= senderPrfVals[i];
        recvListVal[i] ^= recverPrfVals[i];
    }

    auto senderOKVS = preOKVS.encode(sendListKey, sendListVal);
    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);
    auto start = time.setTimePoint("offline preprocess OKVS done");

    auto sockets = coproto::AsioSocket::makePair();
    auto mapSockets = coproto::AsioSocket::makePair();
    FuzzyMapContext fuzzyMapContext {
        config,
        sendSet,
        recvSet,
        sendPid,
        recvPid,
        senderOKVS,
        recverOKVS,
        sockets,
        mapSockets,
        time,
    };
    FuzzyMapPrefixParams fuzzyMapPrefixParams { mapPrefixLengths, mapPrefixCount };
    PrefixFilterParams filterParams { filterPrefixLengths, static_cast<u64>(filterPrefixCount) };

    for (int tryIndex = 0; tryIndex < numTry; ++tryIndex) {
        std::vector<block> receiverIds(n);
        std::vector<block> senderIds(n);

        AltModPrf randomOracle(prng.get());
        auto key = randomOracle.mExpandedKey;
        AltModPrf::KeyType key1 = prng.get();
        AltModPrf::KeyType key0 = key1 ^ key;

        fuzzyMapPrefix(
            fuzzyMapContext, fuzzyMapPrefixParams,
            receiverIds, senderIds, key0, key1);

        time.setTimePoint("fmap-prefix done");

        FilterContext filterContext { config, sendSet, recvSet, senderIds, receiverIds, sockets };
        PrefixFilterLp filter(filterContext, filterParams);
        auto choiceBits = filter.run();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;
        transferElements(sendSet, choiceBits, matches, sockets);

        if (verbose) {
            correctCheck(choiceBits, interIndices);
            std::cout << time << std::endl;
        }
    }

    auto end = time.setTimePoint("OT done");
    auto communication = (sockets[0].bytesReceived() + sockets[0].bytesSent()
                             + mapSockets[0].bytesReceived() + mapSockets[0].bytesSent())
        / 1024.0 / 1024.0;
    auto computation = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
        / double(1000 * 1000);

    computation /= numTry;
    communication /= numTry;
    printFpsiResult("prefix", "both", "disJoin", lp, d, delta, n, communication, computation);
}
