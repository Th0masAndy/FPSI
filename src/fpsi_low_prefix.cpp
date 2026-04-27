#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstddef>
#include <format>
#include <iostream>
#include <thread>
#include <vector>
#include "OKVS.h"
#include "SoOPPRF.h"
#include "b2a.h"
#include "common.h"
#include "eq.h"
#include "fpsi_low.h"
#include "math.h"
#include "mul.h"
#include "mux.h"
#include "param.h"
#include "secure-join/Prf/AltModPrf.h"
#include "utils.h"

void preProcessPrefix(std::vector<std::vector<u64>> &inputs, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    PRNG prng(oc::sysRandomSeed());
    int d = inputs[0].size();
    for (size_t i = 0; i < inputs.size(); i++) {
        auto neighbors = neigh(inputs[i], delta);
        for (int j = 0; j < d; j++) {
            auto prefixes = getIntervalPrefixSet(inputs[i][j] - delta, inputs[i][j] + delta, prefixLenMapNaive.at(2 * delta));
            for (auto prefix : prefixes) {
                for (auto neighbor : neighbors) {
                    listKey.push_back(blake3_hash(neighbor, j, prefix)); // placeholder
                    listVal.push_back(ZeroBlock);
                }
            }
        }
    }
}

void fuzzyPsiLow4DeltaPx(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int LOG = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int prefixNum = static_cast<int>(std::ceil(std::log2(delta * 2 + 1)));
    int prefixLen = static_cast<int>(std::floor(std::log2(delta * 2 + 1))) + 1;
    int interSize = cmd.getOr("nn", 4);

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;
    std::vector<block> rand_R(n);
    std::vector<std::vector<u64>> sendSet;
    std::vector<block> rand_S(n);

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        sendSet.push_back(tmp);
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        recvSet.push_back(tmp);
    }

    std::vector<u64> interIndices;
    while (interIndices.size() < interSize) {
        u64 idx = prng.get<u64>() % n;
        if (std::find(interIndices.begin(), interIndices.end(), idx) == interIndices.end()) {
            interIndices.push_back(idx);
        }
    }

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (delta + 1));
        }
    }

    // auto preOKVS = OKVS(n * d * (1 << d) * prefixNum);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey); // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    // preProcessPrefix(recvSet, recvListKey, recvListVal, delta);
    {
        PRNG prng(sysRandomSeed());
        int d = recvSet[0].size();
        for (size_t i = 0; i < recvSet.size(); i++) {
            auto neighbors = neigh(recvSet[i], delta);
            for (int j = 0; j < d; j++) {
                auto prefixes = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] + delta, prefixLenMapNaive.at(2 * delta));
                for (auto prefix : prefixes) {
                    for (auto neighbor : neighbors) {
                        recvListKey.push_back(blake3_hash(neighbor, j, prefix)); // placeholder
                        recvListVal.push_back(ZeroBlock);
                    }
                }
            }
        }

        while (recvListKey.size() < n * d * prefixNum) {
            recvListKey.push_back(prng.get<block>());
            recvListVal.push_back(prng.get<block>());
        }
    }

    // std::vector<block> recverPrfVals(recvListKey.size());
    // prf.eval(recvListKey, recverPrfVals);
    // for (size_t i = 0; i < sendListKey.size(); i++) {
    //     recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    // }

    // auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto sock = coproto::AsioSocket::makePair();

    std::vector<block> e_S(n * d * prefixLen);
    std::vector<block> e_R(n * d * prefixLen);

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * prefixLen, (1 << d) * d * n * prefixNum, 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);
        });

        std::thread sendOPPRF([&] {
            SoOPPRFRecver recv(n * d * prefixLen, (1 << d) * d * n * prefixNum, 1, false, &sock[1]);

            std::vector<block> inputs(n * d * prefixLen);
            for (u64 i = 0; i < n; i++) {
                auto cell_id = cell(sendSet[i], 2 * delta);
                for (u64 j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], prefixLenMapNaive.at(2 * delta));
                    for (int k = 0; k < prefixLen; k++) {
                        inputs[i * d * prefixLen + j * prefixLen + k] = blake3_hash(cell_id, j, prefixes[k]);
                    }
                }
            }

            recv.OPPRF(inputs, e_S);
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread recvMux([&] {
            MuxRecver mux(n * d, &sock[0]);
            std::vector<block> t(n * d);
            mux.mux(e_R, t, prefixLen);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R[i] ^= t[i * d + j];
                }
            }
        });

        std::thread sendMux([&] {
            MuxSender mux(n * d, &sock[1]);
            std::vector<block> t(n * d);
            mux.mux(e_S, t, prefixLen);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S[i] ^= t[i * d + j];
                }
            }
        });

        sendMux.join();
        recvMux.join();
        time.setTimePoint("Mux done");

        std::thread sendEQT([&] {
            PEqTSender eqSend(n, 1, false, &sock[0]);
            eqSend.eq(rand_S);
        });

        std::vector<u8> choiceBit(n, 0);

        std::thread recvEQT([&] {
            PEqTRecver eqRecv(n, 1, false, &sock[1]);

            std::vector<u64> intersection;
            eqRecv.eq(rand_R, intersection);

            for (auto &v : intersection) {
                choiceBit[v] = 1;
            }
        });

        sendEQT.join();
        recvEQT.join();

        time.setTimePoint("EQT done");

        std::thread sendOT([&] {
            SilentOtExtSender send;
            send.configure(n, 128);
            send.mMultType = type;

            coproto::sync_wait(send.genSilentBaseOts(prng, sock[0]));

            std::vector<std::array<block, 2>> messages(n);

            coproto::sync_wait(send.send(messages, prng, sock[0]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            PRNG prng0, prng1;
            for (int i = 0; i < n; i++) {
                prng0.SetSeed(messages[i][0]);
                prng1.SetSeed(messages[i][1]);
                for (int j = 0; j < d / 2; j++) {
                    correctMessages[i * d + j * 2] = prng0.get<block>();
                    correctMessages[i * d + j * 2 + 1] = block(sendSet[i][j * 2], sendSet[i][j * 2 + 1]) ^ prng0.get<block>();
                }
            }
            coproto::sync_wait(sock[0].send(correctMessages));
        });

        std::vector<std::vector<block>> matches;

        std::thread recvOT([&] {
            SilentOtExtReceiver recv;
            recv.configure(n, 128);
            recv.mMultType = type;

            coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

            std::vector<block> messages(n);
            BitVector choices(choiceBit.data(), choiceBit.size());

            coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

            std::vector<block> correctMessages(n * d / 2 * 2);
            coproto::sync_wait(sock[1].recv(correctMessages));

            PRNG prng;
            for (int i = 0; i < n; i++) {
                if (choiceBit[i]) {
                    prng.SetSeed(messages[i]);
                    std::vector<block> element;
                    for (int j = 0; j < d / 2; j++) {
                        block val = prng.get<block>() ^ correctMessages[i * d + j * 2 + 1];
                        element.push_back(val);
                    }
                    matches.push_back(element);
                }
            }
        });

        sendOT.join();
        recvOT.join();

        if (LOG) {
            for (int i = 0; i < choiceBit.size(); i++) {
                if (choiceBit[i]) {
                    std::cout << "intersection at index " << i << std::endl;
                }
                if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
                    throw runtime_error("false positive in fuzzyPsi");
                }
            }
            std::cout << "All matches found!" << std::endl;
        }
    }

    auto e = time.setTimePoint("OT done");

    if (LOG) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low-px]    L0    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}

void fuzzyPsiLow4DeltaLpPx(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    int LOG = cmd.getOr("v", 0);
    u64 delta_p = std::pow(delta, lp);

    int numTry = cmd.getOr("try", 1);

    int prefixNum = static_cast<int>(std::ceil(std::log2(delta * 2 + 1)));
    int prefixLen = static_cast<int>(std::floor(std::log2(delta * 2 + 1))) + 1;

    int prefixLenIfmat = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

    auto U_prime = prefixLenMapNaive.at(delta);
    int prefixLenUpDown = 2 * U_prime.size();
    int prefixNumUpDown = 2 * prefixNumMapNaive.at(delta);

    int interSize = cmd.getOr("nn", 4);

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;
    std::vector<block> rand_R(n);
    std::vector<std::vector<u64>> sendSet;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;
    std::vector<block> rand_S(n);

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        sendSet.push_back(tmp);
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        recvSet.push_back(tmp);
    }

    std::vector<u64> interIndices;
    while (interIndices.size() < interSize) {
        u64 idx = prng.get<u64>() % n;
        if (std::find(interIndices.begin(), interIndices.end(), idx) == interIndices.end()) {
            interIndices.push_back(idx);
        }
    }

    int averageDiff = (lp == 2) ? std::floor(delta * 1.0 / std::sqrt(d)) : std::floor(delta * 1.0 / d);

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (averageDiff + 1));
        }
    }

    auto preOKVS = OKVS(n * d * (1 << d) * prefixNum);
    AltModPrf::KeyType senderKey = AltModPrf::KeyType({
        block(0, 1),
        block(0, 2),
        block(0, 3),
        block(0, 4),
    });
    AltModPrf prf(senderKey); // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    // preProcessPrefix(recvSet, recvListKey, recvListVal, delta);

    // std::vector<block> recverPrfVals(recvListKey.size());
    // prf.eval(recvListKey, recverPrfVals);
    // for (size_t i = 0; i < sendListKey.size(); i++) {
    //     recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    // }

    // auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto sock = coproto::AsioSocket::makePair();

    std::vector<block> e_S(n * d * prefixLen);
    std::vector<block> e_R(n * d * prefixLen);

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<u8> choiceBit(n, 0);

        std::vector<u64> disR(n, 0);
        std::vector<u64> disS(n, 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;

        int OkvsBatch = lp / 2 + 1;
        int halfprefixLen = prefixLenUpDown / 2;
        int halfprefixNum = prefixNumUpDown / 2;

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d * halfprefixLen * 2 * OkvsBatch);

            for (int batch = 0; batch < OkvsBatch; batch++) {
                for (int i = 0; i < n; i++) {
                    auto cell_id = cell(sendSet[i], 2 * delta);
                    for (int j = 0; j < d; j++) {
                        auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                        for (int s = 0; s < 2; s++) {
                            for (int k = 0; k < halfprefixLen; k++) {
                                auto idx = batch * n * d * halfprefixLen * 2 + i * d * halfprefixLen * 2 + j * halfprefixLen * 2 + s * halfprefixLen + k;
                                //  batch, i, j, s, k
                                inputs[idx] = blake3_hash(cell_id, (j << 8) | (batch << 6) | (s << 4), prefixes[k]);
                            }
                        }
                    }
                }
            }

            SoOPPRFRecver recv(OkvsBatch * n * d * 2 * halfprefixLen, OkvsBatch * n * d * (1 << d) * 2 * halfprefixNum, 1, false, &sock[0]);

            std::vector<block> rand_S(OkvsBatch * n * d * 2 * halfprefixLen);

            recv.OPPRF(inputs, rand_S);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown * lp);

            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_S[i]));
            }
            if (lp == 1) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_S[i]));
                }
            } else if (lp == 2) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_S[i]));
                }
                for (u64 i = 1 * n * d * 2 * halfprefixLen; i < 2 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, high(rand_S[i]));
                }
            } else {
                throw std::runtime_error("lp not supported");
            }

            std::vector<u64> v_A(n * d * prefixLenUpDown * lp);

            oc::Timer localTime;

            auto start = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(n * d * prefixLenUpDown * lp, &sock[0]);
            b2aSender.b2a(v, v_A);

            auto end = localTime.setTimePoint("b2a done");

            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);

            // std::cout << "b2a time: " << dt << " ms" << std::endl;

            std::vector<u64> sumDis(n * d * 2 * halfprefixLen, 0);
            std::vector<u64> e(n * d * 2 * halfprefixLen, 0);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                    for (int s = 0; s < 2; s++) {
                        for (int k = 0; k < halfprefixLen; k++) {
                            e[i * d * prefixLenUpDown + j * prefixLenUpDown + s * halfprefixLen + k] =
                                (s == 0) ? upBound(prefixes[k]) - sendSet[i][j] : sendSet[i][j] - upBound(prefixes[k]);
                        }
                    }
                }
            }

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i] + e[i];
                }
            }
            if (lp == 2) {
                MulSender mulSender(n * d * prefixLenUpDown, &sock[0]);
                std::vector<u64> product(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_1(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_2(n * d * prefixLenUpDown, 0);

                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v_A_1[i] = v_A[i];
                    v_A_2[i] = v_A[i + 1 * n * d * 2 * halfprefixLen];
                }

                mulSender.mul(e, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = e[i] * e[i] + 2 * e[i] * v_A_1[i] + 2 * product[i] + v_A_2[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxSender mux(n * d * prefixLenUpDown, &sock[0]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disS[i] += rand_i_j[i * d + j];
                }
                // disS[i] = v_A[i];
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() != (n * prefixLenIfmat)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * prefixLenIfmat, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey;
            std::vector<block> filterVal;

            for (int i = 0; i < n; i++) {
                auto neighbors = neigh(recvSet[i], delta);
                for (int j = 0; j < d; j++) {
                    auto prefixes0 = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] - 1, U_prime);
                    auto prefixes1 = getIntervalPrefixSet(recvSet[i][j], recvSet[i][j] + delta, U_prime);
                    for (auto &p : prefixes0) {
                        auto upbound = upBound(p);
                        for (int batch = 0; batch < OkvsBatch; batch++) {
                            for (auto neighbor : neighbors) {
                                block key = blake3_hash(neighbor, (j << 8) | (batch << 6) | (0 << 4), p);
                                block val = ZeroBlock;
                                if (batch == 0) {
                                    val = block(0, std::pow(recvSet[i][j] - upbound, batch + 1));
                                } else {
                                    val = block(std::pow(recvSet[i][j] - upbound, batch + 1), 0);
                                }
                                filterKey.push_back(key);
                                filterVal.push_back(val);
                            }
                        }
                    }
                    for (auto &p : prefixes1) {
                        auto upbound = upBound(p);
                        for (int batch = 0; batch < OkvsBatch; batch++) {
                            for (auto neighbor : neighbors) {
                                block key = blake3_hash(neighbor, (j << 8) | (batch << 6) | (1 << 4), p);
                                block val = ZeroBlock;
                                if (batch == 0) {
                                    val = block(0, std::pow(upbound - recvSet[i][j], batch + 1));
                                } else {
                                    val = block(std::pow(upbound - recvSet[i][j], batch + 1), 0);
                                }
                                filterKey.push_back(key);
                                filterVal.push_back(val);
                            }
                        }
                    }
                }
            }

            if (filterKey.size() > n * d * (1 << d) * prefixNumUpDown * OkvsBatch) {
                throw std::runtime_error("filterKey size wrong");
            }

            while (filterKey.size() < n * d * (1 << d) * prefixNumUpDown * OkvsBatch) {
                filterKey.push_back(prng.get<block>());
                filterVal.push_back(prng.get<block>());
            }

            if (filterVal.size() != n * d * (1 << d) * prefixNumUpDown * OkvsBatch) {
                throw std::runtime_error("filterVal size wrong");
            }

            SoOPPRFSender send(n * d * prefixLenUpDown * OkvsBatch, n * d * (1 << d) * prefixNumUpDown * OkvsBatch, 1, false, &sock[1]);

            std::vector<block> rand_R(n * d * prefixLenUpDown * OkvsBatch);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown * lp);

            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_R[i]));
            }
            if (lp == 1) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_R[i]));
                }
            } else if (lp == 2) {
                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, low(rand_R[i]));
                }
                for (u64 i = 1 * n * d * 2 * halfprefixLen; i < 2 * n * d * 2 * halfprefixLen; i++) {
                    v[i] = block(0, high(rand_R[i]));
                }
            } else {
                throw std::runtime_error("lp not supported");
            }

            std::vector<u64> v_A(n * d * prefixLenUpDown * lp);

            B2aRecver b2aRecver(n * d * prefixLenUpDown * lp, &sock[1]);
            b2aRecver.b2a(v, v_A);

            std::vector<u64> sumDis(n * d * prefixLenUpDown, 0);

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i];
                }
            }
            if (lp == 2) {
                MulRecver mulRecver(n * d * prefixLenUpDown, &sock[1]);
                std::vector<u64> product(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_1(n * d * prefixLenUpDown, 0);
                std::vector<u64> v_A_2(n * d * prefixLenUpDown, 0);

                for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                    v_A_1[i] = v_A[i];
                    v_A_2[i] = v_A[i + 1 * n * d * 2 * halfprefixLen];
                }

                mulRecver.mul(v_A_1, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = 2 * product[i] + v_A_2[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxRecver mux(n * d * prefixLenUpDown, &sock[1]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disR[i] += rand_i_j[i * d + j];
                }
                // disR[i] = v_A[i];
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getPrefix(disR[i], prefixLenIfmat);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * prefixLenIfmat, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLenIfmat] = 1;
            }
        });

        sendFilter.join();
        recvFilter.join();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;

        transferElements(sendSet, choiceBit, matches, sock);

        if (LOG) {
            correctCheck(choiceBit, interIndices);
        }
    }

    auto e = time.setTimePoint("OT done");

    if (LOG) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low]    L0    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}

void fuzzyPsiLow4DeltaLpPxAug(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    int LOG = cmd.getOr("v", 0);
    u64 delta_p = std::pow(delta, lp);

    int numTry = cmd.getOr("try", 1);

    int prefixNum = static_cast<int>(std::ceil(std::log2(delta * 2 + 1)));
    int prefixLen = static_cast<int>(std::floor(std::log2(delta * 2 + 1))) + 1;

    int prefixLenIfmat = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

    auto U_prime = prefixLenMapNaive.at(delta);
    int prefixLenUpDown = 2 * U_prime.size();
    int prefixNumUpDown = 2 * prefixNumMapNaive.at(delta);

    int interSize = cmd.getOr("nn", 4);

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;
    std::vector<block> rand_R(n);
    std::vector<std::vector<u64>> sendSet;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;
    std::vector<block> rand_S(n);

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        sendSet.push_back(tmp);
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d - 1; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        tmp.push_back(prng.get<u64>() + 2 * delta); // make sure there are some differences
        recvSet.push_back(tmp);
    }

    std::vector<u64> interIndices;
    while (interIndices.size() < interSize) {
        u64 idx = prng.get<u64>() % n;
        if (std::find(interIndices.begin(), interIndices.end(), idx) == interIndices.end()) {
            interIndices.push_back(idx);
        }
    }

    int averageDiff = (lp == 2) ? std::floor(delta * 1.0 / std::sqrt(d)) : std::floor(delta * 1.0 / d);

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (averageDiff + 1));
        }
    }

    // auto preOKVS = OKVS(n * d * (1 << d) * prefixNum);
    // AltModPrf::KeyType senderKey = AltModPrf::KeyType({
    //     block(0, 1),
    //     block(0, 2),
    //     block(0, 3),
    //     block(0, 4),
    // });
    // AltModPrf prf(senderKey); // local encoding from set, totally offline

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    // preProcessPrefix(recvSet, recvListKey, recvListVal, delta);

    // std::vector<block> recverPrfVals(recvListKey.size());
    // prf.eval(recvListKey, recverPrfVals);
    // for (size_t i = 0; i < sendListKey.size(); i++) {
    //     recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    // }

    // auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto sock = coproto::AsioSocket::makePair();

    std::vector<block> e_S(n * d * prefixLen);
    std::vector<block> e_R(n * d * prefixLen);

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<u8> choiceBit(n, 0);

        std::vector<u64> disR(n, 0);
        std::vector<u64> disS(n, 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;

        int halfprefixLen = prefixLenUpDown / 2;
        int halfprefixNum = prefixNumUpDown / 2;

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d * halfprefixLen * 2);

            {
                for (int i = 0; i < n; i++) {
                    auto cell_id = cell(sendSet[i], 2 * delta);
                    for (int j = 0; j < d; j++) {
                        auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                        for (int s = 0; s < 2; s++) {
                            for (int k = 0; k < halfprefixLen; k++) {
                                auto idx = i * d * halfprefixLen * 2 + j * halfprefixLen * 2 + s * halfprefixLen + k;
                                // i, j, s, k
                                inputs[idx] = blake3_hash(cell_id, (j << 8) | (s << 4), prefixes[k]);
                            }
                        }
                    }
                }
            }

            SoOPPRFRecver recv(n * d * 2 * halfprefixLen, n * d * (1 << d) * 2 * halfprefixNum, 1, false, &sock[0]);

            std::vector<block> rand_S(n * d * 2 * halfprefixLen);

            recv.OPPRF(inputs, rand_S);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown);

            for (u64 i = 0; i < n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_S[i]));
            }
            for (u64 i = 0; i < n * d * 2 * halfprefixLen; i++) {
                v[i] = block(0, low(rand_S[i]));
            }

            std::vector<u64> v_A(n * d * prefixLenUpDown);

            oc::Timer localTime;

            auto start = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(n * d * prefixLenUpDown, &sock[0]);
            b2aSender.b2a(v, v_A);

            auto end = localTime.setTimePoint("b2a done");

            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);

            if (LOG) {
                std::cout << "b2a time: " << dt << " ms" << std::endl;
            }

            std::vector<u64> sumDis(n * d * 2 * halfprefixLen, 0);
            std::vector<u64> e(n * d * 2 * halfprefixLen, 0);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                    for (int s = 0; s < 2; s++) {
                        for (int k = 0; k < halfprefixLen; k++) {
                            e[i * d * prefixLenUpDown + j * prefixLenUpDown + s * halfprefixLen + k] =
                                (s == 0) ? upBound(prefixes[k]) - sendSet[i][j] : sendSet[i][j] - upBound(prefixes[k]);
                        }
                    }
                }
            }

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i] + e[i];
                }
            }
            if (lp == 2) {
                MulSender mulSender(n * d * prefixLenUpDown, &sock[0]);

                std::vector<u64> shares(sumDis.size(), 0);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    shares[i] = v_A[i] + e[i];
                }

                std::vector<u64> product(n * d * prefixLenUpDown, 0);

                mulSender.mul(shares, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = shares[i] * shares[i] + 2 * product[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxSender mux(n * d * prefixLenUpDown, &sock[0]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disS[i] += rand_i_j[i * d + j];
                }
                // disS[i] = v_A[i];
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() != (n * prefixLenIfmat)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * prefixLenIfmat, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey;
            std::vector<block> filterVal;

            for (int i = 0; i < n; i++) {
                auto neighbors = neigh(recvSet[i], delta);
                for (int j = 0; j < d; j++) {
                    auto prefixes0 = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] - 1, U_prime);
                    auto prefixes1 = getIntervalPrefixSet(recvSet[i][j], recvSet[i][j] + delta, U_prime);
                    for (auto &p : prefixes0) {
                        auto upbound = upBound(p);
                        {
                            for (auto neighbor : neighbors) {
                                block key = blake3_hash(neighbor, (j << 8) | (0 << 4), p);
                                block val = ZeroBlock;

                                val = block(0, std::pow(recvSet[i][j] - upbound, 0 + 1));

                                filterKey.push_back(key);
                                filterVal.push_back(val);
                            }
                        }
                    }
                    for (auto &p : prefixes1) {
                        auto upbound = upBound(p);
                        {
                            for (auto neighbor : neighbors) {
                                block key = blake3_hash(neighbor, (j << 8) | (1 << 4), p);
                                block val = ZeroBlock;

                                val = block(0, std::pow(upbound - recvSet[i][j], 0 + 1));

                                filterKey.push_back(key);
                                filterVal.push_back(val);
                            }
                        }
                    }
                }
            }

            if (filterKey.size() > n * d * (1 << d) * prefixNumUpDown) {
                throw std::runtime_error("filterKey size wrong");
            }

            while (filterKey.size() < n * d * (1 << d) * prefixNumUpDown) {
                filterKey.push_back(prng.get<block>());
                filterVal.push_back(prng.get<block>());
            }

            if (filterVal.size() != n * d * (1 << d) * prefixNumUpDown) {
                throw std::runtime_error("filterVal size wrong");
            }

            SoOPPRFSender send(n * d * prefixLenUpDown, n * d * (1 << d) * prefixNumUpDown, 1, false, &sock[1]);

            std::vector<block> rand_R(n * d * prefixLenUpDown);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<block> u(n * d * prefixLenUpDown);
            std::vector<block> v(n * d * prefixLenUpDown);

            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_R[i]));
            }
            for (u64 i = 0; i < 1 * n * d * 2 * halfprefixLen; i++) {
                v[i] = block(0, low(rand_R[i]));
            }

            std::vector<u64> v_A(n * d * prefixLenUpDown);

            B2aRecver b2aRecver(n * d * prefixLenUpDown, &sock[1]);
            b2aRecver.b2a(v, v_A);

            std::vector<u64> sumDis(n * d * prefixLenUpDown, 0);

            if (lp == 1) {
                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i];
                }
            }
            if (lp == 2) {
                MulRecver mulRecver(n * d * prefixLenUpDown, &sock[1]);
                std::vector<u64> product(n * d * prefixLenUpDown, 0);

                mulRecver.mul(v_A, product);

                for (u64 i = 0; i < n * d * prefixLenUpDown; i++) {
                    sumDis[i] = 2 * product[i] + v_A[i] * v_A[i];
                }
            }

            std::vector<u64> rand_i_j(n * d, 0);

            MuxRecver mux(n * d * prefixLenUpDown, &sock[1]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    disR[i] += rand_i_j[i * d + j];
                }
                // disR[i] = v_A[i];·
            }

            for (u64 i = 0; i < n; i++) {
                auto pre = getPrefix(disR[i], prefixLenIfmat);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * prefixLenIfmat, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLenIfmat] = 1;
            }
        });

        sendFilter.join();
        recvFilter.join();

        time.setTimePoint("filter done");

        std::vector<std::vector<block>> matches;

        transferElements(sendSet, choiceBit, matches, sock);

        time.setTimePoint("OT done");

        if (LOG) {
            correctCheck(choiceBit, interIndices);
        }
    }

    auto e = time.setTimePoint("OT done");

    if (LOG) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low-px]    L0    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}