#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstddef>
#include <format>
#include <iostream>
#include <thread>
#include <vector>
#include "Defines.h"
#include "OKVS.h"
#include "SoOPPRF.h"
#include "eq.h"
#include "fpsi_low.h"
#include "math.h"
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

void fuzzyPsiLowPrefix(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

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

    for (u64 i = 0; i < interSize; i++) {
        u64 idx = interIndices[i];
        for (u64 j = 0; j < d; j++) {
            recvSet[idx][j] = sendSet[idx][j] + (1 - 2 * (prng.get<u64>() % 2)) * (prng.get<u64>() % (delta + 1));
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

    preProcessPrefix(recvSet, recvListKey, recvListVal, delta);

    std::vector<block> recverPrfVals(recvListKey.size());
    prf.eval(recvListKey, recverPrfVals);
    for (size_t i = 0; i < sendListKey.size(); i++) {
        recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    }

    auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto sock = coproto::AsioSocket::makePair();

    std::vector<block> e_S(n * d * prefixLen);
    std::vector<block> e_R(n * d * prefixLen);

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * prefixLen, (1 << d) * d * n * prefixNum, 1, false, &sock[0]);

            // send.OPPRF(recvListKey, recvListVal, rand_R);
            send.OPPRF(recverOKVS, e_R);
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
    }

    auto e = time.setTimePoint("OT done");

    if (verbose) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low]    L0    {:^5}  {:^5}  {:^5}  {:^10.3f} "
                     "{:^10.3f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}