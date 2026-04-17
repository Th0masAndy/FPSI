#include "fpsi_low.h"
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
#include "math.h"
#include "mux.h"
#include "param.h"
#include "secure-join/Prf/AltModPrf.h"
#include "utils.h"

void preProcess(std::vector<std::vector<u64>> &inputs, std::vector<block> &listKey, std::vector<block> &listVal, int delta)
{
    int d = inputs[0].size();
    for (size_t i = 0; i < inputs.size(); i++) {
        auto neighbors = neigh(inputs[i], delta);
        for (int j = 0; j < d; j++) {
            for (int t = -delta; t <= delta; t++) {
                for (auto neighbor : neighbors) {
                    listKey.push_back(blake3_hash(neighbor, j, inputs[i][j] + t)); // placeholder
                    listVal.push_back(ZeroBlock);
                }
            }
        }
    }
}

void fuzzyPsiLow2Delta(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

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

    // auto preOKVS = OKVS(n * d * (2 * delta + 1));
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

    {
        PRNG prng(oc::sysRandomSeed());
        int d = recvSet[0].size();
        for (size_t i = 0; i < recvSet.size(); i++) {
            for (int j = 0; j < d; j++) {
                for (int t = -delta; t <= delta; t++) {
                    recvListKey.push_back(blake3_hash(cell(recvSet[i], 2 * delta), j, recvSet[i][j] + t)); // placeholder
                    recvListVal.push_back(ZeroBlock);
                }
            }
        }
    }

    auto sock = coproto::AsioSocket::makePair();

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        // auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

        std::vector<block> e_S(n * d * (1 << d));
        std::vector<block> e_R(n * d * (1 << d));

        std::vector<block> ee_S(n * (1 << d));
        std::vector<block> ee_R(n * (1 << d));

        std::vector<block> v_S(n * d);
        std::vector<block> v_R(n * d);

        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * (1 << d), d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_R[i * (1 << d) + z] += e_R[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        std::thread sendOPPRF([&] {
            SoOPPRFRecver recv(n * d * (1 << d), d * n * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> inputs(n * d * (1 << d));

            for (u64 i = 0; i < n; i++) {
                auto neighbors = neigh(sendSet[i], delta);
                for (u64 j = 0; j < d; j++) {
                    for (int z = 0; z < (1 << d); z++) {
                        inputs[i * d * (1 << d) + j * (1 << d) + z] = blake3_hash(neighbors[z], j, sendSet[i][j]);
                    }
                }
            }

            recv.OPPRF(inputs, e_S);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_S[i * (1 << d) + z] += e_S[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        // std::thread sendEqSel([&] {
        //     MuxSender send(n, &sock[1]);
        //     send.mux(ee_S, rand_S, 1 << d);

        //     // for (u64 i = 0; i < n; i++) {
        //     //     for (u64 j = 0; j < d; j++) {
        //     //         rand_S[i] = rand_S[i] ^ v_S[i * d + j];
        //     //     }
        //     // }
        // });

        // std::thread recvEqSel([&] {
        //     MuxRecver recv(n, &sock[0]);
        //     recv.mux(ee_R, rand_R, 1 << d);

        //     // for (u64 i = 0; i < n; i++) {
        //     //     for (u64 j = 0; j < d; j++) {
        //     //         rand_R[i] = rand_R[i] ^ v_R[i * d + j];
        //     //     }
        //     // }
        // });

        // sendEqSel.join();
        // recvEqSel.join();

        // time.setTimePoint("EqSel done");

        std::thread sendEQT([&] {
            PEqTSender eqSend(n * (1 << d), 1, false, &sock[0]);
            eqSend.eq(ee_S);
        });

        std::vector<u8> choiceBit(n, 0);

        std::thread recvEQT([&] {
            PEqTRecver eqRecv(n * (1 << d), 1, false, &sock[1]);

            std::vector<u64> intersection;
            eqRecv.eq(ee_R, intersection);
            for (auto &v : intersection) {
                choiceBit[v / (1 << d)] = 1;
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

        if (verbose) {
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

    if (verbose) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[2delta]    L0    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}

void fuzzyPsiLow2DeltaPx(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("nn", 4);

    int prefixNum = prefixNumMapLow.at(2 * delta);
    auto U = prefixLenMapLow.at(2 * delta);

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

    // auto preOKVS = OKVS(n * d * (2 * delta + 1));
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

    {
        PRNG prng(oc::sysRandomSeed());
        int d = recvSet[0].size();
        for (size_t i = 0; i < recvSet.size(); i++) {
            for (int j = 0; j < d; j++) {
                auto prefixes = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] + delta, U);

                for (auto prefix : prefixes) {
                    recvListKey.push_back(blake3_hash(cell(recvSet[i], 2 * delta), j, prefix)); // placeholder
                    recvListVal.push_back(ZeroBlock);
                }
            }
        }

        while (recvListKey.size() < n * d * prefixNum) {
            recvListKey.push_back(prng.get<block>());
            recvListVal.push_back(prng.get<block>());
        }
    }

    auto sock = coproto::AsioSocket::makePair();

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<block> e_S(n * d * (1 << d) * U.size());
        std::vector<block> e_R(n * d * (1 << d) * U.size());

        std::vector<block> sel_e_S(n * d * (1 << d));
        std::vector<block> sel_e_R(n * d * (1 << d));

        std::vector<block> ee_S(n * (1 << d));
        std::vector<block> ee_R(n * (1 << d));

        std::vector<block> v_S(n * d);
        std::vector<block> v_R(n * d);

        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * (1 << d) * U.size(), d * n * prefixNum, 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
        });

        std::thread sendOPPRF([&] {
            SoOPPRFRecver recv(n * d * (1 << d) * U.size(), d * n * prefixNum, 1, false, &sock[1]);

            std::vector<block> inputs(n * d * (1 << d) * U.size());
            for (u64 i = 0; i < n; i++) {
                auto neighbors = neigh(sendSet[i], delta);
                for (u64 j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U);
                    for (auto z = 0; z < (1 << d); z++) {
                        for (auto mu = 0; mu < U.size(); mu++) {
                            inputs[i * d * (1 << d) * U.size() + j * (1 << d) * U.size() + z * U.size() + mu] = blake3_hash(neighbors[z], j, prefixes[mu]);
                        }
                    }
                }
            }

            recv.OPPRF(inputs, e_S);
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread sendEqSel([&] {
            MuxSender send(n * d * (1 << d), &sock[1]);
            send.mux(e_S, sel_e_S, U.size());

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_S[i * (1 << d) + z] += sel_e_S[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        std::thread recvEqSel([&] {
            MuxRecver recv(n * d * (1 << d), &sock[0]);
            recv.mux(e_R, sel_e_R, U.size());

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_R[i * (1 << d) + z] += sel_e_R[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        sendEqSel.join();
        recvEqSel.join();

        time.setTimePoint("EqSel done");

        std::thread sendEQT([&] {
            PEqTSender eqSend(n * (1 << d), 1, false, &sock[0]);
            eqSend.eq(ee_S);
        });

        std::vector<u8> choiceBit(n, 0);

        std::thread recvEQT([&] {
            PEqTRecver eqRecv(n * (1 << d), 1, false, &sock[1]);

            std::vector<u64> intersection;
            eqRecv.eq(ee_R, intersection);
            std::cout << "intersection size: " << intersection.size() << std::endl;
            for (auto &v : intersection) {
                choiceBit[v / (1 << d)] = 1;
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

        if (verbose) {
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

    if (verbose) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low-2delta]    L0    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}

void fuzzyPsiLow4Delta(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("nn", 4);

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<std::vector<u64>> sendSet;

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

    // auto preOKVS = OKVS(n * d * (1 << d) * (2 * delta + 1));
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

    // std::vector<block> recverPrfVals(recvListKey.size());
    // prf.eval(recvListKey, recverPrfVals);
    // for (size_t i = 0; i < sendListKey.size(); i++) {
    //     recvListVal[i] = recvListVal[i] ^ recverPrfVals[i];
    // }

    // auto recverOKVS = preOKVS.encode(recvListKey, recvListVal);

    auto sock = coproto::AsioSocket::makePair();

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<block> sendListKey;
        std::vector<block> sendListVal;
        std::vector<block> rand_S(n);

        std::vector<block> recvListKey;
        std::vector<block> recvListVal;
        std::vector<block> rand_R(n);

        std::vector<block> e_S(n * d);
        std::vector<block> e_R(n * d);

        std::thread recvOPPRF([&] {
            preProcess(recvSet, recvListKey, recvListVal, delta);

            SoOPPRFSender send(n * d, (1 << d) * d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R[i] ^= e_R[i * d + j];
                }
            }
        });

        std::thread sendOPPRF([&] {
            SoOPPRFRecver recv(n * d, (1 << d) * d * n * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> inputs(n * d);
            for (u64 i = 0; i < n; i++) {
                auto cell_id = cell(sendSet[i], 2 * delta);
                for (u64 j = 0; j < d; j++) {
                    inputs[i * d + j] = blake3_hash(cell_id, j, recvSet[i][j]);
                }
            }

            recv.OPPRF(inputs, e_S);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S[i] ^= e_S[i * d + j];
                }
            }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

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

        if (verbose) {
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

    if (verbose) {
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

void fuzzyPsiLow4DeltaLp(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("nn", 4);

    int lp = cmd.getOr("p", 2);
    u64 delta_p = std::pow(delta, lp);
    int prefixLen = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<std::vector<u64>> sendSet;

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

    // auto preOKVS = OKVS(n * d * (1 << d) * (2 * delta + 1));

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    auto sock = coproto::AsioSocket::makePair();

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<block> sendListKey;
        std::vector<block> sendListVal;
        std::vector<u64> rand_S(n);
        std::vector<u64> rand_S_Arith(n * d);

        std::vector<block> recvListKey;
        std::vector<block> recvListVal;
        std::vector<u64> rand_R(n);
        std::vector<u64> rand_R_Arith(n * d);

        std::vector<block> e_S(n * d);
        std::vector<block> e_R(n * d);

        std::thread recvOPPRF([&] {
            // preProcess(recvSet, recvListKey, recvListVal, delta);

            int d = recvSet[0].size();
            for (size_t i = 0; i < recvSet.size(); i++) {
                auto neighbors = neigh(recvSet[i], delta);
                for (int j = 0; j < d; j++) {
                    for (int t = -delta; t <= delta; t++) {
                        for (auto neighbor : neighbors) {
                            recvListKey.push_back(blake3_hash(neighbor, j, recvSet[i][j] + t)); // placeholder
                            recvListVal.push_back(block(0, std::pow(std::abs(t), lp)));
                        }
                    }
                }
            }

            SoOPPRFSender send(n * d, (1 << d) * d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_R[i] ^= e_R[i * d + j];
            //     }
            // }
        });

        std::thread sendOPPRF([&] {
            SoOPPRFRecver recv(n * d, (1 << d) * d * n * (2 * delta + 1), 1, false, &sock[1]);

            std::vector<block> inputs(n * d);
            for (u64 i = 0; i < n; i++) {
                auto cell_id = cell(sendSet[i], 2 * delta);
                for (u64 j = 0; j < d; j++) {
                    inputs[i * d + j] = blake3_hash(cell_id, j, sendSet[i][j]);
                }
            }

            recv.OPPRF(inputs, e_S);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_S[i] ^= e_S[i * d + j];
            //     }
            // }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread sendB2A([&] {
            B2aSender send(n * d, &sock[1]);
            send.b2a(e_S, rand_S_Arith);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_S[i] += rand_S_Arith[i * d + j];
                }
            }
        });

        std::thread recvB2A([&] {
            B2aRecver recv(n * d, &sock[0]);
            recv.b2a(e_R, rand_R_Arith);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    rand_R[i] += rand_R_Arith[i * d + j];
                }
            }
        });

        sendB2A.join();
        recvB2A.join();

        time.setTimePoint("B2A done");

        std::vector<u8> choiceBit(n, 0);
        std::vector<block> prefixR;
        std::vector<block> prefixS;

        std::thread sendEQT([&] {
            for (u64 i = 0; i < n; i++) {
                auto pre = getIntervalPrefix(0ULL - rand_S[i], delta_p - rand_S[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() < (n * prefixLen)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * prefixLen, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvEQT([&] {
            for (u64 i = 0; i < n; i++) {
                auto pre = getPrefix(rand_R[i], prefixLen);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * prefixLen, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLen] = 1;
            }
        });

        sendEQT.join();
        recvEQT.join();

        time.setTimePoint("EQT done");

        std::vector<std::vector<block>> matches;

        transferElements(sendSet, choiceBit, matches, sock);

        if (verbose) {
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

    if (verbose) {
        std::cout << time << std::endl;
    }

    auto comm = (sock[0].bytesReceived() + sock[0].bytesSent()) / 1024.0 / 1024.0;
    auto comp = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count() / double(1000 * 1000);

    comp /= numTry;
    comm /= numTry;

    std::cout << std::format(
                     "[ours-low-4delta-lp]    Lp    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}