#include "fpsi_low.h"
#include <cmath>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstddef>
#include <format>
#include <iostream>
#include <iterator>
#include <thread>
#include <vector>
#include "OKVS.h"
#include "SoOPPRF.h"
#include "b2a.h"
#include "common.h"
#include "eq.h"
#include "math.h"
#include "mul.h"
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

void fuzzyPsiLow2DeltaSender(const oc::CLP &cmd)
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

    std::vector<u64> seed(d * n);
    std::vector<u64> s_sum(n);

    prng.get(seed.data(), seed.size());

    for (u64 i = 0; i < n; i++) {
        s_sum[i] = 0;
        for (u64 j = 0; j < d; j++) {
            s_sum[i] = s_sum[i] ^ seed[i * d + j];
        }
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        sendSet.push_back(tmp);
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
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
                    recvListVal.push_back(block(0, seed[i * d + j]));
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

        std::vector<block> r_S(n * (1 << d));
        std::vector<block> r_R(n * (1 << d));

        std::vector<block> v_S(n * (1 << d));
        std::vector<block> v_R(n * (1 << d));

        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * (1 << d), d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_R[i * (1 << d) + z] ^= e_R[i * d * (1 << d) + j * (1 << d) + z];
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
                        ee_S[i * (1 << d) + z] ^= e_S[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread sendEqRand([&] {
            MuxSender send(n * (1 << d), &sock[1]);

            for (u64 i = 0; i < n * (1 << d); i++) {
                r_S[i] = block(0, low(ee_S[i]));
                ee_S[i] = block(0, high(ee_S[i]));
            }

            send.EqRand(ee_S, r_S, v_S);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_S[i] = rand_S[i] ^ v_S[i * d + j];
            //     }
            // }
            coproto::sync_wait(sock[1].send(v_S));
        });

        std::thread recvEqRand([&] {
            MuxRecver recv(n * (1 << d), &sock[0]);

            for (u64 i = 0; i < n * (1 << d); i++) {
                r_R[i] = block(0, low(ee_R[i]));
                ee_R[i] = block(0, high(ee_R[i]));
            }

            recv.EqRand(ee_R, r_R, v_R);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_R[i] = rand_R[i] ^ v_R[i * d + j];
            //     }
            // }
            std::vector<block> v_S(n * (1 << d));

            coproto::sync_wait(sock[0].recv(v_S));

            for (u64 i = 0; i < n * (1 << d); i++) {
                v_R[i] = v_R[i] ^ v_S[i];
            }
        });

        sendEqRand.join();
        recvEqRand.join();

        time.setTimePoint("EqSel done");

        // std::thread sendEQT([&] {
        //     PEqTSender eqSend(n * (1 << d), 1, false, &sock[0]);
        //     eqSend.eq(ee_S);
        // });

        // std::vector<u8> choiceBit(n, 0);

        // std::thread recvEQT([&] {
        //     PEqTRecver eqRecv(n * (1 << d), 1, false, &sock[1]);

        //     std::vector<u64> intersection;
        //     eqRecv.eq(ee_R, intersection);
        //     for (auto &v : intersection) {
        //         choiceBit[v / (1 << d)] = 1;
        //     }
        // });

        // sendEQT.join();
        // recvEQT.join();

        // time.setTimePoint("EQT done");

        std::thread sendOT([&] {
            std::vector<block> keys;
            std::vector<u64> X;
            PRNG prng;
            for (int i = 0; i < n; i++) {
                std::vector<u64> mask(d);
                prng.SetSeed(block(s_sum[i], s_sum[i]));
                keys.push_back(block(0, s_sum[i]));
                prng.get(mask.data(), mask.size());
                for (int j = 0; j < d; j++) {
                    mask[j] = mask[j] ^ sendSet[i][j];
                }
                X.insert(X.end(), mask.begin(), mask.end());
            }
            Hash(keys);
            coproto::sync_wait(sock[1].send(keys));
            coproto::sync_wait(sock[1].send(X));
        });

        std::vector<std::vector<block>> matches;

        u64 cnt = 0;

        std::thread recvOT([&] {
            Hash(v_R);

            std::vector<block> keys;
            std::vector<u64> X;

            coproto::sync_wait(sock[0].recvResize(keys));
            coproto::sync_wait(sock[0].recvResize(X));

            for (u64 i = 0; i < n; i++) {
                for (auto &v : v_R) {
                    if (v == keys[i]) {
                        cnt++;
                        break;
                    }
                }
            }
        });

        sendOT.join();
        recvOT.join();

        time.setTimePoint("wLPSI done");

        if (LOG) {
            std::cout << "Total " << cnt << "/" << interIndices.size() << " matches found!" << std::endl;
        }

        // if (verbose) {
        //     for (int i = 0; i < choiceBit.size(); i++) {
        //         if (choiceBit[i]) {
        //             std::cout << "intersection at index " << i << std::endl;
        //         }
        //         if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
        //             throw runtime_error("false positive in fuzzyPsi");
        //         }
        //     }
        //     std::cout << "All matches found!" << std::endl;
        // }
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

void fuzzyPsiLow2DeltaLpSender(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("nn", 4);
    int lp = cmd.getOr("p", 2);
    u64 delta_p = std::pow(delta, lp);

    PRNG prng(sysRandomSeed());
    std::vector<std::vector<u64>> recvSet;
    std::vector<block> recvListKey;
    std::vector<block> recvListVal;
    std::vector<block> rand_R(n);
    std::vector<std::vector<u64>> sendSet;
    std::vector<block> sendListKey;
    std::vector<block> sendListVal;
    std::vector<block> rand_S(n);

    std::vector<u64> seed(d * n);
    std::vector<u64> s_sum(n);

    prng.get(seed.data(), seed.size());

    for (u64 i = 0; i < n; i++) {
        s_sum[i] = 0;
        for (u64 j = 0; j < d; j++) {
            s_sum[i] = s_sum[i] ^ seed[i * d + j];
        }
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
        sendSet.push_back(tmp);
    }

    for (u64 i = 0; i < n; i++) {
        std::vector<u64> tmp;
        for (u64 j = 0; j < d; j++) {
            tmp.push_back(prng.get<u64>() + 2 * delta);
        }
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
                    recvListVal.push_back(block(std::pow(std::abs(t), lp), seed[i * d + j]));
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

        std::vector<block> r_S(n * (1 << d));
        std::vector<block> r_R(n * (1 << d));

        std::vector<block> v_S(n * (1 << d));
        std::vector<block> v_R(n * (1 << d));

        std::vector<u64> d_S(n * d * (1 << d));
        std::vector<u64> d_R(n * d * (1 << d));

        std::vector<u64> dis_S(n * (1 << d));
        std::vector<u64> dis_R(n * (1 << d));

        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * (1 << d), d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        ee_R[i * (1 << d) + z] ^= block(0, low(e_R[i * d * (1 << d) + j * (1 << d) + z]));
                        e_R[i * d * (1 << d) + j * (1 << d) + z] = block(0, high(e_R[i * d * (1 << d) + j * (1 << d) + z]));
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
                        ee_S[i * (1 << d) + z] ^= block(0, low(e_S[i * d * (1 << d) + j * (1 << d) + z]));
                        e_S[i * d * (1 << d) + j * (1 << d) + z] = block(0, high(e_S[i * d * (1 << d) + j * (1 << d) + z]));
                    }
                }
            }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread sendB2A([&] {
            B2aSender send(n * d * (1 << d), &sock[1]);
            send.b2a(e_S, d_S);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        dis_S[i * (1 << d) + z] += d_S[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        std::thread recvB2A([&] {
            B2aRecver recv(n * d * (1 << d), &sock[0]);
            recv.b2a(e_R, d_R);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        dis_R[i * (1 << d) + z] += d_R[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        recvB2A.join();
        sendB2A.join();

        time.setTimePoint("B2A done");

        std::thread sendCmpRand([&] {
            MuxSender send(n * (1 << d), &sock[1]);

            send.CmpRand(dis_S, ee_S, v_S, delta_p);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_S[i] = rand_S[i] ^ v_S[i * d + j];
            //     }
            // }
            coproto::sync_wait(sock[1].send(v_S));
        });

        std::thread recvCmpRand([&] {
            MuxRecver recv(n * (1 << d), &sock[0]);

            recv.CmpRand(dis_R, ee_R, v_R);

            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         rand_R[i] = rand_R[i] ^ v_R[i * d + j];
            //     }
            // }
            std::vector<block> v_S(n * (1 << d));

            coproto::sync_wait(sock[0].recv(v_S));

            for (u64 i = 0; i < n * (1 << d); i++) {
                v_R[i] = v_R[i] ^ v_S[i];
            }
        });

        sendCmpRand.join();
        recvCmpRand.join();

        time.setTimePoint("CmpRand done");

        // std::thread sendEQT([&] {
        //     PEqTSender eqSend(n * (1 << d), 1, false, &sock[0]);
        //     eqSend.eq(ee_S);
        // });

        // std::vector<u8> choiceBit(n, 0);

        // std::thread recvEQT([&] {
        //     PEqTRecver eqRecv(n * (1 << d), 1, false, &sock[1]);

        //     std::vector<u64> intersection;
        //     eqRecv.eq(ee_R, intersection);
        //     for (auto &v : intersection) {
        //         choiceBit[v / (1 << d)] = 1;
        //     }
        // });

        // sendEQT.join();
        // recvEQT.join();

        // time.setTimePoint("EQT done");

        std::thread sendOT([&] {
            std::vector<block> keys;
            std::vector<u64> X;
            PRNG prng;
            for (int i = 0; i < n; i++) {
                std::vector<u64> mask(d);
                prng.SetSeed(block(s_sum[i], s_sum[i]));
                keys.push_back(block(0, s_sum[i]));
                prng.get(mask.data(), mask.size());
                for (int j = 0; j < d; j++) {
                    mask[j] = mask[j] ^ sendSet[i][j];
                }
                X.insert(X.end(), mask.begin(), mask.end());
            }
            Hash(keys);
            coproto::sync_wait(sock[1].send(keys));
            coproto::sync_wait(sock[1].send(X));
        });

        std::vector<std::vector<block>> matches;

        u64 cnt = 0;

        std::thread recvOT([&] {
            Hash(v_R);

            std::vector<block> keys;
            std::vector<u64> X;

            coproto::sync_wait(sock[0].recvResize(keys));
            coproto::sync_wait(sock[0].recvResize(X));

            for (u64 i = 0; i < n; i++) {
                for (auto &v : v_R) {
                    if (v == keys[i]) {
                        cnt++;
                        break;
                    }
                }
            }
        });

        sendOT.join();
        recvOT.join();

        time.setTimePoint("wLPSI done");

        if (LOG) {
            std::cout << "Total " << cnt << "/" << interIndices.size() << " matches found!" << std::endl;
        }

        // if (verbose) {
        //     for (int i = 0; i < choiceBit.size(); i++) {
        //         if (choiceBit[i]) {
        //             std::cout << "intersection at index " << i << std::endl;
        //         }
        //         if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
        //             throw runtime_error("false positive in fuzzyPsi");
        //         }
        //     }
        //     std::cout << "All matches found!" << std::endl;
        // }
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
                     "[2delta]    L{:^1}    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     lp,
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
            // std::cout << "intersection size: " << intersection.size() << std::endl;
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

void fuzzyPsiLow2DeltaLp(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int verbose = cmd.getOr("v", 0);

    int numTry = cmd.getOr("try", 1);

    int interSize = cmd.getOr("inter", cmd.getOr("nn", 4));

    int lp = cmd.getOr("p", 2);
    u64 delta_p = std::pow(delta, lp);
    int prefixLen = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

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
                    recvListVal.push_back(block(0, std::pow(std::abs(t), lp)));
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

        std::vector<u64> d_S(n * d * (1 << d));
        std::vector<u64> d_R(n * d * (1 << d));

        std::vector<u64> dis_S(n * (1 << d));
        std::vector<u64> dis_R(n * (1 << d));

        std::vector<block> v_S(n * d);
        std::vector<block> v_R(n * d);

        std::thread recvOPPRF([&] {
            SoOPPRFSender send(n * d * (1 << d), d * n * (2 * delta + 1), 1, false, &sock[0]);

            send.OPPRF(recvListKey, recvListVal, e_R);
            // send.OPPRF(recverOKVS, e_R);

            // // aggregate by j
            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         for (u64 z = 0; z < (1 << d); z++) {
            //             ee_R[i * (1 << d) + z] += e_R[i * d * (1 << d) + j * (1 << d) + z];
            //         }
            //     }
            // }
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

            // // aggregate by j
            // for (u64 i = 0; i < n; i++) {
            //     for (u64 j = 0; j < d; j++) {
            //         for (u64 z = 0; z < (1 << d); z++) {
            //             ee_S[i * (1 << d) + z] += e_S[i * d * (1 << d) + j * (1 << d) + z];
            //         }
            //     }
            // }
        });

        sendOPPRF.join();
        recvOPPRF.join();

        time.setTimePoint("OPPRF done");

        std::thread sendB2A([&] {
            B2aSender send(n * d * (1 << d), &sock[1]);
            send.b2a(e_S, d_S);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        dis_S[i * (1 << d) + z] += d_S[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }
        });

        std::thread recvB2A([&] {
            B2aRecver recv(n * d * (1 << d), &sock[0]);
            recv.b2a(e_R, d_R);

            // aggregate by j
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        dis_R[i * (1 << d) + z] += d_R[i * d * (1 << d) + j * (1 << d) + z];
                    }
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
            for (u64 i = 0; i < n * (1 << d); i++) {
                auto pre = getIntervalPrefix(0ULL - dis_S[i], delta_p - dis_S[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() < (n * (1 << d) * prefixLen)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * (1 << d) * prefixLen, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvEQT([&] {
            for (u64 i = 0; i < n * (1 << d); i++) {
                auto pre = getPrefix(dis_R[i], prefixLen);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * (1 << d) * prefixLen, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLen / (1 << d)] = 1;
            }
        });

        sendEQT.join();
        recvEQT.join();

        time.setTimePoint("Interval test done");

        std::vector<std::vector<block>> matches;

        transferElements(sendSet, choiceBit, matches, sock);

        time.setTimePoint("OT done");

        if (LOG) {
            correctCheck(choiceBit, interIndices);
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
                     "[2delta]    L{:^1}    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     lp,
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}

void fuzzyPsiLow2DeltaLpPx(const oc::CLP &cmd)
{
    u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
    size_t d = cmd.getOr("d", 2);
    int delta = cmd.getOr("delta", 2);
    int lp = cmd.getOr("p", 2);
    u64 delta_p = std::pow(delta, lp);

    int numTry = cmd.getOr("try", 1);

    // int prefixNum = prefixNumMapLow.at(2 * delta);
    // auto U = prefixLenMapLow.at(2 * delta);

    int prefixLenIfmat = static_cast<int>(std::ceil(std::log2(delta_p + 1)));

    auto U_prime = prefixLenMapLow.at(delta);
    int prefixLenUpDown = 2 * U_prime.size();
    int prefixNumUpDown = 2 * prefixNumMapLow.at(delta);

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

    // fmap start
    oc::Timer time;

    time.setTimePoint("begin");

    auto sock = coproto::AsioSocket::makePair();

    auto s = time.setTimePoint("preprocess done");

    for (int trial = 0; trial < numTry; trial++) {
        std::vector<u8> choiceBit(n, 0);

        std::vector<u64> disR(n * (1 << d), 0);
        std::vector<u64> disS(n * (1 << d), 0);

        std::vector<block> prefixR;
        std::vector<block> prefixS;

        int halfprefixLen = prefixLenUpDown / 2;
        int halfprefixNum = prefixNumUpDown / 2;

        std::thread sendFilter([&] {
            std::vector<block> inputs(n * d * (1 << d) * halfprefixLen * 2);

            {
                for (int i = 0; i < n; i++) {
                    auto neighbors = neigh(sendSet[i], delta);
                    for (int j = 0; j < d; j++) {
                        auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                        for (int z = 0; z < (1 << d); z++) {
                            for (int s = 0; s < 2; s++) {
                                for (int k = 0; k < halfprefixLen; k++) {
                                    auto idx =
                                        i * d * halfprefixLen * 2 * (1 << d) + j * halfprefixLen * 2 * (1 << d) + z * halfprefixLen * 2 + s * halfprefixLen + k;
                                    // i, j, z, s, k
                                    inputs[idx] = blake3_hash(neighbors[z], (j << 8) | (s << 4), prefixes[k]);
                                }
                            }
                        }
                    }
                }
            }

            SoOPPRFRecver recv(n * d * (1 << d) * 2 * halfprefixLen, n * d * 2 * halfprefixNum, 1, false, &sock[0]);

            std::vector<block> rand_S(n * d * (1 << d) * 2 * halfprefixLen);

            recv.OPPRF(inputs, rand_S);

            std::vector<block> u(n * d * (1 << d) * prefixLenUpDown);
            std::vector<block> v(n * d * (1 << d) * prefixLenUpDown);

            for (u64 i = 0; i < n * d * (1 << d) * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_S[i]));
            }
            for (u64 i = 0; i < n * d * (1 << d) * 2 * halfprefixLen; i++) {
                v[i] = block(0, low(rand_S[i]));
            }

            std::vector<u64> v_A(n * d * (1 << d) * prefixLenUpDown);

            oc::Timer localTime;

            auto start = localTime.setTimePoint("b2a start");

            B2aSender b2aSender(n * d * (1 << d) * prefixLenUpDown, &sock[0]);
            b2aSender.b2a(v, v_A);

            auto end = localTime.setTimePoint("b2a done");

            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);

            if (LOG) {
                std::cout << "b2a time: " << dt << " ms" << std::endl;
            }

            std::vector<u64> sumDis(n * d * (1 << d) * 2 * halfprefixLen, 0);
            std::vector<u64> e(n * d * (1 << d) * 2 * halfprefixLen, 0);

            for (int i = 0; i < n; i++) {
                for (int j = 0; j < d; j++) {
                    auto prefixes = getPrefixSet(sendSet[i][j], U_prime);
                    for (int z = 0; z < (1 << d); z++) {
                        for (int s = 0; s < 2; s++) {
                            for (int k = 0; k < halfprefixLen; k++) {
                                e[i * d * halfprefixLen * 2 * (1 << d) + j * halfprefixLen * 2 * (1 << d) + z * halfprefixLen * 2 + s * halfprefixLen + k] =
                                    (s == 0) ? upBound(prefixes[k]) - sendSet[i][j] : sendSet[i][j] - upBound(prefixes[k]);
                            }
                        }
                    }
                }
            }

            if (lp == 1) {
                for (u64 i = 0; i < n * d * (1 << d) * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i] + e[i];
                }
            }
            if (lp == 2) {
                MulSender mulSender(n * d * (1 << d) * prefixLenUpDown, &sock[0]);

                std::vector<u64> shares(sumDis.size(), 0);

                for (u64 i = 0; i < n * d * (1 << d) * prefixLenUpDown; i++) {
                    shares[i] = v_A[i] + e[i];
                }

                std::vector<u64> product(n * d * (1 << d) * prefixLenUpDown, 0);

                mulSender.mul(shares, product);

                for (u64 i = 0; i < n * d * (1 << d) * prefixLenUpDown; i++) {
                    sumDis[i] = shares[i] * shares[i] + 2 * product[i];
                }
            }

            std::vector<u64> rand_i_j(n * d * (1 << d), 0);

            MuxSender mux(n * d * (1 << d) * prefixLenUpDown, &sock[0]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        disS[i * (1 << d) + z] += rand_i_j[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }

            for (u64 i = 0; i < n * (1 << d); i++) {
                auto pre = getIntervalPrefix(0ULL - disS[i], delta_p - disS[i]);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixS.push_back(p);
                }
            }
            while (prefixS.size() != (n * (1 << d) * prefixLenIfmat)) {
                prefixS.push_back(prng.get<block>());
            }

            PEqTSender eqSend(n * (1 << d) * prefixLenIfmat, 1, false, &sock[0]);

            eqSend.eq(prefixS);
        });

        std::thread recvFilter([&] {
            std::vector<block> filterKey;
            std::vector<block> filterVal;

            for (int i = 0; i < n; i++) {
                auto cell_id = cell(recvSet[i], 2 * delta);
                for (int j = 0; j < d; j++) {
                    auto prefixes0 = getIntervalPrefixSet(recvSet[i][j] - delta, recvSet[i][j] - 1, U_prime);
                    auto prefixes1 = getIntervalPrefixSet(recvSet[i][j], recvSet[i][j] + delta, U_prime);
                    for (auto &p : prefixes0) {
                        auto upbound = upBound(p);
                        {
                            {
                                block key = blake3_hash(cell_id, (j << 8) | (0 << 4), p);
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
                            {
                                block key = blake3_hash(cell_id, (j << 8) | (1 << 4), p);
                                block val = ZeroBlock;

                                val = block(0, std::pow(upbound - recvSet[i][j], 0 + 1));

                                filterKey.push_back(key);
                                filterVal.push_back(val);
                            }
                        }
                    }
                }
            }

            if (filterKey.size() > n * d * prefixNumUpDown) {
                throw std::runtime_error("filterKey size wrong");
            }

            while (filterKey.size() < n * d * prefixNumUpDown) {
                filterKey.push_back(prng.get<block>());
                filterVal.push_back(prng.get<block>());
            }

            if (filterVal.size() != n * d * prefixNumUpDown) {
                throw std::runtime_error("filterVal size wrong");
            }

            SoOPPRFSender send(n * d * (1 << d) * prefixLenUpDown, n * d * prefixNumUpDown, 1, false, &sock[1]);

            std::vector<block> rand_R(n * d * (1 << d) * prefixLenUpDown);

            send.OPPRF(filterKey, filterVal, rand_R);

            std::vector<block> u(n * d * (1 << d) * prefixLenUpDown);
            std::vector<block> v(n * d * (1 << d) * prefixLenUpDown);

            for (u64 i = 0; i < 1 * n * d * (1 << d) * 2 * halfprefixLen; i++) {
                u[i] = block(0, high(rand_R[i]));
            }
            for (u64 i = 0; i < 1 * n * d * (1 << d) * 2 * halfprefixLen; i++) {
                v[i] = block(0, low(rand_R[i]));
            }

            std::vector<u64> v_A(n * d * (1 << d) * prefixLenUpDown);

            B2aRecver b2aRecver(n * d * (1 << d) * prefixLenUpDown, &sock[1]);
            b2aRecver.b2a(v, v_A);

            std::vector<u64> sumDis(n * d * (1 << d) * prefixLenUpDown, 0);

            if (lp == 1) {
                for (u64 i = 0; i < n * d * (1 << d) * prefixLenUpDown; i++) {
                    sumDis[i] = v_A[i];
                }
            }
            if (lp == 2) {
                MulRecver mulRecver(n * d * (1 << d) * prefixLenUpDown, &sock[1]);
                std::vector<u64> product(n * d * (1 << d) * prefixLenUpDown, 0);

                mulRecver.mul(v_A, product);

                for (u64 i = 0; i < n * d * (1 << d) * prefixLenUpDown; i++) {
                    sumDis[i] = 2 * product[i] + v_A[i] * v_A[i];
                }
            }

            std::vector<u64> rand_i_j(n * d * (1 << d), 0);

            MuxRecver mux(n * d * (1 << d) * prefixLenUpDown, &sock[1]);
            mux.muxA(u, sumDis, rand_i_j, prefixLenUpDown);

            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < d; j++) {
                    for (u64 z = 0; z < (1 << d); z++) {
                        disR[i * (1 << d) + z] += rand_i_j[i * d * (1 << d) + j * (1 << d) + z];
                    }
                }
            }

            for (u64 i = 0; i < n * (1 << d); i++) {
                auto pre = getPrefix(disR[i], prefixLenIfmat);
                for (auto &p : pre) {
                    p = p ^ block(i << 32, 0);
                    prefixR.push_back(p);
                }
            }

            PEqTRecver eqRecv(n * (1 << d) * prefixLenIfmat, 1, false, &sock[1]);

            std::vector<u64> intersection;

            eqRecv.eq(prefixR, intersection);

            for (auto &v : intersection) {
                choiceBit[v / prefixLenIfmat / (1 << d)] = 1;
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
                     "[ours-px]    L{:^1}    {:^5}  {:^5}  {:^5}  {:^10.2f} "
                     "{:^10.2f}",
                     lp,
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

        time.setTimePoint("Interval test done");

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