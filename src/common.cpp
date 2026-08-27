#include "common.h"
#include <coproto/Socket/AsioSocket.h>
#include <format>
#include <iostream>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <vector>
#include "utils.h"

using namespace oc;
using namespace std;

void transferElements(
    std::vector<std::vector<u64>> &set, std::vector<u8> &choiceBits, std::vector<std::vector<block>> &matches, std::array<coproto::AsioSocket, 2> &sock)
{
    u64 n = set.size();
    u64 d = set[0].size();
    PRNG prng(sysRandomSeed());

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
                correctMessages[i * d + j * 2 + 1] = block(set[i][j * 2], set[i][j * 2 + 1]) ^ prng0.get<block>();
            }
        }
        coproto::sync_wait(sock[0].send(correctMessages));
    });

    std::thread recvOT([&] {
        SilentOtExtReceiver recv;
        recv.configure(n, 128);
        recv.mMultType = type;

        coproto::sync_wait(recv.genSilentBaseOts(prng, sock[1]));

        std::vector<block> messages(n);
        BitVector choices(choiceBits.data(), choiceBits.size());

        coproto::sync_wait(recv.receive(choices, messages, prng, sock[1]));

        std::vector<block> correctMessages(n * d / 2 * 2);
        coproto::sync_wait(sock[1].recv(correctMessages));

        PRNG prng;
        for (int i = 0; i < n; i++) {
            if (choiceBits[i]) {
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

void correctCheck(std::vector<u8> &choiceBit, std::vector<u64> &interIndices)
{
    u64 cnt = 0;
    for (int i = 0; i < choiceBit.size(); i++) {
        if (choiceBit[i]) {
            cnt++;
        }
        if (choiceBit[i] && std::find(interIndices.begin(), interIndices.end(), i) == interIndices.end()) {
            throw runtime_error("false positive in fuzzyPsi");
        }
    }
    if (cnt != interIndices.size()) {
        throw runtime_error("false negative in fuzzyPsi");
    } else {
        std::cout << "Total " << cnt << "/" << interIndices.size() << " matches found!" << std::endl;
    }
}

bool isPowerOfTwo(int value)
{
    return value > 0 && (value & (value - 1)) == 0;
}

void printFpsiResult(
    std::string_view mode,
    std::string_view side,
    std::string_view assumption,
    int lp,
    std::size_t d,
    int delta,
    u64 n,
    double comm,
    double comp)
{
    const auto modeLabel = std::format("[{}]", mode);
    const auto assumptionSide = std::format("{}-{}", assumption, side);

    std::cout << std::format(
                     "{:<10} {:<15} {:^7}  {:^4}  {:^5}  {:^6}  {:^9.2f} {:^9.2f}",
                     modeLabel,
                     assumptionSide,
                     std::format("L{}", lp),
                     d,
                     delta,
                     n,
                     comm,
                     comp)
              << std::endl;
}