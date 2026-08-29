#include "common.h"
#include <algorithm>
#include <coproto/Common/macoro.h>
#include <coproto/Socket/AsioSocket.h>
#include <format>
#include <iostream>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <unordered_set>
#include <vector>
#include "utils.h"

using namespace oc;
using namespace std;

void sendBytes(coproto::Socket &socket, const std::vector<u8> &bytes)
{
    for (u64 offset = 0; offset < bytes.size(); offset += kBytesPerChunk) {
        const u64 size = std::min<u64>(bytes.size() - offset, kBytesPerChunk);
        coproto::span<const u8> chunk(bytes.data() + offset, size);
        coproto::sync_wait(socket.send(chunk));
    }
}

void recvBytes(coproto::Socket &socket, std::vector<u8> &bytes)
{
    for (u64 offset = 0; offset < bytes.size(); offset += kBytesPerChunk) {
        const u64 size = std::min<u64>(bytes.size() - offset, kBytesPerChunk);
        coproto::span<u8> chunk(bytes.data() + offset, size);
        coproto::sync_wait(socket.recv(chunk));
    }
}

void sendBlocks(coproto::Socket &socket, const std::vector<block> &blocks)
{
    for (u64 offset = 0; offset < blocks.size(); offset += kBlocksPerChunk) {
        const u64 size = std::min<u64>(blocks.size() - offset, kBlocksPerChunk);
        coproto::span<const block> chunk(blocks.data() + offset, size);
        coproto::sync_wait(socket.send(chunk));
    }
}

void recvBlocks(coproto::Socket &socket, std::vector<block> &blocks)
{
    for (u64 offset = 0; offset < blocks.size(); offset += kBlocksPerChunk) {
        const u64 size = std::min<u64>(blocks.size() - offset, kBlocksPerChunk);
        coproto::span<block> chunk(blocks.data() + offset, size);
        coproto::sync_wait(socket.recv(chunk));
    }
}

void transferElements(
    const PointSet &set, std::vector<u8> &choiceBits, std::vector<std::vector<block>> &matches, std::array<coproto::AsioSocket, 2> &sock)
{
    const u64 n = set.size();
    const u64 d = set.dim();
    const u64 packedDimension = (d + 1) / 2;

    std::thread sendOT([&] {
        PRNG otPrng(sysRandomSeed());
        SilentOtExtSender send;
        send.configure(n, 128);
        send.mMultType = type;

        coproto::sync_wait(send.genSilentBaseOts(otPrng, sock[0]));

        std::vector<std::array<block, 2>> messages(n);

        coproto::sync_wait(send.send(messages, otPrng, sock[0]));

        // Only choice 1 receives an element. One ciphertext per pair of
        // coordinates is sufficient; the previous even-index blocks were
        // never consumed by the receiver.
        std::vector<block> ciphertexts(n * packedDimension);
        PRNG payloadPrng;
        for (u64 i = 0; i < n; ++i) {
            payloadPrng.SetSeed(messages[i][1]);
            for (u64 j = 0; j < packedDimension; ++j) {
                const u64 first = set[i][2 * j];
                const u64 second = 2 * j + 1 < d ? set[i][2 * j + 1] : 0;
                ciphertexts[i * packedDimension + j] = block(first, second) ^ payloadPrng.get<block>();
            }
        }
        coproto::sync_wait(sock[0].send(ciphertexts));
    });

    std::thread recvOT([&] {
        PRNG otPrng(sysRandomSeed());
        SilentOtExtReceiver recv;
        recv.configure(n, 128);
        recv.mMultType = type;

        coproto::sync_wait(recv.genSilentBaseOts(otPrng, sock[1]));

        std::vector<block> messages(n);
        BitVector choices(choiceBits.data(), choiceBits.size());

        coproto::sync_wait(recv.receive(choices, messages, otPrng, sock[1]));

        std::vector<block> ciphertexts(n * packedDimension);
        coproto::sync_wait(sock[1].recv(ciphertexts));

        matches.reserve(std::count(choiceBits.begin(), choiceBits.end(), u8 { 1 }));
        PRNG payloadPrng;
        for (u64 i = 0; i < n; ++i) {
            if (choiceBits[i]) {
                payloadPrng.SetSeed(messages[i]);
                std::vector<block> element(packedDimension);
                for (u64 j = 0; j < packedDimension; ++j) {
                    element[j] = payloadPrng.get<block>() ^ ciphertexts[i * packedDimension + j];
                }
                matches.push_back(std::move(element));
            }
        }
    });

    sendOT.join();
    recvOT.join();
}

std::vector<u64> sampleUniqueIndices(u64 n, u64 count, PRNG &prng)
{
    if (count > n) {
        throw std::invalid_argument("intersection size cannot exceed the set size");
    }

    std::vector<u64> indices;
    indices.reserve(count);
    std::unordered_set<u64> selected;
    selected.reserve(count);

    while (indices.size() < count) {
        const u64 index = prng.get<u64>() % n;
        if (selected.insert(index).second) {
            indices.push_back(index);
        }
    }
    return indices;
}

void correctCheck(const std::vector<u8> &choiceBit, const std::vector<u64> &interIndices)
{
    std::vector<u8> expected(choiceBit.size(), 0);
    for (const auto index : interIndices) {
        if (index >= expected.size()) {
            throw std::invalid_argument("expected intersection index is out of range");
        }
        if (expected[index]) {
            throw std::invalid_argument("expected intersection indices contain duplicates");
        }
        expected[index] = 1;
    }

    u64 actualCount = 0;
    std::vector<u64> actualIndices;
    actualIndices.reserve(interIndices.size());
    bool mismatch = false;
    for (u64 i = 0; i < choiceBit.size(); ++i) {
        const bool actual = choiceBit[i] != 0;
        actualCount += actual;
        if (actual) {
            actualIndices.push_back(i);
        }
        mismatch |= actual != static_cast<bool>(expected[i]);
    }

    if (mismatch) {
        auto formatIndices = [](const std::vector<u64> &indices) {
            std::string result;
            for (u64 i = 0; i < indices.size(); ++i) {
                if (i != 0) {
                    result += ",";
                }
                result += std::to_string(indices[i]);
            }
            return result;
        };

        auto sortedExpected = interIndices;
        std::sort(sortedExpected.begin(), sortedExpected.end());
        throw runtime_error(std::format(
            "fuzzyPsi result mismatch: expected [{}], actual [{}]", formatIndices(sortedExpected), formatIndices(actualIndices)));
    }

    std::cout << "Total " << actualCount << "/" << interIndices.size() << " matches found!" << std::endl;
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
