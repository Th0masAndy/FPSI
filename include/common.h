#pragma once

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstddef>
#include <string_view>
#include <vector>
#include "utils.h"

inline constexpr oc::u64 kBytesPerChunk = 1ULL << 30;
inline constexpr oc::u64 kBlocksPerChunk = kBytesPerChunk / sizeof(oc::block);

void sendBytes(coproto::Socket &socket, const std::vector<oc::u8> &bytes);

void recvBytes(coproto::Socket &socket, std::vector<oc::u8> &bytes);

void sendBlocks(coproto::Socket &socket, const std::vector<oc::block> &blocks);

void recvBlocks(coproto::Socket &socket, std::vector<oc::block> &blocks);

void transferElements(
    const PointSet &set,
    std::vector<oc::u8> &choiceBits,
    std::vector<std::vector<oc::block>> &matches,
    std::array<coproto::AsioSocket, 2> &sock);

std::vector<oc::u64> sampleUniqueIndices(oc::u64 n, oc::u64 count, oc::PRNG &prng);

void correctCheck(const std::vector<oc::u8> &choiceBit, const std::vector<oc::u64> &interIndices);

bool isPowerOfTwo(int value);

void printFpsiResult(
    std::string_view mode,
    std::string_view side,
    std::string_view assumption,
    int lp,
    std::size_t d,
    int delta,
    oc::u64 n,
    double comm,
    double comp);
