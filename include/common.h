#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstddef>
#include <string_view>
#include <vector>
#include "utils.h"

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
