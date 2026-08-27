#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cstddef>
#include <string_view>
#include <vector>

void transferElements(
    std::vector<std::vector<oc::u64>> &set,
    std::vector<oc::u8> &choiceBits,
    std::vector<std::vector<oc::block>> &matches,
    std::array<coproto::AsioSocket, 2> &sock);

void correctCheck(std::vector<oc::u8> &choiceBit, std::vector<oc::u64> &interIndices);

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