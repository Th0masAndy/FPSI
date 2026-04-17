#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>

void transferElements(
    std::vector<std::vector<oc::u64>> &set,
    std::vector<oc::u8> &choiceBits,
    std::vector<std::vector<oc::block>> &matches,
    std::array<coproto::AsioSocket, 2> &sock);

void correctCheck(std::vector<oc::u8> &choiceBit, std::vector<oc::u64> &interIndices);