#pragma once
#include <array>
#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/block.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <vector>

extern bool LOG;

class MulSender {
public:
    MulSender(uint64_t num_, coproto::Socket *socket_);
    ~MulSender();
    void mul(std::vector<uint64_t> &in, std::vector<uint64_t> &out);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *send;
    osuCrypto::PRNG *prng;
};

class MulRecver {
public:
    MulRecver(uint64_t num_, coproto::Socket *socket_);
    ~MulRecver();
    void mul(std::vector<uint64_t> &in, std::vector<uint64_t> &out);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtReceiver *recv;
    osuCrypto::PRNG *prng;
};

void runMul(
    std::vector<uint64_t> &sendIn,
    std::vector<uint64_t> &recvIn,
    std::vector<uint64_t> &sendOut,
    std::vector<uint64_t> &recvOut,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);
