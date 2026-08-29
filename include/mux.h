#pragma once

#include <array>
#include <coproto/Socket/AsioSocket.h>

#include <cryptoTools/Common/BitVector.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <vector>
#include <volePSI/Defines.h>

using namespace volePSI;
using namespace osuCrypto;

extern bool LOG;

void ssPEQT(u32 idx, std::vector<block> &input, BitVector &out, Socket &chl, u32 numThreads);

class MuxSender {
public:
    MuxSender(uint64_t num_, coproto::Socket *socket_);
    ~MuxSender();
    BitVector Mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0);

    BitVector Mux(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0);

    void EqSel(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 len);

    void EqSel(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0, u64 len);

    void EqSel(std::vector<block> &u0, std::vector<block> &res0, u64 len);

    BitVector CmpRand(std::vector<u64> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 threshold);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *sender;
    osuCrypto::SilentOtExtReceiver *recver;
    osuCrypto::PRNG *prng;
};

class MuxRecver {
public:
    MuxRecver(uint64_t num_, coproto::Socket *socket_);
    ~MuxRecver();
    BitVector Mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1);
    BitVector Mux(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1);

    void EqSel(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1, u64 len);
    void EqSel(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1, u64 len);

    void EqSel(std::vector<block> &u0, std::vector<block> &res0, u64 len);

    BitVector CmpRand(std::vector<u64> &u1, std::vector<block> &v1, std::vector<block> &res1);

    uint64_t num;

private:
    coproto::Socket *socket;
    osuCrypto::SilentOtExtSender *sender;
    osuCrypto::SilentOtExtReceiver *recver;
    osuCrypto::PRNG *prng;
};

void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<block> &sendValues,
    std::vector<block> &recvValues,
    std::vector<block> &sendResults,
    std::vector<block> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);


void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<block> &sendResults,
    std::vector<block> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);

void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<u64> &sendValues,
    std::vector<u64> &recvValues,
    std::vector<u64> &sendResults,
    std::vector<u64> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);
