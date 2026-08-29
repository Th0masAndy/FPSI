#pragma once

#include <array>
#include <coproto/Socket/AsioSocket.h>
#include <sys/types.h>
#include <vector>
#include "volePSI/RsPsi.h"

using namespace volePSI;

class PEqTSender {
public:
    PEqTSender(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_);
    ~PEqTSender();
    void eq(std::vector<block> &sendSet);

    uint64_t num;
    uint64_t numThreads;
    bool noCompress;

private:
    RsPsiSender *send;
    coproto::Socket *socket;
};

class PEqTRecver {
public:
    PEqTRecver(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_);
    ~PEqTRecver();
    void eq(std::vector<block> &recvSet, std::vector<u64> &intersection);

    uint64_t num;
    uint64_t numThreads;
    bool noCompress;

private:
    RsPsiReceiver *recv;
    coproto::Socket *socket;
};

void runPeqt(
    std::vector<block> &sendInputs,
    std::vector<block> &recvInputs,
    std::vector<u64> &matches,
    std::array<coproto::AsioSocket, 2> &sockets);

void runIntervalTest(
    const std::vector<u64> &sendDis,
    const std::vector<u64> &recvDis,
    u64 deltaPow,
    u64 prefixLen,
    std::vector<u64> &matches,
    std::array<coproto::AsioSocket, 2> &sockets);
