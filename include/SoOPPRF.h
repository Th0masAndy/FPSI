#pragma once

#include <array>
#include <coproto/Socket/AsioSocket.h>
#include <cstdint>
#include <vector>
#include "OKVS.h"
#include "SoOPRF.h"

extern bool LOG;

struct SoOpprfInput {
    std::vector<oc::block> keys;
    std::vector<oc::block> values;
    std::vector<oc::block> queryKeys;
};

class SoOPPRFSender : public SoOPRFSender {
public:
    SoOPPRFSender(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_);
    ~SoOPPRFSender();

    void OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &values, std::vector<oc::block> &y0);

    void OPPRF(const std::vector<oc::block> &encoding, std::vector<oc::block> &y0);

    task<> run_oprf(std::vector<oc::block> &y0);

private:
    OKVS *okvs;
};

class SoOPPRFRecver : public SoOPRFRecver {
public:
    SoOPPRFRecver(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_);
    ~SoOPPRFRecver();

    void OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &y1);

private:
    OKVS *okvs;
};

void runSoOpprf(
    std::vector<oc::block> &keys,
    std::vector<oc::block> &values,
    std::vector<oc::block> &queryKeys,
    std::vector<oc::block> &recvShares,
    std::vector<oc::block> &sendShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);

void runSoOpprf(
    const std::vector<oc::block> &encoding,
    oc::u64 numKeyValues,
    std::vector<oc::block> &queryKeys,
    std::vector<oc::block> &recvShares,
    std::vector<oc::block> &sendShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse = false);
