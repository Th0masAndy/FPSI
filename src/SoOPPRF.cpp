#include "SoOPPRF.h"
#include <thread>
#include "SoOPRF.h"
#include "common.h"

namespace {

struct SoOpprfRoles {
    coproto::Socket *sendSocket;
    coproto::Socket *recvSocket;
    std::vector<oc::block> *sendOutput;
    std::vector<oc::block> *recvOutput;
};

SoOpprfRoles resolveRoles(
    std::vector<oc::block> &recvShares,
    std::vector<oc::block> &sendShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    if (roleInverse) {
        return { &sockets[1], &sockets[0], &recvShares, &sendShares };
    }
    return { &sockets[0], &sockets[1], &sendShares, &recvShares };
}

} // namespace

SoOPPRFSender::SoOPPRFSender(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_)
    : SoOPRFSender(num_, numThreads_, useOle_, socket_)
{
    okvs = new OKVS(num_kv_);
}

SoOPPRFSender::~SoOPPRFSender()
{
    delete okvs;
}

void SoOPPRFSender::OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &values, std::vector<oc::block> &y0)
{
    auto before = socket->bytesReceived() + socket->bytesSent();

    SoOPRFSender::OPRF(y0);

    auto after = socket->bytesReceived() + socket->bytesSent();

    AltModPrf prf(SoOPRFSender::getKey());
    std::vector<block> values_masked(keys.size());
    prf.eval(keys, values_masked);

    for (u64 i = 0; i < values.size(); ++i) {
        values_masked[i] ^= values[i];
    }

    auto encoding = okvs->encode(keys, values_masked);

    if (LOG) {
        std::cout << "OPRF comm: " << (after - before) / 1024.0 / 1024.0 << " MB " << std::endl;

        std::cout << "OKVS size: " << encoding.size() * sizeof(block) / 1024.0 / 1024.0 << " MB " << std::endl;
    }

    sendBlocks(*socket, encoding);
}

void SoOPPRFSender::OPPRF(const std::vector<oc::block> &encoding, std::vector<oc::block> &y0)
{
    auto before = socket->bytesReceived() + socket->bytesSent();

    SoOPRFSender::OPRF(y0);

    auto after = socket->bytesReceived() + socket->bytesSent();

    if (LOG) {
        std::cout << "OPRF comm: " << (after - before) / 1024.0 / 1024.0 << " MB " << std::endl;
        std::cout << "OKVS size: " << encoding.size() * sizeof(block) / 1024.0 / 1024.0 << " MB " << std::endl;
    }

    sendBlocks(*socket, encoding);
}

SoOPPRFRecver::SoOPPRFRecver(uint64_t num_, uint64_t num_kv_, uint64_t numThreads_, bool useOle_, coproto::Socket *socket_)
    : SoOPRFRecver(num_, numThreads_, useOle_, socket_)
{
    okvs = new OKVS(num_kv_);
}

SoOPPRFRecver::~SoOPPRFRecver()
{
    delete okvs;
}

void SoOPPRFRecver::OPPRF(std::vector<oc::block> &keys, std::vector<oc::block> &y1)
{
    std::vector<oc::block> tmp(keys.size());

    SoOPRFRecver::OPRF(keys, tmp);

    std::vector<oc::block> encoding(okvs->size());

    recvBlocks(*socket, encoding);

    okvs->decode(encoding, keys, y1);

    for (u64 i = 0; i < keys.size(); i++) {
        y1[i] ^= tmp[i];
    }
}

void runSoOpprf(
    std::vector<oc::block> &keys,
    std::vector<oc::block> &values,
    std::vector<oc::block> &queryKeys,
    std::vector<oc::block> &recvShares,
    std::vector<oc::block> &sendShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    auto roles = resolveRoles(recvShares, sendShares, sockets, roleInverse);

    std::thread sendParty([&] {
        SoOPPRFRecver recv(queryKeys.size(), keys.size(), 1, false, roles.recvSocket);
        recv.OPPRF(queryKeys, *roles.recvOutput);
    });

    std::thread recvParty([&] {
        SoOPPRFSender send(queryKeys.size(), keys.size(), 1, false, roles.sendSocket);
        send.OPPRF(keys, values, *roles.sendOutput);
    });

    sendParty.join();
    recvParty.join();
}

void runSoOpprf(
    const std::vector<oc::block> &encoding,
    oc::u64 numKeyValues,
    std::vector<oc::block> &queryKeys,
    std::vector<oc::block> &recvShares,
    std::vector<oc::block> &sendShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    auto roles = resolveRoles(recvShares, sendShares, sockets, roleInverse);

    std::thread sendParty([&] {
        SoOPPRFRecver recv(queryKeys.size(), numKeyValues, 1, false, roles.recvSocket);
        recv.OPPRF(queryKeys, *roles.recvOutput);
    });

    std::thread recvParty([&] {
        SoOPPRFSender send(queryKeys.size(), numKeyValues, 1, false, roles.sendSocket);
        send.OPPRF(encoding, *roles.sendOutput);
    });

    sendParty.join();
    recvParty.join();
}
