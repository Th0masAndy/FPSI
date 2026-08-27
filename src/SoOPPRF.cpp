#include "SoOPPRF.h"
#include <algorithm>
#include <coproto/Common/macoro.h>
#include "SoOPRF.h"

namespace {

constexpr u64 kBlocksPerChunk = 1ULL << 20;

void sendBlocks(coproto::Socket &socket, const std::vector<oc::block> &blocks)
{
    for (u64 offset = 0; offset < blocks.size(); offset += kBlocksPerChunk) {
        const u64 size = std::min<u64>(blocks.size() - offset, kBlocksPerChunk);
        coproto::span<const oc::block> chunk(blocks.data() + offset, size);
        coproto::sync_wait(socket.send(chunk));
    }
}

void recvBlocks(coproto::Socket &socket, std::vector<oc::block> &blocks)
{
    for (u64 offset = 0; offset < blocks.size(); offset += kBlocksPerChunk) {
        const u64 size = std::min<u64>(blocks.size() - offset, kBlocksPerChunk);
        coproto::span<oc::block> chunk(blocks.data() + offset, size);
        coproto::sync_wait(socket.recv(chunk));
    }
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
