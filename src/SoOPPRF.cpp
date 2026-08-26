#include "SoOPPRF.h"
#include <coproto/Common/macoro.h>
#include "SoOPRF.h"

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

    std::vector<oc::block> values_masked(values);

    AltModPrf prf(SoOPRFSender::getKey());
    std::vector<block> prf_value(keys.size());
    prf.eval(keys, prf_value);

    for (u64 i = 0; i < values.size(); ++i) {
        values_masked[i] = values[i] ^ prf_value[i];
    }

    auto encoding = okvs->encode(keys, values_masked);

    if (LOG) {
        std::cout << "OPRF comm: " << (after - before) / 1024.0 / 1024.0 << " MB " << std::endl;

        std::cout << "OKVS size: " << encoding.size() * sizeof(block) / 1024.0 / 1024.0 << " MB " << std::endl;
    }

    if (encoding.size() <= (1 << 26)) {
        coproto::sync_wait(socket->send(encoding));
    } else {
        std::vector<oc::block> tmp;
        for (u64 i = 0; i < encoding.size(); i += (1 << 26)) {
            u64 len = std::min<u64>((u64)encoding.size() - i, (1 << 26));
            tmp.assign(encoding.begin() + i, encoding.begin() + i + len);
            coproto::sync_wait(socket->send(tmp));
        }
    }
}

void SoOPPRFSender::OPPRF(std::vector<oc::block> encoding, std::vector<oc::block> &y0)
{
    auto before = socket->bytesReceived() + socket->bytesSent();

    SoOPRFSender::OPRF(y0);

    auto after = socket->bytesReceived() + socket->bytesSent();
    std::cout << "OPRF comm: " << (after - before) / 1024.0 / 1024.0 << " MB " << std::endl;

    std::cout << "OKVS size: " << encoding.size() * sizeof(block) / 1024.0 / 1024.0 << " MB " << std::endl;

    coproto::sync_wait(socket->send(encoding));
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

    if (encoding.size() <= (1 << 26)) {
        coproto::sync_wait(socket->recv(encoding));
    } else {
        std::vector<oc::block> tmp;
        for (u64 i = 0; i < encoding.size(); i += (1 << 26)) {
            u64 len = std::min<u64>((u64)encoding.size() - i, (1 << 26));
            tmp.assign(encoding.begin() + i, encoding.begin() + i + len);
            coproto::sync_wait(socket->recv(tmp));
            std::copy(tmp.begin(), tmp.end(), encoding.begin() + i);
        }
    }

    auto d = okvs->decode(encoding, keys);

    for (u64 i = 0; i < keys.size(); i++) {
        y1[i] = d[i] ^ tmp[i];
    }
}