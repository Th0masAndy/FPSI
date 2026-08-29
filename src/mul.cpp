#include "mul.h"
#include <cstddef>
#include <thread>
#include <vector>
#include "common.h"
#include "utils.h"

using namespace osuCrypto;

namespace {

constexpr u64 kCompressedBytesPerValue = 288;

} // namespace

MulSender::MulSender(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    send = new osuCrypto::SilentOtExtSender();
    send->configure(num * 64);
    send->mMultType = type;

    prng = new PRNG(ZeroBlock);
}

MulSender::~MulSender()
{
    delete send;
    delete prng;
}

void MulSender::mul(std::vector<uint64_t> &in, std::vector<uint64_t> &out)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();
    coproto::sync_wait(send->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<std::array<block, 2>> messages(numOts);

    coproto::sync_wait(send->send(messages, *prng, *socket));

    std::vector<u8> compressedBits(kCompressedBytesPerValue * num);
    u64 offset = 0;
    for (u64 i = 0; i < num; ++i) {
        for (int shift = 0; shift < 64; ++shift) {
            const u64 idx = i * 64 + shift;
            const u64 mask = low(messages[idx][0]) + in[i];
            const u64 correction = (low(messages[idx][1]) ^ mask) << shift >> shift;
            const int byteCount = 8 - shift / 8;
            for (int j = 0; j < byteCount; ++j) {
                compressedBits[offset++] = static_cast<u8>(correction >> (8 * j));
            }
            out[i] -= (low(messages[idx][0]) << shift >> shift) << shift;
        }
    }

    sendBytes(*socket, compressedBits);

    auto end_comm = socket->bytesReceived() + socket->bytesSent();
    if (LOG) {
        std::cout << "mul comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;
    }
}

MulRecver::MulRecver(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    recv = new osuCrypto::SilentOtExtReceiver();
    recv->configure(num * 64);
    recv->mMultType = type;

    prng = new PRNG(OneBlock);
}

MulRecver::~MulRecver()
{
    delete recv;
    delete prng;
}

void MulRecver::mul(std::vector<uint64_t> &in, std::vector<uint64_t> &out)
{
    coproto::sync_wait(recv->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<u8> bytes(numOts / 8);

    for (size_t i = 0; i < num; i++) {
        u64 lowbits = in[i];
        for (int j = 0; j < 8; j++) {
            size_t idx = i * 8ULL + j;
            bytes[idx] = (lowbits >> (8 * j)) & 0xFF;
        }
    }

    std::vector<block> messages(numOts);

    BitVector choiceBit(bytes.data(), numOts);

    coproto::sync_wait(recv->receive(choiceBit, messages, *prng, *socket));

    std::vector<u8> compressedBits(kCompressedBytesPerValue * num);
    recvBytes(*socket, compressedBits);

    u64 offset = 0;
    for (size_t i = 0; i < numOts; i++) {
        u64 msg = 0;
        int shift = i % 64;
        for (int j = 0; j < 8 - shift / 8; j++) {
            msg |= u64(compressedBits[offset++]) << (8 * j);
        }
        if (choiceBit[i] & 1) {
            out[i / 64] += ((low(messages[i]) ^ msg) << shift >> shift) << (i % 64);
        } else {
            out[i / 64] += (low(messages[i]) << shift >> shift) << (i % 64);
        }
    }
}

void runMul(
    std::vector<uint64_t> &sendIn,
    std::vector<uint64_t> &recvIn,
    std::vector<uint64_t> &sendOut,
    std::vector<uint64_t> &recvOut,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        MulSender mul(sendIn.size(), &sockets[sendSocket]);
        mul.mul(sendIn, sendOut);
    });
    std::thread recv([&] {
        MulRecver mul(recvIn.size(), &sockets[recvSocket]);
        mul.mul(recvIn, recvOut);
    });
    send.join();
    recv.join();
}
