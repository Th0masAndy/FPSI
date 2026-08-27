#include "mul.h"
#include <cstddef>
#include <vector>
#include "utils.h"

using namespace osuCrypto;

namespace {

constexpr u64 kCompressedBytesPerValue = 288;
constexpr u64 kIoChunkBytes = 1ULL << 30;

void sendBytes(coproto::Socket &socket, std::vector<u8> &bytes)
{
    for (u64 offset = 0; offset < bytes.size(); offset += kIoChunkBytes) {
        const u64 size = std::min<u64>(bytes.size() - offset, kIoChunkBytes);
        coproto::span<u8> chunk(bytes.data() + offset, size);
        coproto::sync_wait(socket.send(chunk));
    }
}

void recvBytes(coproto::Socket &socket, std::vector<u8> &bytes)
{
    for (u64 offset = 0; offset < bytes.size(); offset += kIoChunkBytes) {
        const u64 size = std::min<u64>(bytes.size() - offset, kIoChunkBytes);
        coproto::span<u8> chunk(bytes.data() + offset, size);
        coproto::sync_wait(socket.recv(chunk));
    }
}

} // namespace

MulSender::MulSender(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num * 64);
    sender->mMultType = type;

    prng = new PRNG(ZeroBlock);
}

MulSender::~MulSender()
{
    delete sender;
    delete prng;
}

void MulSender::mul(std::vector<uint64_t> &inputs, std::vector<uint64_t> &val)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<std::array<block, 2>> messages(numOts);

    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u8> compressedBits(kCompressedBytesPerValue * num);
    u64 offset = 0;
    for (u64 i = 0; i < num; ++i) {
        for (int shift = 0; shift < 64; ++shift) {
            const u64 idx = i * 64 + shift;
            const u64 mask = low(messages[idx][0]) + inputs[i];
            const u64 correction = (low(messages[idx][1]) ^ mask) << shift >> shift;
            const int byteCount = 8 - shift / 8;
            for (int j = 0; j < byteCount; ++j) {
                compressedBits[offset++] = static_cast<u8>(correction >> (8 * j));
            }
            val[i] -= (low(messages[idx][0]) << shift >> shift) << shift;
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
    receiver = new osuCrypto::SilentOtExtReceiver();
    receiver->configure(num * 64);
    receiver->mMultType = type;

    prng = new PRNG(OneBlock);
}

MulRecver::~MulRecver()
{
    delete receiver;
    delete prng;
}

void MulRecver::mul(std::vector<uint64_t> &inputs, std::vector<uint64_t> &val)
{
    coproto::sync_wait(receiver->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<u8> bytes(numOts / 8);

    for (size_t i = 0; i < num; i++) {
        u64 lowbits = inputs[i];
        for (int j = 0; j < 8; j++) {
            size_t idx = i * 8ULL + j;
            bytes[idx] = (lowbits >> (8 * j)) & 0xFF;
        }
    }

    std::vector<block> messages(numOts);

    BitVector choiceBit(bytes.data(), numOts);

    coproto::sync_wait(receiver->receive(choiceBit, messages, *prng, *socket));

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
            val[i / 64] += ((low(messages[i]) ^ msg) << shift >> shift) << (i % 64);
        } else {
            val[i / 64] += (low(messages[i]) << shift >> shift) << (i % 64);
        }
    }
}
