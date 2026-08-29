#include "b2a.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>
#include <cstring>
#include <thread>
#include <vector>
#include "common.h"
#include "utils.h"

using namespace oc;

namespace {

constexpr u64 kCompressedBytesPerValue = 288;

} // namespace

B2aSender::B2aSender(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num * 64);
    sender->mMultType = type;

    prng = new PRNG(ZeroBlock);
}

B2aSender::~B2aSender()
{
    delete sender;
    delete prng;
}

void B2aSender::b2a(std::vector<block> &blk, std::vector<u64> &val)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<std::array<block, 2>> messages(numOts);

    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u8> compressedBits(kCompressedBytesPerValue * num);
    u64 offset = 0;
    for (u64 i = 0; i < num; ++i) {
        const u64 lowbits = low(blk[i]);
        for (int shift = 0; shift < 64; ++shift) {
            const u64 idx = i * 64 + shift;
            const u8 bit = (lowbits >> shift) & 1;
            const u64 mask = low(messages[idx][0]) + u64(bit);
            const u64 correction = (low(messages[idx][1]) ^ mask) << shift >> shift;
            const int byteCount = 8 - shift / 8;
            for (int j = 0; j < byteCount; ++j) {
                compressedBits[offset++] = static_cast<u8>(correction >> (8 * j));
            }
            val[i] += (u64(bit) + 2 * ((low(messages[idx][0]) << shift) >> shift)) << shift;
        }
    }

    sendBytes(*socket, compressedBits);

    auto end_comm = socket->bytesReceived() + socket->bytesSent();
    if (LOG) {
        std::cout << "b2a comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;
    }
}

B2aRecver::B2aRecver(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    receiver = new osuCrypto::SilentOtExtReceiver();
    receiver->configure(num * 64);
    receiver->mMultType = type;

    prng = new PRNG(OneBlock);
}

B2aRecver::~B2aRecver()
{
    delete receiver;
    delete prng;
}

void B2aRecver::b2a(std::vector<block> &blk, std::vector<u64> &val)
{
    coproto::sync_wait(receiver->genSilentBaseOts(*prng, *socket));

    u64 numOts = num * 64;
    std::vector<block> messages(numOts);

    std::vector<u8> bytes(numOts / 8);

    for (size_t i = 0; i < num; i++) {
        u64 lowbits = low(blk[i]);
        for (int j = 0; j < 8; j++) {
            size_t idx = i * 8ULL + j;
            bytes[idx] = (lowbits >> (8 * j)) & 0xFF;
        }
    }

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
            val[i / 64] += (u64(choiceBit[i]) - 2 * (((low(messages[i]) ^ msg) << shift) >> shift)) << shift;
        } else {
            val[i / 64] += (u64(choiceBit[i]) - 2 * ((low(messages[i]) << shift) >> shift)) << shift;
        }
    }
}

void runB2a(
    std::vector<block> &sendShares,
    std::vector<block> &recvShares,
    std::vector<u64> &sendArithShares,
    std::vector<u64> &recvArithShares,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        B2aSender b2a(sendShares.size(), &sockets[sendSocket]);
        b2a.b2a(sendShares, sendArithShares);
    });
    std::thread recv([&] {
        B2aRecver b2a(recvShares.size(), &sockets[recvSocket]);
        b2a.b2a(recvShares, recvArithShares);
    });
    send.join();
    recv.join();
}
