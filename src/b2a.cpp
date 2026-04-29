#include "b2a.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>
#include <cstring>
#include <vector>
#include "utils.h"

using namespace oc;

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

    std::vector<u8> bits(numOts);

    for (size_t i = 0; i < num; i++) {
        u64 lowbits = low(blk[i]);
        for (int j = 0; j < 64; j++) {
            size_t idx = i * 64ULL + j;
            bits[idx] = (lowbits >> j) & 1;
        }
    }

    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u64> correctMessages(numOts);

    std::vector<u8> compressedBits;

    for (size_t i = 0; i < numOts; i++) {
        u8 bit = bits[i];
        int shift = i % 64;
        u64 mask = low(messages[i][0]) + u64(bit);
        correctMessages[i] = (low(messages[i][1]) ^ mask) << shift >> shift;
        for (int j = 0; j < 8 - shift / 8; j++) {
            compressedBits.push_back(static_cast<uint8_t>(correctMessages[i] >> (8 * j)) & 0xFF);
        }
    }

    for (size_t i = 0; i < numOts; i++) {
        u8 bit = bits[i];
        int shift = i % 64;
        val[i / 64] += (u64(bit) + 2 * ((low(messages[i][0]) << shift) >> shift)) << shift;
    }

    // coproto::sync_wait(socket->send(compressedBits));

    if (compressedBits.size() <= (1 << 30)) {
        coproto::sync_wait(socket->send(compressedBits));
    } else {
        std::vector<u8> tmp;
        for (u64 i = 0; i < compressedBits.size(); i += (1 << 30)) {
            u64 len = std::min<u64>((u64)compressedBits.size() - i, (1 << 30));
            tmp.assign(compressedBits.begin() + i, compressedBits.begin() + i + len);
            coproto::sync_wait(socket->send(tmp));
        }
    }

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

    std::vector<u64> correctMessages(numOts);

    std::vector<u8> compressedBits(288 * num);

    // coproto::sync_wait(socket->recvResize(compressedBits));

    if (compressedBits.size() <= (1 << 30)) {
        coproto::sync_wait(socket->recv(compressedBits));
    } else {
        std::vector<u8> tmp;
        for (u64 i = 0; i < compressedBits.size(); i += (1 << 30)) {
            u64 len = std::min<u64>((u64)compressedBits.size() - i, (1 << 30));
            tmp.assign(compressedBits.begin() + i, compressedBits.begin() + i + len);
            coproto::sync_wait(socket->recv(tmp));
            std::copy(tmp.begin(), tmp.end(), compressedBits.begin() + i);
        }
    }

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