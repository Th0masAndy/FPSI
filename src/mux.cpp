#include "mux.h"
#include <coproto/Socket/Socket.h>
#include <coproto/coproto.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <sys/types.h>
#include <thread>
#include <vector>
#include <volePSI/Defines.h>
#include <volePSI/GMW/Circuit.h>
#include <volePSI/GMW/Gmw.h>
#include <volePSI/Paxos.h>
#include <volePSI/config.h>
#include "cmp.h"
#include "utils.h"

void ssPEQT(u32 idx, std::vector<block> &input, BitVector &out, Socket &chl, u32 numThreads)
{
    u32 numBins = input.size();
    u64 keyBitLength = 40 + oc::log2ceil(numBins);
    u64 keyByteLength = oc::divCeil(keyBitLength, 8);
    PRNG prng(sysRandomSeed());

    oc::Matrix<u8> mLabel(numBins, keyByteLength);
    for (u32 i = 0; i < numBins; ++i) {
        memcpy(&mLabel(i, 0), &input[i], keyByteLength);
    }

    // call gmw
    auto cir = volePSI::isZeroCircuit(keyBitLength);

    // volePSI::BetaCircuit cir = volePSI::isZeroCircuit(keyBitLength);
    volePSI::Gmw cmp;
    cmp.init(mLabel.rows(), cir, numThreads, idx, prng.get());

    if (idx == 1) {
        cmp.setInput(0, mLabel);
    } else {
        cmp.implSetInput(0, mLabel, mLabel.cols());
    }

    coproto::sync_wait(cmp.run(chl));

    oc::Matrix<u8> mOut;
    mOut.resize(numBins, 1);
    cmp.getOutput(0, mOut);

    // get the final output
    out.resize(numBins);
    for (u32 i = 0; i < numBins; ++i) {
        out[i] = mOut(i, 0) & 1;
    }
    return;
}

MuxSender::MuxSender(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num);
    sender->mMultType = type;

    recver = new osuCrypto::SilentOtExtReceiver();
    recver->configure(num);
    recver->mMultType = type;

    prng = new PRNG(ZeroBlock);
}

MuxSender::~MuxSender()
{
    delete sender;
    delete recver;
    delete prng;
}

BitVector MuxSender::Mux(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();

    BitVector b0(num);
    ssPEQT(1, u0, b0, *socket, 1);

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v0[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    coproto::sync_wait(recver->receive(b0, res0, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    for (u64 i = 0; i < num; i++) {
        res0[i] = res0[i] ^ (b0[i] ? correctMessages1[i] : block(0, 0));
        res0[i] = res0[i] ^ messages[i][0];
        res0[i] = res0[i] ^ (b0[i] ? v0[i] : block(0, 0));
    }

    auto end_comm = socket->bytesReceived() + socket->bytesSent();

    if (LOG) {
        std::cout << "Mux comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;
    }

    return b0;
}

BitVector MuxSender::CmpRand(std::vector<u64> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 threshold)
{
    auto curr_comm = socket->bytesReceived() + socket->bytesSent();

    BitVector b0(num);
    std::vector<u8> res(2 * num);
    std::vector<u64> inputs(2 * num);

    for (u64 i = 0; i < num; i++) {
        inputs[i] = threshold - u0[i];
        inputs[num + i] = 0ULL - u0[i];
    }

    MillionaireProtocolSender cmp(2 * num, 64);
    cmp.compare(res.data(), inputs.data(), *socket);

    for (u64 i = 0; i < num; i++) {
        const bool localCorrection = threshold != 0
            && ((u0[i] < threshold) ^ (u0[i] == 0));
        b0[i] = (res[i] ^ res[num + i]
                    ^ static_cast<u8>(localCorrection))
            & 1;
    }

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v0[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    coproto::sync_wait(recver->receive(b0, res0, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    for (u64 i = 0; i < num; i++) {
        res0[i] = res0[i] ^ (b0[i] ? correctMessages1[i] : block(0, 0));
        res0[i] = res0[i] ^ messages[i][0];
        res0[i] = res0[i] ^ (b0[i] ? v0[i] : block(0, 0));
    }

    std::vector<block> randomMessage(num);
    std::vector<std::array<block, 2>> randomMessages(num);
    coproto::sync_wait(recver->receive(
        b0, randomMessage, *prng, *socket));
    coproto::sync_wait(sender->send(
        randomMessages, *prng, *socket));
    for (u64 i = 0; i < num; ++i) {
        res0[i] ^= randomMessage[i]
            ^ (b0[i] ? randomMessages[i][0]
                     : randomMessages[i][1]);
    }

    auto end_comm = socket->bytesReceived() + socket->bytesSent();

    if (LOG) {
        std::cout << "CmpRand comm: " << (end_comm - curr_comm) / 1024.0 / 1024.0 << " MB " << std::endl;
    }

    return b0;
}

void MuxSender::EqSel(std::vector<block> &u0, std::vector<block> &v0, std::vector<block> &res0, u64 len)
{
    std::vector<block> temp(v0.size());
    BitVector b0 = Mux(u0, v0, temp);

    u64 outputLen = v0.size() / len;
    BitVector b0_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b0_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b0_sum[i] = b0_sum[i] ^ b0[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(recver->receive(b0_sum, message, *prng, *socket));
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res0[i] = res0[i] ^ temp[i * len + j];
        }
        res0[i] = res0[i] ^ message[i] ^ (b0_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

void MuxSender::EqConstant(
    std::vector<block> &u0,
    std::vector<block> &v0,
    std::vector<block> &res0,
    u64 len,
    block constant)
{
    std::vector<block> temp(v0.size());
    BitVector b0 = Mux(u0, v0, temp);

    const u64 outputLen = v0.size() / len;
    for (u64 i = 0; i < outputLen; ++i) {
        bool selected = false;
        for (u64 j = 0; j < len; ++j) {
            const u64 index = i * len + j;
            selected ^= b0[index];
            res0[i] ^= temp[index];
        }
        if (!selected) {
            res0[i] ^= constant;
        }
    }
}

void MuxSender::EqSel(std::vector<block> &u0, std::vector<block> &res0, u64 len)
{
    BitVector b0(u0.size());
    ssPEQT(1, u0, b0, *socket, 1);

    u64 outputLen = u0.size() / len;
    BitVector b0_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b0_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b0_sum[i] = b0_sum[i] ^ b0[i * len + j];
        }
    }

    // for (u64 i = 0; i < outputLen; i++) {
    //     b0_sum[i] = b0_sum[i] ^ 1;
    // }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(recver->receive(b0_sum, message, *prng, *socket));
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        res0[i] = res0[i] ^ message[i] ^ (b0_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

BitVector MuxSender::Mux(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0)
{

    BitVector b0(num);
    ssPEQT(1, u0, b0, *socket, 1);

    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u64> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        u64 mask = low(messages[i][0]) + (v0[i] - 2 * u64(b0[i]) * v0[i]);
        correctMessages[i] = low(messages[i][1]) ^ mask;
    }

    coproto::sync_wait(socket->send(correctMessages));

    std::vector<block> message(num);
    coproto::sync_wait(recver->receive(b0, message, *prng, *socket));

    std::vector<u64> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    for (u64 i = 0; i < num; i++) {
        res0[i] = low(message[i]) ^ (b0[i] ? correctMessages1[i] : 0);
        res0[i] = res0[i] + u64(b0[i]) * v0[i];
        res0[i] = res0[i] - low(messages[i][0]);
    }

    return b0;
}

void MuxSender::EqSel(std::vector<block> &u0, std::vector<u64> &v0, std::vector<u64> &res0, u64 len)
{
    std::vector<u64> temp(v0.size());
    BitVector b0 = Mux(u0, v0, temp);

    u64 outputLen = v0.size() / len;
    BitVector b0_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b0_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b0_sum[i] = b0_sum[i] ^ b0[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(recver->receive(b0_sum, message, *prng, *socket));
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res0[i] = res0[i] + temp[i * len + j];
        }
        res0[i] = res0[i] + low(message[i]) - (b0_sum[i] ? low(messages[i][0]) : low(messages[i][1]));
    }
}

MuxRecver::MuxRecver(uint64_t num_, coproto::Socket *socket_) : num(num_), socket(socket_)
{
    sender = new osuCrypto::SilentOtExtSender();
    sender->configure(num);
    sender->mMultType = type;

    recver = new osuCrypto::SilentOtExtReceiver();
    recver->configure(num);
    recver->mMultType = type;

    prng = new PRNG(OneBlock);
}

MuxRecver::~MuxRecver()
{
    delete sender;
    delete recver;
    delete prng;
}

BitVector MuxRecver::Mux(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1)
{
    BitVector b1(num);
    ssPEQT(0, u1, b1, *socket, 1);

    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    coproto::sync_wait(recver->receive(b1, res1, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v1[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    for (u64 i = 0; i < num; i++) {
        res1[i] = res1[i] ^ (b1[i] ? correctMessages1[i] : block(0, 0));
        res1[i] = res1[i] ^ messages[i][0];
        res1[i] = res1[i] ^ (b1[i] ? v1[i] : block(0, 0));
    }

    return b1;
}

BitVector MuxRecver::CmpRand(std::vector<u64> &u1, std::vector<block> &v1, std::vector<block> &res1)
{
    BitVector b1(num);

    std::vector<u8> res(2 * num);
    std::vector<u64> inputs(2 * num);
    for (u64 i = 0; i < num; ++i) {
        inputs[i] = u1[i];
        inputs[num + i] = u1[i];
    }
    MillionaireProtocolRecver cmp(2 * num, 64);
    cmp.compare(res.data(), inputs.data(), *socket);

    for (u64 i = 0; i < num; i++) {
        b1[i] = (res[i] ^ res[num + i]) & 1;
    }

    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    coproto::sync_wait(recver->receive(b1, res1, *prng, *socket));

    std::vector<block> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<block> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        correctMessages[i] = messages[i][0] ^ messages[i][1] ^ v1[i];
    }

    coproto::sync_wait(socket->send(correctMessages));

    for (u64 i = 0; i < num; i++) {
        res1[i] = res1[i] ^ (b1[i] ? correctMessages1[i] : block(0, 0));
        res1[i] = res1[i] ^ messages[i][0];
        res1[i] = res1[i] ^ (b1[i] ? v1[i] : block(0, 0));
    }

    std::vector<std::array<block, 2>> randomMessages(num);
    std::vector<block> randomMessage(num);
    coproto::sync_wait(sender->send(
        randomMessages, *prng, *socket));
    coproto::sync_wait(recver->receive(
        b1, randomMessage, *prng, *socket));
    for (u64 i = 0; i < num; ++i) {
        res1[i] ^= randomMessage[i]
            ^ (b1[i] ? randomMessages[i][0]
                     : randomMessages[i][1]);
    }

    return b1;
}

void MuxRecver::EqSel(std::vector<block> &u1, std::vector<block> &v1, std::vector<block> &res1, u64 len)
{
    std::vector<block> temp(v1.size());
    BitVector b1 = Mux(u1, v1, temp);

    u64 outputLen = v1.size() / len;
    BitVector b1_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b1_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b1_sum[i] = b1_sum[i] ^ b1[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(sender->send(messages, *prng, *socket));
    coproto::sync_wait(recver->receive(b1_sum, message, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res1[i] = res1[i] ^ temp[i * len + j];
        }
        res1[i] = res1[i] ^ message[i] ^ (b1_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

void MuxRecver::EqConstant(
    std::vector<block> &u1,
    std::vector<block> &v1,
    std::vector<block> &res1,
    u64 len,
    block constant)
{
    std::vector<block> temp(v1.size());
    BitVector b1 = Mux(u1, v1, temp);

    const u64 outputLen = v1.size() / len;
    for (u64 i = 0; i < outputLen; ++i) {
        bool selected = false;
        for (u64 j = 0; j < len; ++j) {
            const u64 index = i * len + j;
            selected ^= b1[index];
            res1[i] ^= temp[index];
        }
        if (selected) {
            res1[i] ^= constant;
        }
    }
}

void MuxRecver::EqSel(std::vector<block> &u1, std::vector<block> &res1, u64 len)
{
    BitVector b1(u1.size());
    ssPEQT(0, u1, b1, *socket, 1);

    u64 outputLen = u1.size() / len;
    BitVector b1_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b1_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b1_sum[i] = b1_sum[i] ^ b1[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(sender->send(messages, *prng, *socket));
    coproto::sync_wait(recver->receive(b1_sum, message, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        res1[i] = res1[i] ^ message[i] ^ (b1_sum[i] ? messages[i][0] : messages[i][1]);
    }
}

BitVector MuxRecver::Mux(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1)
{
    BitVector b1(num);
    ssPEQT(0, u1, b1, *socket, 1);

    coproto::sync_wait(recver->genSilentBaseOts(*prng, *socket));
    coproto::sync_wait(sender->genSilentBaseOts(*prng, *socket));

    std::vector<block> message(num);
    coproto::sync_wait(recver->receive(b1, message, *prng, *socket));

    std::vector<u64> correctMessages1(num);

    coproto::sync_wait(socket->recv(correctMessages1));

    std::vector<std::array<block, 2>> messages(num);
    coproto::sync_wait(sender->send(messages, *prng, *socket));

    std::vector<u64> correctMessages(num);

    for (u64 i = 0; i < num; i++) {
        u64 mask = low(messages[i][0]) + (v1[i] - 2 * u64(b1[i]) * v1[i]);
        correctMessages[i] = low(messages[i][1]) ^ mask;
    }

    coproto::sync_wait(socket->send(correctMessages));

    for (u64 i = 0; i < num; i++) {
        res1[i] = low(message[i]) ^ (b1[i] ? correctMessages1[i] : 0);
        res1[i] = res1[i] + u64(b1[i]) * v1[i];
        res1[i] = res1[i] - low(messages[i][0]);
    }

    return b1;
}

void MuxRecver::EqSel(std::vector<block> &u1, std::vector<u64> &v1, std::vector<u64> &res1, u64 len)
{
    std::vector<u64> temp(v1.size());
    BitVector b1 = Mux(u1, v1, temp);

    u64 outputLen = v1.size() / len;
    BitVector b1_sum(outputLen);
    for (u64 i = 0; i < outputLen; i++) {
        b1_sum[i] = false;
        for (u64 j = 0; j < len; j++) {
            b1_sum[i] = b1_sum[i] ^ b1[i * len + j];
        }
    }

    std::vector<block> message(outputLen);
    std::vector<std::array<block, 2>> messages(outputLen);

    coproto::sync_wait(sender->send(messages, *prng, *socket));
    coproto::sync_wait(recver->receive(b1_sum, message, *prng, *socket));

    for (u64 i = 0; i < outputLen; i++) {
        for (u64 j = 0; j < len; j++) {
            res1[i] = res1[i] + temp[i * len + j];
        }
        res1[i] = res1[i] + low(message[i]) - (b1_sum[i] ? low(messages[i][0]) : low(messages[i][1]));
    }
}

void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<block> &sendValues,
    std::vector<block> &recvValues,
    std::vector<block> &sendResults,
    std::vector<block> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        MuxSender mux(sendSelectors.size(), &sockets[sendSocket]);
        mux.EqSel(
            sendSelectors, sendValues, sendResults, len);
    });
    std::thread recv([&] {
        MuxRecver mux(recvSelectors.size(), &sockets[recvSocket]);
        mux.EqSel(
            recvSelectors, recvValues, recvResults, len);
    });
    send.join();
    recv.join();
}

void runEqConstant(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<block> &sendValues,
    std::vector<block> &recvValues,
    std::vector<block> &sendResults,
    std::vector<block> &recvResults,
    u64 len,
    block constant,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        MuxSender mux(sendSelectors.size(), &sockets[sendSocket]);
        mux.EqConstant(
            sendSelectors, sendValues, sendResults, len, constant);
    });
    std::thread recv([&] {
        MuxRecver mux(recvSelectors.size(), &sockets[recvSocket]);
        mux.EqConstant(
            recvSelectors, recvValues, recvResults, len, constant);
    });
    send.join();
    recv.join();
}

void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<block> &sendResults,
    std::vector<block> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        MuxSender mux(sendResults.size(), &sockets[sendSocket]);
        mux.EqSel(sendSelectors, sendResults, len);
    });
    std::thread recv([&] {
        MuxRecver mux(recvResults.size(), &sockets[recvSocket]);
        mux.EqSel(recvSelectors, recvResults, len);
    });
    send.join();
    recv.join();
}

void runEqSel(
    std::vector<block> &sendSelectors,
    std::vector<block> &recvSelectors,
    std::vector<u64> &sendValues,
    std::vector<u64> &recvValues,
    std::vector<u64> &sendResults,
    std::vector<u64> &recvResults,
    u64 len,
    std::array<coproto::AsioSocket, 2> &sockets,
    bool roleInverse)
{
    const size_t sendSocket = roleInverse ? 1 : 0;
    const size_t recvSocket = roleInverse ? 0 : 1;
    std::thread send([&] {
        MuxSender mux(sendSelectors.size(), &sockets[sendSocket]);
        mux.EqSel(sendSelectors, sendValues, sendResults, len);
    });
    std::thread recv([&] {
        MuxRecver mux(recvSelectors.size(), &sockets[recvSocket]);
        mux.EqSel(recvSelectors, recvValues, recvResults, len);
    });
    send.join();
    recv.join();
}
