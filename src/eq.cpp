#include "eq.h"
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <stdexcept>
#include <thread>
#include <vector>
#include "utils.h"

namespace {

std::vector<block> makeSendIntervalInputs(
    const std::vector<u64> &dis,
    u64 deltaPow,
    u64 prefixLen)
{
    std::vector<block> inputs;
    inputs.reserve(dis.size() * prefixLen);
    for (u64 i = 0; i < dis.size(); ++i) {
        auto prefixes = getIntervalPrefix(0ULL - dis[i], deltaPow - dis[i]);
        for (auto &prefix : prefixes) {
            prefix ^= block(i << 32, 0);
            inputs.push_back(prefix);
        }
    }

    const u64 expectedCount = dis.size() * prefixLen;
    if (inputs.size() > expectedCount) {
        throw std::runtime_error("interval sender input exceeds expected size");
    }

    PRNG paddingPrng(sysRandomSeed());
    while (inputs.size() < expectedCount) {
        inputs.push_back(paddingPrng.get<block>());
    }
    return inputs;
}

std::vector<block> makeRecvIntervalInputs(
    const std::vector<u64> &dis,
    u64 prefixLen)
{
    std::vector<block> inputs;
    inputs.reserve(dis.size() * prefixLen);
    for (u64 i = 0; i < dis.size(); ++i) {
        auto prefixes = getPrefix(dis[i], prefixLen);
        for (auto &prefix : prefixes) {
            prefix ^= block(i << 32, 0);
            inputs.push_back(prefix);
        }
    }
    const u64 expectedCount = dis.size() * prefixLen;
    if (inputs.size() != expectedCount) {
        throw std::runtime_error("interval receiver input size mismatch");
    }
    return inputs;
}

} // namespace

PEqTSender::PEqTSender(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_)
    : num(num_), numThreads(numThreads_), noCompress(noCompress_), socket(socket_)
{
    send = new RsPsiSender();
    send->init(num, num, 40, oc::ZeroBlock, false, numThreads);

    auto type = oc::DefaultMultType;

    send->setMultType(type);

    if (noCompress) {
        send->mCompress = false;
        send->mMaskSize = sizeof(block);
    }
}

void PEqTSender::eq(std::vector<block> &sendSet)
{
    coproto::sync_wait(send->run(sendSet, *socket));
}

PEqTSender::~PEqTSender()
{
    delete send;
}

PEqTRecver::PEqTRecver(uint64_t num_, uint64_t numThreads_, bool noCompress_, coproto::Socket *socket_)
    : num(num_), numThreads(numThreads_), noCompress(noCompress_), socket(socket_)
{
    recv = new RsPsiReceiver();
    recv->init(num, num, 40, oc::ZeroBlock, false, numThreads);

    auto type = oc::DefaultMultType;

    recv->setMultType(type);

    if (noCompress) {
        recv->mCompress = false;
        recv->mMaskSize = sizeof(block);
    }
}

void PEqTRecver::eq(std::vector<block> &recvSet, std::vector<u64> &intersection)
{
    coproto::sync_wait(recv->run(recvSet, *socket));
    intersection = recv->mIntersection;
}

PEqTRecver::~PEqTRecver()
{
    delete recv;
}

void runPeqt(
    std::vector<block> &sendInputs,
    std::vector<block> &recvInputs,
    std::vector<u64> &matches,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    std::thread send([&] {
        PEqTSender peqt(sendInputs.size(), 1, false, &sockets[0]);
        peqt.eq(sendInputs);
    });

    std::thread recv([&] {
        PEqTRecver peqt(recvInputs.size(), 1, false, &sockets[1]);
        peqt.eq(recvInputs, matches);
    });

    send.join();
    recv.join();
}

void runIntervalTest(
    const std::vector<u64> &sendDis,
    const std::vector<u64> &recvDis,
    u64 deltaPow,
    u64 prefixLen,
    std::vector<u64> &matches,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    auto sendInputs = makeSendIntervalInputs(sendDis, deltaPow, prefixLen);
    auto recvInputs = makeRecvIntervalInputs(recvDis, prefixLen);

    std::thread send([&] {
        PEqTSender peqt(sendInputs.size(), 1, false, &sockets[0]);
        peqt.eq(sendInputs);
    });

    std::thread recv([&] {
        PEqTRecver peqt(recvInputs.size(), 1, false, &sockets[1]);
        peqt.eq(recvInputs, matches);
    });

    send.join();
    recv.join();
}
