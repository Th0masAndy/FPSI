#include "filter.h"
#include <cmath>
#include <cstdlib>
#include <stdexcept>
#include <thread>
#include "SoOPPRF.h"
#include "b2a.h"
#include "eq.h"
#include "mul.h"
#include "mux.h"

using namespace oc;

namespace {

struct SoOpprfInput {
    std::vector<block> keys;
    std::vector<block> values;
    std::vector<block> queryKeys;
};

struct BlockMuxInput {
    std::vector<block> selectors;
    std::vector<block> values;
};

struct PrefixLpMpcInput {
    std::vector<block> selectors;
    std::vector<block> valueShares;
};

std::vector<block> xorDimensions(const std::vector<block> &values, u64 n, u64 d)
{
    std::vector<block> shares(n);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            shares[i] ^= values[i * d + j];
        }
    }
    return shares;
}

std::vector<u64> sumDimensions(const std::vector<u64> &values, u64 n, u64 d)
{
    std::vector<u64> sums(n, 0);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            sums[i] += values[i * d + j];
        }
    }
    return sums;
}

std::vector<u8> makeChoiceBits(u64 n, const std::vector<u64> &matches, u64 groupSize = 1)
{
    std::vector<u8> choiceBits(n, 0);
    for (const auto match : matches) {
        choiceBits[match / groupSize] = 1;
    }
    return choiceBits;
}

SoOpprfInput makeNormalSoOpprfInput(const FilterContext &context, int metric)
{
    const auto n = context.config.n;
    const auto d = context.config.dimension;
    const auto delta = context.config.delta;
    SoOpprfInput input;
    input.queryKeys.resize(n * d);
    input.keys.resize(n * d * (2 * delta + 1));
    input.values.resize(input.keys.size());

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            input.queryKeys[i * d + j] = block(high(context.sendIds[i]) << 8, 0)
                ^ block(j, context.sendSet[i][j]);
        }
    }

    u64 index = 0;
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            for (int offset = -delta; offset <= delta; ++offset) {
                input.keys[index] = block(high(context.recvIds[i]) << 8, 0)
                    ^ block(j, context.recvSet[i][j] + offset);
                input.values[index] = metric == 0
                    ? ZeroBlock
                    : block(0, integerPow(std::abs(offset), metric));
                ++index;
            }
        }
    }
    return input;
}

SoOpprfInput makePrefixL0SoOpprfInput(
    const FilterContext &context,
    const PrefixFilterParams &prefix)
{
    const auto n = context.config.n;
    const auto d = context.config.dimension;
    const auto delta = context.config.delta;
    const u64 prefixLen = prefix.prefixLens.size();
    const u64 encodedCount = n * d * prefix.encodedPrefixCount;
    SoOpprfInput input;
    input.queryKeys.resize(n * d * prefixLen);

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            auto pointPrefixes = getPrefixSet(context.sendSet[i][j], prefix.prefixLens);
            for (u64 k = 0; k < prefixLen; ++k) {
                input.queryKeys[i * d * prefixLen + j * prefixLen + k] =
                    block(high(context.sendIds[i]) << 8, 0)
                    ^ block(j << 4, 0) ^ pointPrefixes[k];
            }

            auto intervalPrefixes = getIntervalPrefixSet(
                context.recvSet[i][j] - delta,
                context.recvSet[i][j] + delta,
                prefix.prefixLens);
            for (const auto &value : intervalPrefixes) {
                input.keys.push_back(block(high(context.recvIds[i]) << 8, 0)
                    ^ block(j << 4, 0) ^ value);
                input.values.push_back(ZeroBlock);
            }
        }
    }

    PRNG paddingPrng(sysRandomSeed());
    while (input.keys.size() < encodedCount) {
        input.keys.push_back(paddingPrng.get<block>());
        input.values.push_back(paddingPrng.get<block>());
    }
    return input;
}

SoOpprfInput makePrefixLpSoOpprfInput(
    const FilterContext &context,
    const PrefixFilterParams &prefix)
{
    const auto n = context.config.n;
    const auto d = context.config.dimension;
    const auto delta = context.config.delta;
    const auto metric = context.config.metric;
    const u64 halfPrefixLen = prefix.prefixLens.size();
    const u64 prefixLen = 2 * halfPrefixLen;
    const int okvsBatch = metric / 2 + 1;
    const u64 encodedCount = n * d * prefix.encodedPrefixCount * okvsBatch;
    SoOpprfInput input;
    input.queryKeys.resize(okvsBatch * n * d * prefixLen);

    for (int batch = 0; batch < okvsBatch; ++batch) {
        for (u64 i = 0; i < n; ++i) {
            for (u64 j = 0; j < d; ++j) {
                auto pointPrefixes = getPrefixSet(context.sendSet[i][j], prefix.prefixLens);
                for (u64 side = 0; side < 2; ++side) {
                    for (u64 k = 0; k < halfPrefixLen; ++k) {
                        const u64 index = batch * n * d * prefixLen
                            + i * d * prefixLen + j * prefixLen
                            + side * halfPrefixLen + k;
                        input.queryKeys[index] = block(high(context.sendIds[i]) << 12, 0)
                            ^ block((j << 8) | (batch << 6) | (side << 4), 0)
                            ^ pointPrefixes[k];
                    }
                }
            }
        }
    }

    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            auto lowerPrefixes = getIntervalPrefixSet(
                context.recvSet[i][j] - delta,
                context.recvSet[i][j] - 1,
                prefix.prefixLens);
            auto upperPrefixes = getIntervalPrefixSet(
                context.recvSet[i][j],
                context.recvSet[i][j] + delta,
                prefix.prefixLens);

            for (const auto &value : lowerPrefixes) {
                const auto bound = upBound(value);
                for (int batch = 0; batch < okvsBatch; ++batch) {
                    input.keys.push_back(block(high(context.recvIds[i]) << 12, 0)
                        ^ block((j << 8) | (batch << 6), 0) ^ value);
                    input.values.push_back(batch == 0
                            ? block(0, integerPow(context.recvSet[i][j] - bound, batch + 1))
                            : block(integerPow(context.recvSet[i][j] - bound, batch + 1), 0));
                }
            }
            for (const auto &value : upperPrefixes) {
                const auto bound = upBound(value);
                for (int batch = 0; batch < okvsBatch; ++batch) {
                    input.keys.push_back(block(high(context.recvIds[i]) << 12, 0)
                        ^ block((j << 8) | (batch << 6) | (1 << 4), 0) ^ value);
                    input.values.push_back(batch == 0
                            ? block(0, integerPow(bound - context.recvSet[i][j], batch + 1))
                            : block(integerPow(bound - context.recvSet[i][j], batch + 1), 0));
                }
            }
        }
    }

    if (input.keys.size() > encodedCount) {
        throw std::runtime_error("filterKey size wrong");
    }
    PRNG paddingPrng(sysRandomSeed());
    while (input.keys.size() < encodedCount) {
        input.keys.push_back(paddingPrng.get<block>());
        input.values.push_back(paddingPrng.get<block>());
    }
    return input;
}

BlockMuxInput makeBlockMuxInput(const std::vector<block> &shares)
{
    BlockMuxInput input {
        std::vector<block>(shares.size()),
        std::vector<block>(shares.size()),
    };
    for (u64 i = 0; i < shares.size(); ++i) {
        input.selectors[i] = block(0, high(shares[i]));
        input.values[i] = block(0, low(shares[i]));
    }
    return input;
}

PrefixLpMpcInput makePrefixLpMpcInput(
    const std::vector<block> &shares,
    u64 baseCount,
    int metric)
{
    PrefixLpMpcInput input {
        std::vector<block>(baseCount),
        std::vector<block>(baseCount * metric),
    };
    for (u64 i = 0; i < baseCount; ++i) {
        input.selectors[i] = block(0, high(shares[i]));
        input.valueShares[i] = block(0, low(shares[i]));
    }
    if (metric == 2) {
        for (u64 i = 0; i < baseCount; ++i) {
            input.valueShares[i + baseCount] = block(0, high(shares[i + baseCount]));
        }
    }
    return input;
}

void runBlockMux(
    BlockMuxInput &sendInput,
    BlockMuxInput &recvInput,
    u64 outputCount,
    u64 groupSize,
    std::vector<block> &sendOutput,
    std::vector<block> &recvOutput,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    sendOutput.resize(outputCount);
    recvOutput.resize(outputCount);

    std::thread send([&] {
        MuxSender mux(sendInput.selectors.size(), &sockets[0]);
        mux.EqSel(sendInput.selectors, sendInput.values, sendOutput, groupSize);
    });
    std::thread recv([&] {
        MuxRecver mux(recvInput.selectors.size(), &sockets[1]);
        mux.EqSel(recvInput.selectors, recvInput.values, recvOutput, groupSize);
    });
    send.join();
    recv.join();
}

void runArithMux(
    std::vector<block> &sendSelectors,
    std::vector<u64> &sendValues,
    std::vector<block> &recvSelectors,
    std::vector<u64> &recvValues,
    u64 outputCount,
    u64 groupSize,
    std::vector<u64> &sendOutput,
    std::vector<u64> &recvOutput,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    sendOutput.resize(outputCount);
    recvOutput.resize(outputCount);

    std::thread send([&] {
        MuxSender mux(sendSelectors.size(), &sockets[0]);
        mux.EqSel(sendSelectors, sendValues, sendOutput, groupSize);
    });
    std::thread recv([&] {
        MuxRecver mux(recvSelectors.size(), &sockets[1]);
        mux.EqSel(recvSelectors, recvValues, recvOutput, groupSize);
    });
    send.join();
    recv.join();
}

} // namespace

NormalFilterL0::NormalFilterL0(const FilterContext &context)
    : mContext(context)
{
}

std::vector<u8> NormalFilterL0::run()
{
    const auto n = mContext.config.n;
    const auto d = mContext.config.dimension;
    auto soOpprfInput = makeNormalSoOpprfInput(mContext, 0);
    std::vector<block> recvShares(soOpprfInput.queryKeys.size());
    std::vector<block> sendShares(soOpprfInput.queryKeys.size());
    runSoOpprf(
        soOpprfInput.keys,
        soOpprfInput.values,
        soOpprfInput.queryKeys,
        recvShares,
        sendShares,
        mContext.sockets,
        true);

    auto sendPeqtInputs = xorDimensions(sendShares, n, d);
    auto recvPeqtInputs = xorDimensions(recvShares, n, d);
    std::vector<u64> matches;
    runPeqt(sendPeqtInputs, recvPeqtInputs, matches, mContext.sockets);
    return makeChoiceBits(n, matches);
}

NormalFilterLp::NormalFilterLp(const FilterContext &context)
    : mContext(context)
{
}

std::vector<u8> NormalFilterLp::run()
{
    const auto n = mContext.config.n;
    const auto d = mContext.config.dimension;
    const auto delta = mContext.config.delta;
    const auto metric = mContext.config.metric;
    const u64 deltaPow = integerPow(delta, metric);
    const u64 prefixLen = static_cast<u64>(std::ceil(std::log2(deltaPow + 1)));

    auto soOpprfInput = makeNormalSoOpprfInput(mContext, metric);
    std::vector<block> recvShares(soOpprfInput.queryKeys.size());
    std::vector<block> sendShares(soOpprfInput.queryKeys.size());
    runSoOpprf(
        soOpprfInput.keys,
        soOpprfInput.values,
        soOpprfInput.queryKeys,
        recvShares,
        sendShares,
        mContext.sockets,
        true);

    std::vector<u64> sendArithShares(sendShares.size());
    std::vector<u64> recvArithShares(recvShares.size());
    runB2a(
        sendShares,
        recvShares,
        sendArithShares,
        recvArithShares,
        mContext.sockets);

    auto sendDis = sumDimensions(sendArithShares, n, d);
    auto recvDis = sumDimensions(recvArithShares, n, d);
    std::vector<u64> matches;
    runIntervalTest(sendDis, recvDis, deltaPow, prefixLen, matches, mContext.sockets);
    return makeChoiceBits(n, matches, prefixLen);
}

PrefixFilterL0::PrefixFilterL0(
    const FilterContext &context,
    const PrefixFilterParams &prefix)
    : mContext(context)
    , mPrefix(prefix)
{
}

std::vector<u8> PrefixFilterL0::run()
{
    const auto n = mContext.config.n;
    const auto d = mContext.config.dimension;
    const u64 prefixLen = mPrefix.prefixLens.size();
    auto soOpprfInput = makePrefixL0SoOpprfInput(mContext, mPrefix);
    std::vector<block> recvShares(soOpprfInput.queryKeys.size());
    std::vector<block> sendShares(soOpprfInput.queryKeys.size());
    runSoOpprf(
        soOpprfInput.keys,
        soOpprfInput.values,
        soOpprfInput.queryKeys,
        recvShares,
        sendShares,
        mContext.sockets,
        true);

    auto sendMuxInput = makeBlockMuxInput(sendShares);
    auto recvMuxInput = makeBlockMuxInput(recvShares);
    std::vector<block> sendSel;
    std::vector<block> recvSel;
    runBlockMux(
        sendMuxInput,
        recvMuxInput,
        n * d,
        prefixLen,
        sendSel,
        recvSel,
        mContext.sockets);

    auto sendPeqtInputs = xorDimensions(sendSel, n, d);
    auto recvPeqtInputs = xorDimensions(recvSel, n, d);
    std::vector<u64> matches;
    runPeqt(sendPeqtInputs, recvPeqtInputs, matches, mContext.sockets);
    return makeChoiceBits(n, matches);
}

PrefixFilterLp::PrefixFilterLp(
    const FilterContext &context,
    const PrefixFilterParams &prefix)
    : mContext(context)
    , mPrefix(prefix)
{
}

std::vector<u8> PrefixFilterLp::run()
{
    const auto n = mContext.config.n;
    const auto d = mContext.config.dimension;
    const auto delta = mContext.config.delta;
    const auto metric = mContext.config.metric;
    if (metric != 1 && metric != 2) {
        throw std::runtime_error("lp not supported");
    }

    const u64 halfPrefixLen = mPrefix.prefixLens.size();
    const u64 prefixLen = 2 * halfPrefixLen;
    const u64 valueCount = n * d * prefixLen;
    const u64 deltaPow = integerPow(delta, metric);
    const u64 disPrefixLen = static_cast<u64>(std::ceil(std::log2(deltaPow * 2 + 1)));

    auto soOpprfInput = makePrefixLpSoOpprfInput(mContext, mPrefix);
    std::vector<block> recvShares(soOpprfInput.queryKeys.size());
    std::vector<block> sendShares(soOpprfInput.queryKeys.size());
    runSoOpprf(
        soOpprfInput.keys,
        soOpprfInput.values,
        soOpprfInput.queryKeys,
        recvShares,
        sendShares,
        mContext.sockets,
        true);

    auto sendMpcInput = makePrefixLpMpcInput(sendShares, valueCount, metric);
    auto recvMpcInput = makePrefixLpMpcInput(recvShares, valueCount, metric);
    std::vector<u64> sendArithShares(sendMpcInput.valueShares.size());
    std::vector<u64> recvArithShares(recvMpcInput.valueShares.size());
    runB2a(
        sendMpcInput.valueShares,
        recvMpcInput.valueShares,
        sendArithShares,
        recvArithShares,
        mContext.sockets);

    std::vector<u64> localDis(valueCount, 0);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < d; ++j) {
            auto pointPrefixes = getPrefixSet(mContext.sendSet[i][j], mPrefix.prefixLens);
            for (u64 side = 0; side < 2; ++side) {
                for (u64 k = 0; k < halfPrefixLen; ++k) {
                    const u64 index = i * d * prefixLen + j * prefixLen
                        + side * halfPrefixLen + k;
                    localDis[index] = side == 0
                        ? upBound(pointPrefixes[k]) - mContext.sendSet[i][j]
                        : mContext.sendSet[i][j] - upBound(pointPrefixes[k]);
                }
            }
        }
    }

    std::vector<u64> sendDisShares(valueCount, 0);
    std::vector<u64> recvDisShares(valueCount, 0);
    if (metric == 1) {
        for (u64 i = 0; i < valueCount; ++i) {
            sendDisShares[i] = sendArithShares[i] + localDis[i];
            recvDisShares[i] = recvArithShares[i];
        }
    } else {
        std::vector<u64> recvFirstShares(
            recvArithShares.begin(),
            recvArithShares.begin() + valueCount);
        std::vector<u64> sendProd(localDis.size());
        std::vector<u64> recvProd(recvFirstShares.size());
        runMul(
            localDis,
            recvFirstShares,
            sendProd,
            recvProd,
            mContext.sockets);

        for (u64 i = 0; i < valueCount; ++i) {
            sendDisShares[i] = localDis[i] * localDis[i]
                + 2 * localDis[i] * sendArithShares[i]
                + 2 * sendProd[i] + sendArithShares[i + valueCount];
            recvDisShares[i] = 2 * recvProd[i]
                + recvArithShares[i + valueCount];
        }
    }

    std::vector<u64> sendSelDis;
    std::vector<u64> recvSelDis;
    runArithMux(
        sendMpcInput.selectors,
        sendDisShares,
        recvMpcInput.selectors,
        recvDisShares,
        n * d,
        prefixLen,
        sendSelDis,
        recvSelDis,
        mContext.sockets);

    auto sendDis = sumDimensions(sendSelDis, n, d);
    auto recvDis = sumDimensions(recvSelDis, n, d);
    std::vector<u64> matches;
    runIntervalTest(sendDis, recvDis, deltaPow, disPrefixLen, matches, mContext.sockets);
    return makeChoiceBits(n, matches, disPrefixLen);
}
