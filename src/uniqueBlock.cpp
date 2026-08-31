#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "SoOPPRF.h"
#include "b2a.h"
#include "common.h"
#include "eq.h"
#include "genData.h"
#include "mul.h"
#include "mux.h"
#include "param.h"
#include "protocol.h"
#include "utils.h"

// Memory optimization:
// Normal uniqueBlock may produce more than 2^31 programmed KVs, so they should
// not be encoded by one OKVS instance. Hash cells with a public seed, generate
// and encode fixed-capacity shards sequentially, and equally pad every shard to
// hide its distribution.

using namespace oc;

namespace {

enum class PrefixDistanceMode {
    Standard,
    Augmented,
};

struct PrefixDistanceInput {
    SoOpprfInput soOpprf;
    std::vector<u64> localOffsets;
    u64 groupSize;
    u64 valueCount;
    int batches;
};

struct PrefixMpcInput {
    std::vector<block> selectors;
    std::vector<block> valueShares;
};

const std::vector<u64> &prefixLensFor(int delta)
{
    const auto it = prefixLenMapNaive.find(delta);
    if (it == prefixLenMapNaive.end()) {
        throw std::invalid_argument("uniqueBlock prefix does not support this delta");
    }
    return it->second;
}

u64 encodedPrefixCountFor(int delta)
{
    const auto it = prefixNumMapNaive.find(delta);
    if (it == prefixNumMapNaive.end()) {
        throw std::invalid_argument("uniqueBlock prefix does not support this delta");
    }
    return it->second;
}

void padKeyValues(SoOpprfInput &input, u64 expectedCount)
{
    if (input.keys.size() != input.values.size()) {
        throw std::runtime_error("uniqueBlock key/value count mismatch");
    }
    if (input.keys.size() > expectedCount) {
        throw std::runtime_error("uniqueBlock encoded input exceeds its configured size");
    }

    input.keys.reserve(expectedCount);
    input.values.reserve(expectedCount);
    PRNG paddingPrng(sysRandomSeed());
    while (input.keys.size() < expectedCount) {
        input.keys.push_back(paddingPrng.get<block>());
        input.values.push_back(paddingPrng.get<block>());
    }
}

SoOpprfInput makeNormalInput(
    const PointSet &sendSet,
    const PointSet &recvSet,
    u64 n,
    std::size_t dimension,
    int delta,
    int metric)
{
    const u64 cellCount = 1ULL << dimension;
    const u64 offsetCount = 2 * static_cast<u64>(delta) + 1;
    const u64 encodedCount = n * dimension * cellCount * offsetCount;

    SoOpprfInput input;
    input.keys.reserve(encodedCount);
    input.values.reserve(encodedCount);
    input.queryKeys.resize(n * dimension);

    std::vector<u64> offsetValues(offsetCount);
    for (int offset = -delta; offset <= delta; ++offset) {
        offsetValues[offset + delta] = metric == 0
            ? 0
            : integerPow(std::abs(offset), metric);
    }

    for (u64 i = 0; i < n; ++i) {
        const auto cellId = cell(sendSet[i], 2 * delta);
        for (u64 j = 0; j < dimension; ++j) {
            input.queryKeys[i * dimension + j] =
                blake3_hash(cellId, j, sendSet[i][j]);
        }
    }

    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(recvSet[i], delta);
        for (u64 j = 0; j < dimension; ++j) {
            for (int offset = -delta; offset <= delta; ++offset) {
                const block value = metric == 0
                    ? ZeroBlock
                    : block(0, offsetValues[offset + delta]);
                for (u64 k = 0; k < neighbors.size(); ++k) {
                    input.keys.push_back(
                        blake3_hash(neighbors[k], j, recvSet[i][j] + offset));
                    input.values.push_back(value);
                }
            }
        }
    }

    if (input.keys.size() != encodedCount) {
        throw std::runtime_error("uniqueBlock normal input size mismatch");
    }
    return input;
}

SoOpprfInput makePrefixL0Input(
    const PointSet &sendSet,
    const PointSet &recvSet,
    u64 n,
    std::size_t dimension,
    int delta,
    const std::vector<u64> &prefixLens,
    u64 encodedPrefixCount)
{
    const u64 cellCount = 1ULL << dimension;
    const u64 prefixLen = prefixLens.size();
    const u64 encodedCount =
        n * dimension * cellCount * encodedPrefixCount;

    SoOpprfInput input;
    input.keys.reserve(encodedCount);
    input.values.reserve(encodedCount);
    input.queryKeys.resize(n * dimension * prefixLen);

    for (u64 i = 0; i < n; ++i) {
        const auto cellId = cell(sendSet[i], 2 * delta);
        for (u64 j = 0; j < dimension; ++j) {
            const auto prefixes = getPrefixSet(sendSet[i][j], prefixLens);
            if (prefixes.size() != prefixLen) {
                throw std::runtime_error("uniqueBlock query prefix count mismatch");
            }
            for (u64 k = 0; k < prefixLen; ++k) {
                input.queryKeys[
                    i * dimension * prefixLen + j * prefixLen + k] =
                    blake3_hash(cellId, j, prefixes[k]);
            }
        }
    }

    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(recvSet[i], delta);
        for (u64 j = 0; j < dimension; ++j) {
            const auto prefixes = getIntervalPrefixSet(
                recvSet[i][j] - delta,
                recvSet[i][j] + delta,
                prefixLens);
            for (const auto &prefix : prefixes) {
                for (u64 k = 0; k < neighbors.size(); ++k) {
                    input.keys.push_back(
                        blake3_hash(neighbors[k], j, prefix));
                    input.values.push_back(ZeroBlock);
                }
            }
        }
    }

    padKeyValues(input, encodedCount);
    return input;
}

PrefixDistanceInput makePrefixDistanceInput(
    const PointSet &sendSet,
    const PointSet &recvSet,
    u64 n,
    std::size_t dimension,
    int delta,
    int metric,
    const std::vector<u64> &prefixLens,
    u64 encodedPrefixCount,
    PrefixDistanceMode mode)
{
    const u64 halfPrefixLen = prefixLens.size();
    const u64 groupSize = 2 * halfPrefixLen;
    const int batches =
        mode == PrefixDistanceMode::Standard ? metric / 2 + 1 : 1;
    const u64 valueCount = n * dimension * groupSize;
    const u64 encodedCount = static_cast<u64>(batches)
        * n * dimension * (1ULL << dimension)
        * 2 * encodedPrefixCount;

    PrefixDistanceInput input {
        {},
        std::vector<u64>(valueCount),
        groupSize,
        valueCount,
        batches,
    };
    input.soOpprf.keys.reserve(encodedCount);
    input.soOpprf.values.reserve(encodedCount);
    input.soOpprf.queryKeys.resize(
        static_cast<u64>(batches) * valueCount);

    for (int batch = 0; batch < batches; ++batch) {
        for (u64 i = 0; i < n; ++i) {
            const auto cellId = cell(sendSet[i], 2 * delta);
            for (u64 j = 0; j < dimension; ++j) {
                const auto prefixes =
                    getPrefixSet(sendSet[i][j], prefixLens);
                if (prefixes.size() != halfPrefixLen) {
                    throw std::runtime_error(
                        "uniqueBlock query prefix count mismatch");
                }
                for (u64 side = 0; side < 2; ++side) {
                    for (u64 k = 0; k < halfPrefixLen; ++k) {
                        const u64 index =
                            static_cast<u64>(batch) * valueCount
                            + i * dimension * groupSize
                            + j * groupSize
                            + side * halfPrefixLen + k;
                        const u64 domain = mode == PrefixDistanceMode::Standard
                            ? (j << 8) | (static_cast<u64>(batch) << 6)
                                | (side << 4)
                            : (j << 8) | (side << 4);
                        input.soOpprf.queryKeys[index] =
                            blake3_hash(cellId, domain, prefixes[k]);

                        if (batch == 0) {
                            const u64 localIndex =
                                i * dimension * groupSize
                                + j * groupSize
                                + side * halfPrefixLen + k;
                            input.localOffsets[localIndex] = side == 0
                                ? upBound(prefixes[k]) - sendSet[i][j]
                                : sendSet[i][j] - upBound(prefixes[k]);
                        }
                    }
                }
            }
        }
    }

    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(recvSet[i], delta);
        for (u64 j = 0; j < dimension; ++j) {
            const auto lowerPrefixes = getIntervalPrefixSet(
                recvSet[i][j] - delta,
                recvSet[i][j] - 1,
                prefixLens);
            const auto upperPrefixes = getIntervalPrefixSet(
                recvSet[i][j],
                recvSet[i][j] + delta,
                prefixLens);

            const auto appendPrefixes =
                [&](const std::vector<block> &prefixes, u64 side) {
                    for (const auto &prefix : prefixes) {
                        const u64 bound = upBound(prefix);
                        const u64 distance = side == 0
                            ? recvSet[i][j] - bound
                            : bound - recvSet[i][j];
                        for (int batch = 0; batch < batches; ++batch) {
                            const u64 domain =
                                mode == PrefixDistanceMode::Standard
                                ? (j << 8)
                                    | (static_cast<u64>(batch) << 6)
                                    | (side << 4)
                                : (j << 8) | (side << 4);
                            const u64 power = mode
                                    == PrefixDistanceMode::Standard
                                ? integerPow(distance, batch + 1)
                                : distance;
                            const block value =
                                mode == PrefixDistanceMode::Standard
                                    && batch != 0
                                ? block(power, 0)
                                : block(0, power);
                            for (u64 k = 0; k < neighbors.size(); ++k) {
                                input.soOpprf.keys.push_back(
                                    blake3_hash(
                                        neighbors[k], domain, prefix));
                                input.soOpprf.values.push_back(value);
                            }
                        }
                    }
                };

            appendPrefixes(lowerPrefixes, 0);
            appendPrefixes(upperPrefixes, 1);
        }
    }

    padKeyValues(input.soOpprf, encodedCount);
    return input;
}

PrefixMpcInput makePrefixMpcInput(
    const std::vector<block> &shares,
    u64 valueCount,
    int metric,
    PrefixDistanceMode mode)
{
    const u64 valueShareCount =
        mode == PrefixDistanceMode::Standard
        ? valueCount * metric
        : valueCount;
    if (shares.size() < valueShareCount) {
        throw std::runtime_error("uniqueBlock OPPRF share count mismatch");
    }

    PrefixMpcInput input {
        std::vector<block>(valueCount),
        std::vector<block>(valueShareCount),
    };
    for (u64 i = 0; i < valueCount; ++i) {
        input.selectors[i] = block(0, high(shares[i]));
        input.valueShares[i] = block(0, low(shares[i]));
    }
    if (mode == PrefixDistanceMode::Standard && metric == 2) {
        for (u64 i = 0; i < valueCount; ++i) {
            input.valueShares[i + valueCount] =
                block(0, high(shares[i + valueCount]));
        }
    }
    return input;
}

std::vector<block> xorDimensions(
    const std::vector<block> &values,
    u64 n,
    std::size_t dimension)
{
    if (values.size() != n * dimension) {
        throw std::runtime_error("uniqueBlock block share count mismatch");
    }
    std::vector<block> result(n);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < dimension; ++j) {
            result[i] ^= values[i * dimension + j];
        }
    }
    return result;
}

std::vector<u64> sumDimensions(
    const std::vector<u64> &values,
    u64 n,
    std::size_t dimension)
{
    if (values.size() != n * dimension) {
        throw std::runtime_error(
            "uniqueBlock arithmetic share count mismatch");
    }
    std::vector<u64> result(n, 0);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < dimension; ++j) {
            result[i] += values[i * dimension + j];
        }
    }
    return result;
}

std::vector<u8> makeChoiceBits(
    u64 n,
    const std::vector<u64> &matches,
    u64 groupSize = 1)
{
    std::vector<u8> choiceBits(n, 0);
    for (const u64 match : matches) {
        const u64 index = match / groupSize;
        if (index >= n) {
            throw std::runtime_error("uniqueBlock match index out of range");
        }
        choiceBits[index] = 1;
    }
    return choiceBits;
}

void runPrefixDistance(
    const FpsiConfig &config,
    PrefixDistanceMode mode)
{
    const auto &prefixLens = prefixLensFor(config.delta);
    const u64 encodedPrefixCount =
        encodedPrefixCountFor(config.delta);

    PRNG dataPrng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(
        config, dataPrng);
    const auto &sendSet = testCase.sendSet;
    const auto &recvSet = testCase.recvSet;
    const auto &expectedIndices = testCase.expectedOutputIndices;

    oc::Timer timer;
    timer.setTimePoint("begin");
    auto input = makePrefixDistanceInput(
        sendSet,
        recvSet,
        config.n,
        config.dimension,
        config.delta,
        config.metric,
        prefixLens,
        encodedPrefixCount,
        mode);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    const u64 deltaPow =
        integerPow(config.delta, config.metric);
    const u64 disPrefixLen = static_cast<u64>(
        std::ceil(std::log2(deltaPow + 1)));

    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> recvOpprfShares(
            input.soOpprf.queryKeys.size());
        std::vector<block> sendOpprfShares(
            input.soOpprf.queryKeys.size());
        runSoOpprf(
            input.soOpprf.keys,
            input.soOpprf.values,
            input.soOpprf.queryKeys,
            recvOpprfShares,
            sendOpprfShares,
            sockets,
            true);
        timer.setTimePoint("OPPRF done");

        auto sendMpcInput = makePrefixMpcInput(
            sendOpprfShares,
            input.valueCount,
            config.metric,
            mode);
        auto recvMpcInput = makePrefixMpcInput(
            recvOpprfShares,
            input.valueCount,
            config.metric,
            mode);

        std::vector<u64> sendArithShares(
            sendMpcInput.valueShares.size());
        std::vector<u64> recvArithShares(
            recvMpcInput.valueShares.size());
        runB2a(
            sendMpcInput.valueShares,
            recvMpcInput.valueShares,
            sendArithShares,
            recvArithShares,
            sockets);
        timer.setTimePoint("B2A done");

        std::vector<u64> sendDisShares(input.valueCount, 0);
        std::vector<u64> recvDisShares(input.valueCount, 0);
        if (config.metric == 1) {
            for (u64 i = 0; i < input.valueCount; ++i) {
                sendDisShares[i] =
                    sendArithShares[i] + input.localOffsets[i];
                recvDisShares[i] = recvArithShares[i];
            }
        } else if (mode == PrefixDistanceMode::Standard) {
            std::vector<u64> recvFirstShares(
                recvArithShares.begin(),
                recvArithShares.begin() + input.valueCount);
            std::vector<u64> sendProducts(input.valueCount);
            std::vector<u64> recvProducts(input.valueCount);
            runMul(
                input.localOffsets,
                recvFirstShares,
                sendProducts,
                recvProducts,
                sockets);

            for (u64 i = 0; i < input.valueCount; ++i) {
                const u64 local = input.localOffsets[i];
                sendDisShares[i] = local * local
                    + 2 * local * sendArithShares[i]
                    + 2 * sendProducts[i]
                    + sendArithShares[i + input.valueCount];
                recvDisShares[i] = 2 * recvProducts[i]
                    + recvArithShares[i + input.valueCount];
            }
        } else {
            std::vector<u64> shiftedSendShares(input.valueCount);
            for (u64 i = 0; i < input.valueCount; ++i) {
                shiftedSendShares[i] =
                    sendArithShares[i] + input.localOffsets[i];
            }

            std::vector<u64> sendProducts(input.valueCount);
            std::vector<u64> recvProducts(input.valueCount);
            runMul(
                shiftedSendShares,
                recvArithShares,
                sendProducts,
                recvProducts,
                sockets);

            for (u64 i = 0; i < input.valueCount; ++i) {
                sendDisShares[i] =
                    shiftedSendShares[i] * shiftedSendShares[i]
                    + 2 * sendProducts[i];
                recvDisShares[i] =
                    recvArithShares[i] * recvArithShares[i]
                    + 2 * recvProducts[i];
            }
        }
        timer.setTimePoint("distance shares done");

        std::vector<u64> sendSelected(
            config.n * config.dimension);
        std::vector<u64> recvSelected(
            config.n * config.dimension);
        runEqSel(
            sendMpcInput.selectors,
            recvMpcInput.selectors,
            sendDisShares,
            recvDisShares,
            sendSelected,
            recvSelected,
            input.groupSize,
            sockets);
        timer.setTimePoint("Mux done");

        auto sendDis =
            sumDimensions(sendSelected, config.n, config.dimension);
        auto recvDis =
            sumDimensions(recvSelected, config.n, config.dimension);
        std::vector<u64> matches;
        runIntervalTest(
            sendDis,
            recvDis,
            deltaPow,
            disPrefixLen,
            matches,
            sockets);
        auto choiceBits =
            makeChoiceBits(config.n, matches, disPrefixLen);
        timer.setTimePoint("Interval test done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(sendSet, choiceBits, transferredElements, sockets);
        if (config.verbose) {
            correctCheck(choiceBits, expectedIndices);
        }
    }

    auto end = timer.setTimePoint("OT done");
    if (config.verbose) {
        std::cout << timer << std::endl;
    }
    const double comm =
        (sockets[0].bytesReceived() + sockets[0].bytesSent())
        / 1024.0 / 1024.0 / config.trials;
    const double comp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            end - preprocessingDone)
            .count()
        / double(1000 * 1000) / config.trials;
    printFpsiResult(
        "prefix", "recv", "uniqBlk", config.metric,
        config.dimension, config.delta, config.n, comm, comp);
}

} // namespace

void fuzzyPsiUniqueBlockPxL0(const FpsiConfig &config)
{
    const auto &prefixLens = prefixLensFor(2 * config.delta);
    const u64 encodedPrefixCount =
        encodedPrefixCountFor(2 * config.delta);

    PRNG dataPrng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(
        config, dataPrng);
    const auto &sendSet = testCase.sendSet;
    const auto &recvSet = testCase.recvSet;
    const auto &expectedIndices = testCase.expectedOutputIndices;

    oc::Timer timer;
    timer.setTimePoint("begin");
    auto input = makePrefixL0Input(
        sendSet,
        recvSet,
        config.n,
        config.dimension,
        config.delta,
        prefixLens,
        encodedPrefixCount);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    const u64 prefixLen = prefixLens.size();
    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> sendShares(input.queryKeys.size());
        std::vector<block> recvShares(input.queryKeys.size());
        runSoOpprf(
            input.keys,
            input.values,
            input.queryKeys,
            sendShares,
            recvShares,
            sockets);
        timer.setTimePoint("OPPRF done");

        std::vector<block> sendSelected(
            config.n * config.dimension);
        std::vector<block> recvSelected(
            config.n * config.dimension);
        runEqSel(
            sendShares,
            recvShares,
            sendSelected,
            recvSelected,
            prefixLen,
            sockets,
            true);
        timer.setTimePoint("Mux done");

        auto sendPeqtInputs = xorDimensions(
            sendSelected, config.n, config.dimension);
        auto recvPeqtInputs = xorDimensions(
            recvSelected, config.n, config.dimension);
        std::vector<u64> matches;
        runPeqt(
            sendPeqtInputs,
            recvPeqtInputs,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(config.n, matches);
        timer.setTimePoint("EQT done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(sendSet, choiceBits, transferredElements, sockets);
        if (config.verbose) {
            correctCheck(choiceBits, expectedIndices);
        }
    }

    auto end = timer.setTimePoint("OT done");
    if (config.verbose) {
        std::cout << timer << std::endl;
    }
    const double comm =
        (sockets[0].bytesReceived() + sockets[0].bytesSent())
        / 1024.0 / 1024.0 / config.trials;
    const double comp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            end - preprocessingDone)
            .count()
        / double(1000 * 1000) / config.trials;
    printFpsiResult(
        "prefix", "recv", "uniqBlk", 0,
        config.dimension, config.delta, config.n, comm, comp);
}

void fuzzyPsiUniqueBlockPxLp(const FpsiConfig &config)
{
    runPrefixDistance(config, PrefixDistanceMode::Standard);
}

void fuzzyPsiUniqueBlockPxAugLp(const FpsiConfig &config)
{
    runPrefixDistance(config, PrefixDistanceMode::Augmented);
}

void fuzzyPsiUniqueBlockL0(const FpsiConfig &config)
{
    PRNG dataPrng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(
        config, dataPrng);
    const auto &sendSet = testCase.sendSet;
    const auto &recvSet = testCase.recvSet;
    const auto &expectedIndices = testCase.expectedOutputIndices;

    oc::Timer timer;
    timer.setTimePoint("begin");
    auto input = makeNormalInput(
        sendSet,
        recvSet,
        config.n,
        config.dimension,
        config.delta,
        0);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> sendShares(input.queryKeys.size());
        std::vector<block> recvShares(input.queryKeys.size());
        runSoOpprf(
            input.keys,
            input.values,
            input.queryKeys,
            sendShares,
            recvShares,
            sockets);
        timer.setTimePoint("OPPRF done");

        auto sendPeqtInputs = xorDimensions(
            sendShares, config.n, config.dimension);
        auto recvPeqtInputs = xorDimensions(
            recvShares, config.n, config.dimension);
        std::vector<u64> matches;
        runPeqt(
            sendPeqtInputs,
            recvPeqtInputs,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(config.n, matches);
        timer.setTimePoint("EQT done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(sendSet, choiceBits, transferredElements, sockets);
        if (config.verbose) {
            correctCheck(choiceBits, expectedIndices);
        }
    }

    auto end = timer.setTimePoint("OT done");
    if (config.verbose) {
        std::cout << timer << std::endl;
    }
    const double comm =
        (sockets[0].bytesReceived() + sockets[0].bytesSent())
        / 1024.0 / 1024.0 / config.trials;
    const double comp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            end - preprocessingDone)
            .count()
        / double(1000 * 1000) / config.trials;
    printFpsiResult(
        "normal", "recv", "uniqBlk", 0,
        config.dimension, config.delta, config.n, comm, comp);
}

void fuzzyPsiUniqueBlockLp(const FpsiConfig &config)
{
    PRNG dataPrng(sysRandomSeed());
    auto testCase = generateFpsiTestCase(
        config, dataPrng);
    const auto &sendSet = testCase.sendSet;
    const auto &recvSet = testCase.recvSet;
    const auto &expectedIndices = testCase.expectedOutputIndices;

    oc::Timer timer;
    timer.setTimePoint("begin");
    auto input = makeNormalInput(
        sendSet,
        recvSet,
        config.n,
        config.dimension,
        config.delta,
        config.metric);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    const u64 deltaPow =
        integerPow(config.delta, config.metric);
    const u64 prefixLen = static_cast<u64>(
        std::ceil(std::log2(deltaPow + 1)));

    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> sendShares(input.queryKeys.size());
        std::vector<block> recvShares(input.queryKeys.size());
        runSoOpprf(
            input.keys,
            input.values,
            input.queryKeys,
            sendShares,
            recvShares,
            sockets);
        timer.setTimePoint("OPPRF done");

        std::vector<u64> sendArithShares(sendShares.size());
        std::vector<u64> recvArithShares(recvShares.size());
        runB2a(
            sendShares,
            recvShares,
            sendArithShares,
            recvArithShares,
            sockets,
            true);
        timer.setTimePoint("B2A done");

        auto sendDis = sumDimensions(
            sendArithShares, config.n, config.dimension);
        auto recvDis = sumDimensions(
            recvArithShares, config.n, config.dimension);
        std::vector<u64> matches;
        runIntervalTest(
            sendDis,
            recvDis,
            deltaPow,
            prefixLen,
            matches,
            sockets);
        auto choiceBits =
            makeChoiceBits(config.n, matches, prefixLen);
        timer.setTimePoint("Interval test done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(sendSet, choiceBits, transferredElements, sockets);
        if (config.verbose) {
            correctCheck(choiceBits, expectedIndices);
        }
    }

    auto end = timer.setTimePoint("OT done");
    if (config.verbose) {
        std::cout << timer << std::endl;
    }
    const double comm =
        (sockets[0].bytesReceived() + sockets[0].bytesSent())
        / 1024.0 / 1024.0 / config.trials;
    const double comp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            end - preprocessingDone)
            .count()
        / double(1000 * 1000) / config.trials;
    printFpsiResult(
        "normal", "recv", "uniqBlk", config.metric,
        config.dimension, config.delta, config.n, comm, comp);
}
