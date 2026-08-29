#include "protocol.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
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
#include "utils.h"

using namespace oc;

namespace {

struct PrefixDistanceInput {
    SoOpprfInput soOpprf;
    std::vector<u64> localOffsets;
    u64 groupSize;
};

struct SplitShares {
    std::vector<block> highShares;
    std::vector<block> lowShares;
};

const std::vector<u64> &prefixLensFor(int delta)
{
    const auto it = prefixLenMapLow.find(delta);
    if (it == prefixLenMapLow.end()) {
        throw std::invalid_argument("uniqueCell prefix does not support this delta");
    }
    return it->second;
}

u64 encodedPrefixCountFor(int delta)
{
    const auto it = prefixNumMapLow.find(delta);
    if (it == prefixNumMapLow.end()) {
        throw std::invalid_argument("uniqueCell prefix does not support this delta");
    }
    return it->second;
}

void padKeyValues(SoOpprfInput &input, u64 expectedCount)
{
    if (input.keys.size() != input.values.size()) {
        throw std::runtime_error("uniqueCell key/value count mismatch");
    }
    if (input.keys.size() > expectedCount) {
        throw std::runtime_error("uniqueCell encoded input exceeds its configured size");
    }

    input.keys.reserve(expectedCount);
    input.values.reserve(expectedCount);
    PRNG paddingPrng(sysRandomSeed());
    while (input.keys.size() < expectedCount) {
        input.keys.push_back(paddingPrng.get<block>());
        input.values.push_back(paddingPrng.get<block>());
    }
}

std::vector<block> makeNormalQueryKeys(
    const PointSet &sendSet,
    u64 n,
    std::size_t dimension,
    int delta)
{
    const u64 cellCount = 1ULL << dimension;
    std::vector<block> queryKeys(n * dimension * cellCount);
    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(sendSet[i], delta);
        if (neighbors.size() != cellCount) {
            throw std::runtime_error("uniqueCell neighbor count mismatch");
        }
        for (u64 j = 0; j < dimension; ++j) {
            for (u64 z = 0; z < cellCount; ++z) {
                queryKeys[
                    i * dimension * cellCount + j * cellCount + z] =
                    blake3_hash(neighbors[z], j, sendSet[i][j]);
            }
        }
    }
    return queryKeys;
}

SoOpprfInput makeNormalInput(
    const PointSet &sendSet,
    const PointSet &recvSet,
    u64 n,
    std::size_t dimension,
    int delta,
    int metric,
    const std::vector<u64> *seeds = nullptr)
{
    const u64 offsetCount = 2 * static_cast<u64>(delta) + 1;
    const u64 encodedCount = n * dimension * offsetCount;
    if (seeds != nullptr && seeds->size() != n * dimension) {
        throw std::runtime_error("uniqueCell seed count mismatch");
    }

    SoOpprfInput input;
    input.keys.reserve(encodedCount);
    input.values.reserve(encodedCount);
    input.queryKeys = makeNormalQueryKeys(sendSet, n, dimension, delta);

    for (u64 i = 0; i < n; ++i) {
        const auto cellId = cell(recvSet[i], 2 * delta);
        for (u64 j = 0; j < dimension; ++j) {
            for (int offset = -delta; offset <= delta; ++offset) {
                input.keys.push_back(
                    blake3_hash(cellId, j, recvSet[i][j] + offset));
                const u64 distance = metric == 0
                    ? 0
                    : integerPow(std::abs(offset), metric);
                input.values.push_back(seeds == nullptr
                        ? block(0, distance)
                        : block(distance, (*seeds)[i * dimension + j]));
            }
        }
    }

    if (input.keys.size() != encodedCount) {
        throw std::runtime_error("uniqueCell normal input size mismatch");
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
    const u64 encodedCount = n * dimension * encodedPrefixCount;

    SoOpprfInput input;
    input.keys.reserve(encodedCount);
    input.values.reserve(encodedCount);
    input.queryKeys.resize(n * dimension * cellCount * prefixLen);

    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(sendSet[i], delta);
        if (neighbors.size() != cellCount) {
            throw std::runtime_error("uniqueCell neighbor count mismatch");
        }
        for (u64 j = 0; j < dimension; ++j) {
            const auto prefixes = getPrefixSet(sendSet[i][j], prefixLens);
            if (prefixes.size() != prefixLen) {
                throw std::runtime_error("uniqueCell query prefix count mismatch");
            }
            for (u64 z = 0; z < cellCount; ++z) {
                for (u64 k = 0; k < prefixLen; ++k) {
                    const u64 index =
                        i * dimension * cellCount * prefixLen
                        + j * cellCount * prefixLen
                        + z * prefixLen + k;
                    input.queryKeys[index] =
                        blake3_hash(neighbors[z], j, prefixes[k]);
                }
            }
        }
    }

    for (u64 i = 0; i < n; ++i) {
        const auto cellId = cell(recvSet[i], 2 * delta);
        for (u64 j = 0; j < dimension; ++j) {
            const auto prefixes = getIntervalPrefixSet(
                recvSet[i][j] - delta,
                recvSet[i][j] + delta,
                prefixLens);
            for (const auto &prefix : prefixes) {
                input.keys.push_back(blake3_hash(cellId, j, prefix));
                input.values.push_back(ZeroBlock);
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
    const std::vector<u64> &prefixLens,
    u64 encodedPrefixCount)
{
    const u64 cellCount = 1ULL << dimension;
    const u64 halfPrefixLen = prefixLens.size();
    const u64 groupSize = 2 * halfPrefixLen;
    const u64 queryCount = n * dimension * cellCount * groupSize;
    const u64 encodedCount = 2 * n * dimension * encodedPrefixCount;

    PrefixDistanceInput input {
        {},
        std::vector<u64>(queryCount),
        groupSize,
    };
    input.soOpprf.keys.reserve(encodedCount);
    input.soOpprf.values.reserve(encodedCount);
    input.soOpprf.queryKeys.resize(queryCount);

    for (u64 i = 0; i < n; ++i) {
        const auto neighbors = neigh(sendSet[i], delta);
        if (neighbors.size() != cellCount) {
            throw std::runtime_error("uniqueCell neighbor count mismatch");
        }
        for (u64 j = 0; j < dimension; ++j) {
            const auto prefixes = getPrefixSet(sendSet[i][j], prefixLens);
            if (prefixes.size() != halfPrefixLen) {
                throw std::runtime_error("uniqueCell query prefix count mismatch");
            }
            for (u64 z = 0; z < cellCount; ++z) {
                for (u64 side = 0; side < 2; ++side) {
                    for (u64 k = 0; k < halfPrefixLen; ++k) {
                        const u64 index =
                            i * dimension * cellCount * groupSize
                            + j * cellCount * groupSize
                            + z * groupSize
                            + side * halfPrefixLen + k;
                        const u64 domain = (j << 8) | (side << 4);
                        input.soOpprf.queryKeys[index] =
                            blake3_hash(neighbors[z], domain, prefixes[k]);
                        input.localOffsets[index] = side == 0
                            ? upBound(prefixes[k]) - sendSet[i][j]
                            : sendSet[i][j] - upBound(prefixes[k]);
                    }
                }
            }
        }
    }

    for (u64 i = 0; i < n; ++i) {
        const auto cellId = cell(recvSet[i], 2 * delta);
        for (u64 j = 0; j < dimension; ++j) {
            const auto lowerPrefixes = getIntervalPrefixSet(
                recvSet[i][j] - delta,
                recvSet[i][j] - 1,
                prefixLens);
            const auto upperPrefixes = getIntervalPrefixSet(
                recvSet[i][j],
                recvSet[i][j] + delta,
                prefixLens);

            for (const auto &prefix : lowerPrefixes) {
                input.soOpprf.keys.push_back(
                    blake3_hash(cellId, j << 8, prefix));
                input.soOpprf.values.push_back(
                    block(0, recvSet[i][j] - upBound(prefix)));
            }
            for (const auto &prefix : upperPrefixes) {
                input.soOpprf.keys.push_back(
                    blake3_hash(cellId, (j << 8) | (1 << 4), prefix));
                input.soOpprf.values.push_back(
                    block(0, upBound(prefix) - recvSet[i][j]));
            }
        }
    }

    padKeyValues(input.soOpprf, encodedCount);
    return input;
}

std::vector<u64> makeSeedSums(
    const std::vector<u64> &seeds,
    u64 n,
    std::size_t dimension)
{
    if (seeds.size() != n * dimension) {
        throw std::runtime_error("uniqueCell seed count mismatch");
    }
    std::vector<u64> sums(n, 0);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < dimension; ++j) {
            sums[i] ^= seeds[i * dimension + j];
        }
    }
    return sums;
}

SplitShares splitShares(const std::vector<block> &shares)
{
    SplitShares result {
        std::vector<block>(shares.size()),
        std::vector<block>(shares.size()),
    };
    for (u64 i = 0; i < shares.size(); ++i) {
        result.highShares[i] = block(0, high(shares[i]));
        result.lowShares[i] = block(0, low(shares[i]));
    }
    return result;
}

std::vector<block> xorDimensions(
    const std::vector<block> &values,
    u64 n,
    std::size_t dimension,
    u64 valuesPerDimension)
{
    if (values.size() != n * dimension * valuesPerDimension) {
        throw std::runtime_error("uniqueCell block share count mismatch");
    }
    std::vector<block> result(n * valuesPerDimension);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < dimension; ++j) {
            for (u64 k = 0; k < valuesPerDimension; ++k) {
                result[i * valuesPerDimension + k] ^=
                    values[
                        i * dimension * valuesPerDimension
                        + j * valuesPerDimension + k];
            }
        }
    }
    return result;
}

std::vector<u64> sumDimensions(
    const std::vector<u64> &values,
    u64 n,
    std::size_t dimension,
    u64 valuesPerDimension)
{
    if (values.size() != n * dimension * valuesPerDimension) {
        throw std::runtime_error("uniqueCell arithmetic share count mismatch");
    }
    std::vector<u64> result(n * valuesPerDimension, 0);
    for (u64 i = 0; i < n; ++i) {
        for (u64 j = 0; j < dimension; ++j) {
            for (u64 k = 0; k < valuesPerDimension; ++k) {
                result[i * valuesPerDimension + k] +=
                    values[
                        i * dimension * valuesPerDimension
                        + j * valuesPerDimension + k];
            }
        }
    }
    return result;
}

std::vector<u8> makeChoiceBits(
    u64 n,
    const std::vector<u64> &matches,
    u64 groupSize)
{
    std::vector<u8> choiceBits(n, 0);
    for (const u64 match : matches) {
        const u64 index = match / groupSize;
        if (index >= n) {
            throw std::runtime_error("uniqueCell match index out of range");
        }
        choiceBits[index] = 1;
    }
    return choiceBits;
}

std::vector<block> runEqRandReveal(
    std::vector<block> &sendShares,
    std::vector<block> &recvShares,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    auto sendSplit = splitShares(sendShares);
    auto recvSplit = splitShares(recvShares);
    std::vector<block> sendOutput(sendShares.size());
    std::vector<block> recvOutput(recvShares.size());

    std::thread send([&] {
        MuxSender mux(sendShares.size(), &sockets[1]);
        mux.EqRand(
            sendSplit.highShares,
            sendSplit.lowShares,
            sendOutput);
        sendBlocks(sockets[1], sendOutput);
    });
    std::thread recv([&] {
        MuxRecver mux(recvShares.size(), &sockets[0]);
        mux.EqRand(
            recvSplit.highShares,
            recvSplit.lowShares,
            recvOutput);
        std::vector<block> remoteOutput(recvOutput.size());
        recvBlocks(sockets[0], remoteOutput);
        for (u64 i = 0; i < recvOutput.size(); ++i) {
            recvOutput[i] ^= remoteOutput[i];
        }
    });
    send.join();
    recv.join();
    return recvOutput;
}

std::vector<block> runCmpRandReveal(
    std::vector<u64> &sendDis,
    std::vector<u64> &recvDis,
    std::vector<block> &sendSeedShares,
    std::vector<block> &recvSeedShares,
    u64 threshold,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    std::vector<block> sendOutput(sendDis.size());
    std::vector<block> recvOutput(recvDis.size());

    std::thread send([&] {
        MuxSender mux(sendDis.size(), &sockets[1]);
        mux.CmpRand(
            sendDis,
            sendSeedShares,
            sendOutput,
            threshold);
        sendBlocks(sockets[1], sendOutput);
    });
    std::thread recv([&] {
        MuxRecver mux(recvDis.size(), &sockets[0]);
        mux.CmpRand(
            recvDis,
            recvSeedShares,
            recvOutput);
        std::vector<block> remoteOutput(recvOutput.size());
        recvBlocks(sockets[0], remoteOutput);
        for (u64 i = 0; i < recvOutput.size(); ++i) {
            recvOutput[i] ^= remoteOutput[i];
        }
    });
    send.join();
    recv.join();
    return recvOutput;
}

PointSet runWeakLablePsi(
    const PointSet &sendSet,
    const std::vector<u64> &seedSums,
    const std::vector<block> &recvSeed,
    std::array<coproto::AsioSocket, 2> &sockets)
{
    const u64 n = sendSet.size();
    const u64 dimension = sendSet.dim();
    if (seedSums.size() != n) {
        throw std::runtime_error("uniqueCell weak PSI input size mismatch");
    }
    PointSet recvPoints(0, dimension);

    std::thread sendParty([&] {
        std::vector<block> keys;
        std::vector<u64> maskedPoints;
        keys.reserve(n);
        maskedPoints.reserve(n * dimension);
        PRNG maskPrng;
        for (u64 i = 0; i < n; ++i) {
            std::vector<u64> mask(dimension);
            maskPrng.SetSeed(block(seedSums[i], seedSums[i]));
            keys.push_back(block(0, seedSums[i]));
            maskPrng.get(mask.data(), mask.size());
            for (u64 j = 0; j < dimension; ++j) {
                mask[j] ^= sendSet[i][j];
            }
            maskedPoints.insert(
                maskedPoints.end(), mask.begin(), mask.end());
        }
        Hash(keys);
        coproto::sync_wait(sockets[1].send(keys));
        coproto::sync_wait(sockets[1].send(maskedPoints));
    });

    std::thread recvParty([&] {
        auto recvKeys = recvSeed;
        Hash(recvKeys);
        std::vector<block> keys;
        std::vector<u64> maskedPoints;
        coproto::sync_wait(sockets[0].recvResize(keys));
        coproto::sync_wait(sockets[0].recvResize(maskedPoints));
        if (keys.size() != n || maskedPoints.size() != n * dimension) {
            throw std::runtime_error("uniqueCell weak PSI payload size mismatch");
        }

        std::unordered_multimap<u64, u64> sendKeyIndices;
        sendKeyIndices.reserve(n);
        for (u64 i = 0; i < n; ++i) {
            sendKeyIndices.emplace(low(keys[i]), i);
        }

        std::vector<u8> recovered(n, 0);
        recvPoints.reserve(n);
        PRNG maskPrng;
        for (u64 i = 0; i < recvKeys.size(); ++i) {
            const auto [begin, end] =
                sendKeyIndices.equal_range(low(recvKeys[i]));
            for (auto it = begin; it != end; ++it) {
                const u64 sendIndex = it->second;
                if (recovered[sendIndex]
                    || recvKeys[i] != keys[sendIndex]) {
                    continue;
                }

                const u64 seed = low(recvSeed[i]);
                maskPrng.SetSeed(block(seed, seed));
                std::vector<u64> point(dimension);
                maskPrng.get(point.data(), point.size());
                for (u64 j = 0; j < dimension; ++j) {
                    point[j] ^=
                        maskedPoints[sendIndex * dimension + j];
                }
                recvPoints.push_back(point);
                recovered[sendIndex] = 1;
            }
        }
    });

    sendParty.join();
    recvParty.join();
    return recvPoints;
}

void correctCheckSenderPoints(
    const PointSet &recvPoints,
    const PointSet &sendSet,
    const std::vector<u64> &expectedIndices)
{
    if (recvPoints.dim() != sendSet.dim()) {
        throw std::runtime_error("uniqueCell recovered point dimension mismatch");
    }

    std::vector<std::vector<u64>> expectedPoints;
    expectedPoints.reserve(expectedIndices.size());
    for (const u64 index : expectedIndices) {
        if (index >= sendSet.size()) {
            throw std::runtime_error(
                "uniqueCell expected sender index out of range");
        }
        expectedPoints.emplace_back(
            sendSet[index].begin(), sendSet[index].end());
    }

    std::vector<std::vector<u64>> actualPoints;
    actualPoints.reserve(recvPoints.size());
    for (u64 i = 0; i < recvPoints.size(); ++i) {
        actualPoints.emplace_back(
            recvPoints[i].begin(), recvPoints[i].end());
    }

    std::sort(expectedPoints.begin(), expectedPoints.end());
    std::sort(actualPoints.begin(), actualPoints.end());
    if (actualPoints != expectedPoints) {
        throw std::runtime_error(
            "uniqueCell recovered sender points mismatch");
    }

    std::cout << "Total " << actualPoints.size() << "/"
              << expectedPoints.size() << " matches found!" << std::endl;
}

void runSenderProtocol(const FpsiConfig &config)
{
    const u64 cellCount = 1ULL << config.dimension;
    const u64 queryCount =
        config.n * config.dimension * cellCount;

    PRNG dataPrng(sysRandomSeed());
    std::vector<u64> seeds(config.n * config.dimension);
    dataPrng.get(seeds.data(), seeds.size());
    auto seedSums = makeSeedSums(
        seeds, config.n, config.dimension);
    auto testCase = generateFpsiTestCase(
        config, dataPrng);
    const auto &sendSet = testCase.sendSet;
    const auto &recvSet = testCase.recvSet;
    const auto &expectedIndices = testCase.expectedOutputIndices;

    oc::Timer timer;
    timer.setTimePoint("begin");
    auto input = makeNormalInput(
        recvSet,
        sendSet,
        config.n,
        config.dimension,
        config.delta,
        config.metric,
        &seeds);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> sendShares(queryCount);
        std::vector<block> recvShares(queryCount);
        runSoOpprf(
            input.keys,
            input.values,
            input.queryKeys,
            sendShares,
            recvShares,
            sockets,
            true);
        timer.setTimePoint("OPPRF done");

        std::vector<block> recvSeed;
        if (config.metric == 0) {
            auto sendAggregated = xorDimensions(
                sendShares,
                config.n,
                config.dimension,
                cellCount);
            auto recvAggregated = xorDimensions(
                recvShares,
                config.n,
                config.dimension,
                cellCount);
            recvSeed = runEqRandReveal(
                sendAggregated,
                recvAggregated,
                sockets);
            timer.setTimePoint("EqRand done");
        } else {
            auto sendSplit = splitShares(sendShares);
            auto recvSplit = splitShares(recvShares);
            auto sendSeedShares = xorDimensions(
                sendSplit.lowShares,
                config.n,
                config.dimension,
                cellCount);
            auto recvSeedShares = xorDimensions(
                recvSplit.lowShares,
                config.n,
                config.dimension,
                cellCount);

            std::vector<u64> sendArithShares(queryCount);
            std::vector<u64> recvArithShares(queryCount);
            runB2a(
                sendSplit.highShares,
                recvSplit.highShares,
                sendArithShares,
                recvArithShares,
                sockets,
                true);
            auto sendDis = sumDimensions(
                sendArithShares,
                config.n,
                config.dimension,
                cellCount);
            auto recvDis = sumDimensions(
                recvArithShares,
                config.n,
                config.dimension,
                cellCount);
            timer.setTimePoint("B2A done");

            recvSeed = runCmpRandReveal(
                sendDis,
                recvDis,
                sendSeedShares,
                recvSeedShares,
                integerPow(config.delta, config.metric),
                sockets);
            timer.setTimePoint("CmpRand done");
        }

        auto recvPoints = runWeakLablePsi(
            sendSet,
            seedSums,
            recvSeed,
            sockets);
        timer.setTimePoint("wLPSI done");

        if (config.verbose) {
            correctCheckSenderPoints(
                recvPoints, sendSet, expectedIndices);
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
        "normal", "send", "uniqCel", config.metric,
        config.dimension, config.delta, config.n, comm, comp);
}

} // namespace

void fuzzyPsiUniqueCellPxLp(const FpsiConfig &config)
{
    const auto &prefixLens = prefixLensFor(config.delta);
    const u64 encodedPrefixCount =
        encodedPrefixCountFor(config.delta);
    const u64 cellCount = 1ULL << config.dimension;

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
        prefixLens,
        encodedPrefixCount);
    auto sockets = coproto::AsioSocket::makePair();
    auto preprocessingDone = timer.setTimePoint("preprocess done");

    const u64 deltaPow =
        integerPow(config.delta, config.metric);
    const u64 intervalPrefixLen = static_cast<u64>(
        std::ceil(std::log2(deltaPow + 1)));

    for (int trial = 0; trial < config.trials; ++trial) {
        std::vector<block> sendShares(
            input.soOpprf.queryKeys.size());
        std::vector<block> recvShares(
            input.soOpprf.queryKeys.size());
        runSoOpprf(
            input.soOpprf.keys,
            input.soOpprf.values,
            input.soOpprf.queryKeys,
            recvShares,
            sendShares,
            sockets,
            true);
        timer.setTimePoint("OPPRF done");

        auto sendSplit = splitShares(sendShares);
        auto recvSplit = splitShares(recvShares);
        std::vector<u64> sendArithShares(sendShares.size());
        std::vector<u64> recvArithShares(recvShares.size());
        runB2a(
            sendSplit.lowShares,
            recvSplit.lowShares,
            sendArithShares,
            recvArithShares,
            sockets);
        timer.setTimePoint("B2A done");

        std::vector<u64> sendDisShares(sendShares.size());
        std::vector<u64> recvDisShares(recvShares.size());
        if (config.metric == 1) {
            for (u64 i = 0; i < sendShares.size(); ++i) {
                sendDisShares[i] =
                    sendArithShares[i] + input.localOffsets[i];
                recvDisShares[i] = recvArithShares[i];
            }
        } else {
            for (u64 i = 0; i < sendShares.size(); ++i) {
                sendArithShares[i] += input.localOffsets[i];
            }
            std::vector<u64> sendProducts(sendShares.size());
            std::vector<u64> recvProducts(recvShares.size());
            runMul(
                sendArithShares,
                recvArithShares,
                sendProducts,
                recvProducts,
                sockets);
            for (u64 i = 0; i < sendShares.size(); ++i) {
                sendDisShares[i] =
                    sendArithShares[i] * sendArithShares[i]
                    + 2 * sendProducts[i];
                recvDisShares[i] =
                    recvArithShares[i] * recvArithShares[i]
                    + 2 * recvProducts[i];
            }
            timer.setTimePoint("Mul done");
        }

        std::vector<u64> sendSelected(
            config.n * config.dimension * cellCount);
        std::vector<u64> recvSelected(
            config.n * config.dimension * cellCount);
        runEqSel(
            sendSplit.highShares,
            recvSplit.highShares,
            sendDisShares,
            recvDisShares,
            sendSelected,
            recvSelected,
            input.groupSize,
            sockets);
        timer.setTimePoint("Mux done");

        auto sendDis = sumDimensions(
            sendSelected,
            config.n,
            config.dimension,
            cellCount);
        auto recvDis = sumDimensions(
            recvSelected,
            config.n,
            config.dimension,
            cellCount);
        std::vector<u64> matches;
        runIntervalTest(
            sendDis,
            recvDis,
            deltaPow,
            intervalPrefixLen,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(
            config.n,
            matches,
            cellCount * intervalPrefixLen);
        timer.setTimePoint("Interval test done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(
            sendSet, choiceBits, transferredElements, sockets);
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
        "prefix", "recv", "uniqCel", config.metric,
        config.dimension, config.delta, config.n, comm, comp);
}

void fuzzyPsiUniqueCellL0(const FpsiConfig &config)
{
    const u64 cellCount = 1ULL << config.dimension;

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
            sendShares,
            config.n,
            config.dimension,
            cellCount);
        auto recvPeqtInputs = xorDimensions(
            recvShares,
            config.n,
            config.dimension,
            cellCount);
        std::vector<u64> matches;
        runPeqt(
            sendPeqtInputs,
            recvPeqtInputs,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(
            config.n, matches, cellCount);
        timer.setTimePoint("EQT done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(
            sendSet, choiceBits, transferredElements, sockets);
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
        "normal", "recv", "uniqCel", 0,
        config.dimension, config.delta, config.n, comm, comp);
}

void fuzzyPsiUniqueCellSenderL0(const FpsiConfig &config)
{
    runSenderProtocol(config);
}

void fuzzyPsiUniqueCellSenderLp(const FpsiConfig &config)
{
    runSenderProtocol(config);
}

void fuzzyPsiUniqueCellPxL0(const FpsiConfig &config)
{
    const auto &prefixLens = prefixLensFor(2 * config.delta);
    const u64 encodedPrefixCount =
        encodedPrefixCountFor(2 * config.delta);
    const u64 cellCount = 1ULL << config.dimension;

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
            config.n * config.dimension * cellCount);
        std::vector<block> recvSelected(
            config.n * config.dimension * cellCount);
        runEqSel(
            sendShares,
            recvShares,
            sendSelected,
            recvSelected,
            prefixLen,
            sockets,
            true);
        timer.setTimePoint("EqSel done");

        auto sendPeqtInputs = xorDimensions(
            sendSelected,
            config.n,
            config.dimension,
            cellCount);
        auto recvPeqtInputs = xorDimensions(
            recvSelected,
            config.n,
            config.dimension,
            cellCount);
        std::vector<u64> matches;
        runPeqt(
            sendPeqtInputs,
            recvPeqtInputs,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(
            config.n, matches, cellCount);
        timer.setTimePoint("EQT done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(
            sendSet, choiceBits, transferredElements, sockets);
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
        "prefix", "recv", "uniqCel", 0,
        config.dimension, config.delta, config.n, comm, comp);
}

void fuzzyPsiUniqueCellLp(const FpsiConfig &config)
{
    const u64 cellCount = 1ULL << config.dimension;
    const u64 deltaPow =
        integerPow(config.delta, config.metric);
    const u64 prefixLen = static_cast<u64>(
        std::ceil(std::log2(deltaPow + 1)));

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
        auto sendDis = sumDimensions(
            sendArithShares,
            config.n,
            config.dimension,
            cellCount);
        auto recvDis = sumDimensions(
            recvArithShares,
            config.n,
            config.dimension,
            cellCount);
        timer.setTimePoint("B2A done");

        std::vector<u64> matches;
        runIntervalTest(
            sendDis,
            recvDis,
            deltaPow,
            prefixLen,
            matches,
            sockets);
        auto choiceBits = makeChoiceBits(
            config.n,
            matches,
            cellCount * prefixLen);
        timer.setTimePoint("Interval test done");

        std::vector<std::vector<block>> transferredElements;
        transferElements(
            sendSet, choiceBits, transferredElements, sockets);
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
        "normal", "recv", "uniqCel", config.metric,
        config.dimension, config.delta, config.n, comm, comp);
}
