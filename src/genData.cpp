#include "genData.h"
#include <cmath>
#include "common.h"

namespace {

PointSet generateRandomPointSet(const FpsiConfig &config, oc::PRNG &prng)
{
    PointSet points(0, config.dimension);
    points.reserve(config.n);

    for (oc::u64 i = 0; i < config.n; ++i) {
        std::vector<oc::u64> point(config.dimension);
        for (auto &coordinate : point) {
            coordinate = prng.get<oc::u64>() + 2 * config.delta;
        }
        points.push_back(point);
    }

    return points;
}

oc::u64 coordinateDifferenceBound(const FpsiConfig &config)
{
    if (config.metric == 0) {
        return config.delta;
    }
    if (config.metric == 2) {
        return std::floor(config.delta * 1.0 / std::sqrt(config.dimension));
    }
    return std::floor(config.delta * 1.0 / config.dimension);
}

} // namespace

FpsiTestCase generateFpsiTestCase(
    const FpsiConfig &config,
    oc::PRNG &prng)
{
    FpsiTestCase testCase {
        .sendSet = generateRandomPointSet(config, prng),
        .recvSet = generateRandomPointSet(config, prng),
        .expectedOutputIndices = sampleUniqueIndices(config.n, config.intersectionSize, prng),
    };

    testCase.receiverMatchIndices =
        sampleUniqueIndices(config.n, config.intersectionSize, prng);

    const oc::u64 differenceBound = coordinateDifferenceBound(config);
    for (oc::u64 i = 0; i < config.intersectionSize; ++i) {
        const oc::u64 sendIdx = testCase.expectedOutputIndices[i];
        const oc::u64 recvIdx = testCase.receiverMatchIndices[i];
        for (oc::u64 j = 0; j < config.dimension; ++j) {
            const oc::u64 sign = 1 - 2 * (prng.get<oc::u64>() % 2);
            const oc::u64 difference = prng.get<oc::u64>() % (differenceBound + 1);
            testCase.recvSet[recvIdx][j] = testCase.sendSet[sendIdx][j] + sign * difference;
        }
    }

    return testCase;
}
