#pragma once

#include <cryptoTools/Crypto/PRNG.h>
#include <vector>
#include "config.h"
#include "utils.h"

struct FpsiTestCase {
    PointSet sendSet;
    PointSet recvSet;
    std::vector<oc::u64> expectedOutputIndices;
    std::vector<oc::u64> receiverMatchIndices;
};

FpsiTestCase generateFpsiTestCase(
    const FpsiConfig &config,
    oc::PRNG &prng);
