#pragma once

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cstddef>

struct FpsiConfig {
    oc::u64 n;
    std::size_t dimension;
    int delta;
    int metric;
    oc::u64 intersectionSize;
    int trials;
    bool verbose;

    static FpsiConfig fromCommandLine(const oc::CLP &cmd);
};
