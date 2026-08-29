#pragma once

#include <array>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include "config.h"
#include "utils.h"

struct FilterContext {
    const FpsiConfig &config;
    const PointSet &sendSet;
    const PointSet &recvSet;
    const std::vector<oc::block> &sendIds;
    const std::vector<oc::block> &recvIds;
    std::array<coproto::AsioSocket, 2> &sockets;
};

struct PrefixFilterParams {
    const std::vector<oc::u64> &prefixLens;
    oc::u64 encodedPrefixCount;
};

class NormalFilterL0 {
public:
    explicit NormalFilterL0(const FilterContext &context);
    std::vector<oc::u8> run();

private:
    const FilterContext &mContext;
};

class NormalFilterLp {
public:
    explicit NormalFilterLp(const FilterContext &context);
    std::vector<oc::u8> run();

private:
    const FilterContext &mContext;
};

class PrefixFilterL0 {
public:
    PrefixFilterL0(const FilterContext &context, const PrefixFilterParams &prefix);
    std::vector<oc::u8> run();

private:
    const FilterContext &mContext;
    const PrefixFilterParams &mPrefix;
};

class PrefixFilterLp {
public:
    PrefixFilterLp(const FilterContext &context, const PrefixFilterParams &prefix);
    std::vector<oc::u8> run();

private:
    const FilterContext &mContext;
    const PrefixFilterParams &mPrefix;
};
