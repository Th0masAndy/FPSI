#pragma once

#include "cryptoTools/Common/CLP.h"
#include "utils.h"

using namespace oc;

void LocalMap(PointSet &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiL0(const oc::CLP &cmd);

void fuzzyPsiLp(const oc::CLP &cmd);

// prefix optimization

void LocalMapPrefix(PointSet &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiPrefixL0(const oc::CLP &cmd);

void fuzzyPsiPrefixLp(const oc::CLP &cmd);
