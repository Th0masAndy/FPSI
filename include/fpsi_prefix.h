#pragma once

#include "cryptoTools/Common/CLP.h"
#include "utils.h"

using namespace oc;

void LocalMapPrefix(PointSet &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiPrefixL0(const oc::CLP &cmd);

void fuzzyPsiPrefixLp(const oc::CLP &cmd);
