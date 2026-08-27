#pragma once

#include "cryptoTools/Common/CLP.h"

using namespace oc;

void LocalMap(std::vector<std::vector<u64>> &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiL0(const oc::CLP &cmd);

void fuzzyPsiLp(const oc::CLP &cmd);

// prefix optimization

void LocalMapPrefix(std::vector<std::vector<u64>> &inputs, std::vector<block> &pid, std::vector<block> &listKey, std::vector<block> &listVal, int delta);

void fuzzyPsiPrefixL0(const oc::CLP &cmd);

void fuzzyPsiPrefixLp(const oc::CLP &cmd);