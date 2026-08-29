#pragma once

#include "config.h"

// uniqueCell
void fuzzyPsiUniqueCellL0(const FpsiConfig &config);
void fuzzyPsiUniqueCellLp(const FpsiConfig &config);
void fuzzyPsiUniqueCellPxL0(const FpsiConfig &config);
void fuzzyPsiUniqueCellPxLp(const FpsiConfig &config);
void fuzzyPsiUniqueCellPxLpOpt(const FpsiConfig &config);
void fuzzyPsiUniqueCellSenderL0(const FpsiConfig &config);
void fuzzyPsiUniqueCellSenderLp(const FpsiConfig &config);

// uniqueBlock
void fuzzyPsiUniqueBlockL0(const FpsiConfig &config);
void fuzzyPsiUniqueBlockLp(const FpsiConfig &config);
void fuzzyPsiUniqueBlockPxL0(const FpsiConfig &config);
void fuzzyPsiUniqueBlockPxLp(const FpsiConfig &config);
void fuzzyPsiUniqueBlockPxAugLp(const FpsiConfig &config);

// disJoint
void fuzzyPsiL0(const FpsiConfig &config);
void fuzzyPsiLp(const FpsiConfig &config);
void fuzzyPsiPrefixL0(const FpsiConfig &config);
void fuzzyPsiPrefixLp(const FpsiConfig &config);
