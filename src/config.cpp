#include "config.h"

FpsiConfig FpsiConfig::fromCommandLine(const oc::CLP &cmd)
{
    return {
        .n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10)),
        .dimension = cmd.getOr("d", std::size_t { 2 }),
        .delta = cmd.getOr("delta", 2),
        .metric = cmd.getOr("p", 0),
        .intersectionSize = cmd.getOr("inter", 4ull),
        .trials = cmd.getOr("try", 1),
        .verbose = cmd.getOr("v", 0) != 0,
        .prefixShift = cmd.getOr("s", 0),
    };
}
