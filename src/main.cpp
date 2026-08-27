#include <coproto/Socket/AsioSocket.h>
#include <iostream>
#include <string_view>
#include "b2a.h"
#include "cmp.h"
#include "common.h"
#include "cryptoTools/Common/CLP.h"
#include "fpsi.h"
#include "fpsi_low.h"

bool LOG = false;

namespace {

void printHelp(const char *program)
{
    std::cout
        << "usage: " << program << " [options]\n\n"
        << "options:\n"
        << "  -type <0|1>        protocol: 0 = one-sided (default), 1 = two-sided\n"
        << "  -p <0|1|2>         metric: 0 = linf (default), 1 = l1, 2 = l2\n"
        << "  -assumption <0|1>  one-sided assumption: 0 = unique cell (default), 1 = unique block\n"
        << "  -prefix            enable prefix optimization; delta must be a power of two\n"
        << "  -sender            use the sender-sided one-sided protocol\n"
        << "  -n <integer>       input set size\n"
        << "  -nn <integer>      log2 input set size (default: 10)\n"
        << "  -d <integer>       dimension (default: 2)\n"
        << "  -delta <integer>   distance threshold (default: 2)\n"
        << "  -inter <integer>   planted intersection size\n"
        << "  -try <integer>     number of benchmark runs (default: 1)\n"
        << "  -v <0|1>           verbose output (default: 0)\n"
        << "  -s <integer>       prefix shift (default: 0)\n"
        << "  -h, --help         show this help and exit\n";
}

bool helpRequested(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help" || arg == "-help") {
            return true;
        }
    }
    return false;
}

void runOneSidedSender(const oc::CLP &cmd, int lp, int assumption, bool prefix)
{
    if (assumption != 0 || prefix) {
        return;
    }

    if (lp == 0) {
        fuzzyPsiUniqueCellSenderL0(cmd);
    } else {
        fuzzyPsiUniqueCellSenderLp(cmd);
    }
}

void runOneSidedReceiver(const oc::CLP &cmd, int lp, int assumption, bool prefix)
{
    if (assumption == 0) {
        if (lp == 0) {
            prefix ? fuzzyPsiUniqueCellPxL0(cmd) : fuzzyPsiUniqueCellL0(cmd);
        } else {
            prefix ? fuzzyPsiUniqueCellPxLp(cmd) : fuzzyPsiUniqueCellLp(cmd);
        }
        return;
    }

    if (assumption == 1) {
        if (lp == 0) {
            prefix ? fuzzyPsiUniqueBlockPxL0(cmd) : fuzzyPsiUniqueBlockL0(cmd);
        } else {
            prefix ? fuzzyPsiUniqueBlockPxAugLp(cmd) : fuzzyPsiUniqueBlockLp(cmd);
        }
    }
}

void runTwoSided(const oc::CLP &cmd, int lp, bool prefix)
{
    if (lp == 0) {
        prefix ? fuzzyPsiPrefixL0(cmd) : fuzzyPsiL0(cmd);
    } else {
        prefix ? fuzzyPsiPrefixLp(cmd) : fuzzyPsiLp(cmd);
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (helpRequested(argc, argv)) {
        printHelp(argv[0]);
        return 0;
    }

    oc::CLP cmd(argc, argv);

    // Protocol parameters:
    //   type       : 0 = one-sided, 1 = two-sided
    //   p          : 0 = L_infinity, non-zero = L_p
    //   sender     : use the sender-sided one-sided protocol
    //   assumption : 0 = unique cell (2delta), 1 = unique block (4delta), only for one-sided
    //   prefix     : enable prefix optimization
    const int type = cmd.getOr("type", 0);
    const int lp = cmd.getOr("p", 0);
    const int assumption = cmd.getOr("assumption", 0);
    const bool prefix = cmd.isSet("prefix");
    const bool sender = cmd.isSet("sender");
    const int delta = cmd.getOr("delta", 2);
    LOG = cmd.getOr("v", 0);

    if (prefix && !isPowerOfTwo(delta)) {
        std::cerr << "error: '-delta' must be a power of two when '-prefix' is enabled\n";
        return 2;
    }

    if (type == 0) {
        if (sender) {
            runOneSidedSender(cmd, lp, assumption, prefix);
        } else {
            runOneSidedReceiver(cmd, lp, assumption, prefix);
        }
        return 0;
    }

    if (type == 1) {
        if (sender) {
            return 0;
        }
        runTwoSided(cmd, lp, prefix);
    }

    return 0;
}
