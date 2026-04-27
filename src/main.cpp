#include "cryptoTools/Common/CLP.h"
#include "fmap.h"
#include "fpsi_low.h"

bool LOG = false;

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    // Dispatch parameters:
    //   type       : 0 = low communication, 1 = high communication
    //   lp         : 0 = L_infinity norm,   non-zero = L_p norm
    //   prefix     : flag, enables prefix optimization
    //   assumption : 0 = 2delta,            1 = 4delta   (only used when type=low, lp=L_inf)
    const int type = cmd.getOr("type", 0);
    const int lp = cmd.getOr("p", 0);
    const int assumption = cmd.getOr("assumption", 0);
    const bool prefix = cmd.isSet("prefix");
    LOG = cmd.getOr("v", 0);

    const bool is_low = (type == 0);
    const bool is_linf = (lp == 0);
    const bool is_2delta = (assumption == 0);

    if (is_low && is_linf) {
        // L_infinity: choose between 2delta / 4delta assumption
        if (is_2delta) {
            prefix ? fuzzyPsiLow2DeltaPx(cmd) : fuzzyPsiLow2Delta(cmd);
        } else {
            prefix ? fuzzyPsiLow4DeltaPx(cmd) : fuzzyPsiLow4Delta(cmd);
        }
    } else if (is_low && !is_linf) {
        // L_p
        if (is_2delta) {
            prefix ? fuzzyPsiLow2DeltaLpPx(cmd) : fuzzyPsiLow2DeltaLp(cmd);
        } else {
            prefix ? fuzzyPsiLow4DeltaLpPxAug(cmd) : fuzzyPsiLow4DeltaLp(cmd);
            // prefix ? fuzzyPsiLow4DeltaLpPx(cmd) : fuzzyPsiLow4DeltaLp(cmd); // naive version of S&P 26
        }
    } else if (!is_low && is_linf) {
        // L_infinity
        prefix ? fuzzyPsiPrefix(cmd) : fuzzyPsi(cmd);
    } else {
        // L_p
        prefix ? fuzzyPsiLpPrefix(cmd) : fuzzyPsiLp(cmd);
    }

    return 0;
}
