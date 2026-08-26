#include <coproto/Socket/AsioSocket.h>
#include <vector>
#include "b2a.h"
#include "cmp.h"
#include "cryptoTools/Common/CLP.h"
#include "fpsi.h"
#include "fpsi_low.h"

bool LOG = false;

int main(int argc, char **argv)
{
    // u64 n = 1ull << 12;

    // auto sock = coproto::AsioSocket::makePair();

    // PRNG prng(oc::sysRandomSeed());

    // std::vector<block> e_S(n);
    // std::vector<u64> d_S(n);

    // std::vector<block> e_R(n);
    // std::vector<u64> d_R(n);

    // std::vector<u8> res_S(n);
    // std::vector<u8> res_R(n);

    // for (u64 i = 0; i < n; i++) {
    //     d_R[i] = prng.get<u64>();
    //     d_S[i] = prng.get<u64>();
    // }

    // std::thread sendB2A([&] {
    //     MillionaireProtocolSender send(n, 64);
    //     send.compare(res_S.data(), d_S.data(), sock[1]);
    // });

    // std::thread recvB2A([&] {
    //     MillionaireProtocolRecver recv(n, 64);
    //     recv.compare(res_R.data(), d_R.data(), sock[0]);
    // });

    // sendB2A.join();
    // recvB2A.join();

    // for (u64 i = 0; i < n; i++) {
    //     std::cout << (((res_R[i] ^ res_S[i]) & 1) == (d_R[i] < d_S[i])) << std::endl;
    // }

    // return 0;

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
    const bool sender = cmd.isSet("sender");
    LOG = cmd.getOr("v", 0);

    const bool is_low = (type == 0);
    const bool is_linf = (lp == 0);
    const bool is_2delta = (assumption == 0);

    if (!sender) {
        // Receiver sided assumption
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
    } else {
        is_linf ? fuzzyPsiLow2DeltaSender(cmd) : fuzzyPsiLow2DeltaLpSender(cmd);
    }

    return 0;
}