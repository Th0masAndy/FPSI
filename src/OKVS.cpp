#include "OKVS.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <algorithm>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

constexpr u64 kMinItemsPerThread = 1ULL << 16;
constexpr u64 kMaxOkvsThreads = 16;

u64 resolveThreadCount(u64 requested, u64 itemCount)
{
    if (requested != 0) {
        return requested;
    }

    const u64 hardwareThreads = std::max(1u, std::thread::hardware_concurrency());
    const u64 workThreads = std::max<u64>(1, (itemCount + kMinItemsPerThread - 1) / kMinItemsPerThread);
    return std::min({ hardwareThreads, workThreads, kMaxOkvsThreads });
}

} // namespace

OKVS::OKVS(u64 numItems, u64 weight_, u64 ssp, u64 binSize_)
{
    paxos.init(numItems, binSize_, weight_, ssp, volePSI::PaxosParam::GF128, oc::ZeroBlock);
    param = paxos.mPaxosParam;
}

vector<block> OKVS::encode(const vector<block> &keys, const vector<block> &values, u64 numThreads)
{
    vector<block> encoding;
    encode(keys, values, encoding, numThreads);
    return encoding;
}

void OKVS::encode(const vector<block> &keys, const vector<block> &values, vector<block> &encoding, u64 numThreads)
{
    if (keys.size() != values.size()) {
        throw std::invalid_argument("OKVS keys and values must have the same size");
    }

    encoding.resize(paxos.size());
    PRNG prng(sysRandomSeed());
    paxos.solve<block>(keys, values, encoding, &prng, resolveThreadCount(numThreads, keys.size()));
}

vector<block> OKVS::decode(const vector<block> &encoding, const vector<block> &keys, u64 numThreads)
{
    vector<block> values;
    decode(encoding, keys, values, numThreads);
    return values;
}

void OKVS::decode(const vector<block> &encoding, const vector<block> &keys, vector<block> &values, u64 numThreads)
{
    if (encoding.size() != paxos.size()) {
        throw std::invalid_argument("OKVS encoding has an unexpected size");
    }

    values.resize(keys.size());
    paxos.decode<block>(keys, values, encoding, resolveThreadCount(numThreads, keys.size()));
}

u64 OKVS::size()
{
    return paxos.size();
}

// SparseOKVS::SparseOKVS(u64 numItems, u64 weight_, u64 ssp, u64 binSize_) : weight(weight_), binSize(binSize_)
// {
//     paxos.init(numItems, binSize_, weight_, ssp, volePSI::PaxosParam::GF128, oc::ZeroBlock);
//     param = paxos.mPaxosParam;
//     binNum = paxos.mNumBins;
//     sparseSize = param.mSparseSize;
//     denseSize = param.mDenseSize;
// }

// void SparseOKVS::encode(vector<block> &keys, vector<block> &values, vector<block> &E_s, vector<block> &E_d, u64 numThreads)
// {
//     vector<block> E(paxos.size());

//     if (keys.size() != values.size())
//         throw RTE_LOC;

//     paxos.solve<block>(keys, values, E, nullptr, numThreads);

//     // split E into sparse and dense part.
//     getSparse(E, E_s);
//     getDense(E, E_d);
// }

// void SparseOKVS::computeIndex(vector<block> &keys, vector<block> &hashs, vector<vector<u64>> &idxs, u64 numThreads)
// {
//     if (keys.size() != hashs.size() || keys.size() != idxs.size())
//         throw RTE_LOC;
//     if (idxs[0].size() != weight + 1)
//         throw RTE_LOC;

//     paxos.computeRetrievalIdx<block>(keys, hashs, idxs, numThreads);
// }

// void SparseOKVS::decode(vector<block> &hashs, vector<vector<u64>> &idxs, vector<block> &values, vector<std::map<u64, block>> &E, u64 numThreads)
// {
//     paxos.decodeRetrievalIdx<block>(hashs, idxs, values, E, numThreads);
// }

// void SparseOKVS::getSparse(vector<block> &E, vector<block> &E_s)
// {
//     E_s.resize(binNum * sparseSize);
//     for (u64 b = 0; b < binNum; ++b) {
//         for (u64 j = 0; j < sparseSize; ++j) {
//             E_s[b * sparseSize + j] = E[b * (sparseSize + denseSize) + j];
//         }
//     }
// }

// void SparseOKVS::getDense(vector<block> &E, vector<block> &E_d)
// {
//     E_d.resize(binNum * denseSize);
//     for (u64 b = 0; b < binNum; ++b) {
//         for (u64 j = 0; j < denseSize; ++j) {
//             E_d[b * denseSize + j] = E[b * (sparseSize + denseSize) + sparseSize + j];
//         }
//     }
// }

// u64 SparseOKVS::size()
// {
//     return paxos.size();
// }

// u64 SparseOKVS::sizeOfSparse()
// {
//     return binNum * sparseSize;
// }

// u64 SparseOKVS::sizeOfDense()
// {
//     return binNum * denseSize;
// }

// void perfBaxos(oc::CLP &cmd)
// {
//     auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 26));
//     auto t = cmd.getOr("t", 1ull);
//     // auto rand = cmd.isSet("rand");
//     auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);
//     auto w = cmd.getOr("w", 3);
//     auto ssp = cmd.getOr("ssp", 40);
//     auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;
//     auto nt = cmd.getOr("nt", 1);

//     // PaxosParam pp(n, w, ssp, dt);
//     auto binSize = 1 << cmd.getOr("lbs", 14);
//     u64 baxosSize;
//     {
//         Baxos paxos;
//         paxos.init(n, binSize, w, ssp, dt, oc::ZeroBlock);
//         baxosSize = paxos.size();
//     }
//     std::vector<block> key(n), val(n), pax(baxosSize);

//     auto decode_size = 500;

//     std::vector<block> decode_val(decode_size);
//     std::vector<block> decode_key(decode_size);

//     PRNG prng(ZeroBlock);
//     prng.get<block>(key);
//     prng.get<block>(val);

//     Timer timer;
//     auto start = timer.setTimePoint("start");
//     auto end = start;
//     auto decode_start = start;
//     auto decode_end = start;
//     for (u64 i = 0; i < t; ++i) {
//         Baxos paxos;

//         paxos.init(n, binSize, w, ssp, dt, block(i, i));

//         // if (v > 1)
//         //	paxos.setTimer(timer);

//         timer.setTimePoint("s" + std::to_string(i));

//         paxos.solve<block>(key, val, pax, nullptr, nt);

//         end = timer.setTimePoint("d" + std::to_string(i));

//         memcpy(decode_key.data(), key.data(), decode_key.size() * sizeof(block));

//         // paxos.decode<block>(decode_key, decode_val, pax, nt);

//         vector<block> hashs(decode_key.size());
//         vector<vector<u64>> idxs(decode_key.size(), vector<u64>(3 + 1));

//         paxos.computeRetrievalIdx<block>(decode_key, hashs, idxs, nt);

//         // for (auto &vec : idxs) {
//         //     for (auto &u : vec)
//         //         std::cout << u << ",";
//         // }

//         decode_start = timer.setTimePoint("decode");

//         vector<std::map<u64, block>> pp(paxos.mNumBins, std::map<u64, block>());

//         // dense part
//         for (u64 b = 0; b < paxos.mNumBins; ++b) {
//             auto paxos_seg = std::vector<block>(
//                 pax.begin() + b * (paxos.mPaxosParam.mSparseSize + paxos.mPaxosParam.mDenseSize),
//                 pax.begin() + (b + 1) * (paxos.mPaxosParam.mSparseSize + paxos.mPaxosParam.mDenseSize));

//             for (u64 j = 0; j < paxos.mPaxosParam.mDenseSize; ++j) {
//                 pp[b][j + paxos.mPaxosParam.mSparseSize] = paxos_seg[j + paxos.mPaxosParam.mSparseSize];
//             }
//         }

//         // sparse part
//         for (u64 i = 0; i < decode_key.size(); ++i) {
//             auto vec = idxs[i];
//             auto binIdx = vec[paxos.mPaxosParam.mWeight];
//             for (u64 j = 0; j < paxos.mPaxosParam.mWeight; ++j) {
//                 pp[binIdx][vec[j]] = pax[binIdx * (paxos.mPaxosParam.mSparseSize + paxos.mPaxosParam.mDenseSize) + vec[j]];
//             }
//         }

//         decode_end = timer.setTimePoint("decode");

//         std::cout << "total dense size: " << paxos.mNumBins * paxos.mPaxosParam.mDenseSize * sizeof(block) / 1024.0 / 1024.0 << " MB" << std::endl;

//         paxos.decodeRetrievalIdx<block>(hashs, idxs, decode_val, pp, nt);
//     }

//     if (memcmp(val.data(), decode_val.data(), decode_val.size() * sizeof(block)) != 0)
//         std::cout << "Error: Decoded values do not match original values." << std::endl;

//     if (v)
//         std::cout << timer << std::endl;

//     auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);

//     auto decode_t = std::chrono::duration_cast<std::chrono::microseconds>(decode_end - decode_start).count() / double(1000);

//     std::cout << "encode " << tt << " ms, decode " << decode_t << " ms, e=" << double(baxosSize) / n << std::endl;
// }
