#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>
#include <cstring>
#include <map>
#include <vector>
#include "volePSI/Paxos.h"
using namespace oc;
using namespace osuCrypto;
using namespace std;

class OKVS {
public:
    OKVS(u64 numItems, u64 weight_ = 3, u64 ssp = 40, u64 binSize_ = 1 << 14);

    vector<block> encode(const vector<block> &keys, const vector<block> &values);

    void encode(const vector<block> &keys, const vector<block> &values, vector<block> &encoding);

    vector<block> decode(const vector<block> &encoding, const vector<block> &keys, u64 numThreads = 0);

    void decode(const vector<block> &encoding, const vector<block> &keys, vector<block> &values, u64 numThreads = 0);

    u64 size();

private:
    volePSI::Baxos paxos;
    volePSI::PaxosParam param;
};

// A sparse OKVS based on Paxos, including encoding, decoding, and computing sparse index.
class SparseOKVS {
public:
    u64 sparseSize;
    u64 denseSize;
    u64 weight;
    u64 binNum;
    u64 binSize;

    SparseOKVS(u64 numItems, u64 weight_ = 3, u64 ssp = 40, u64 binSize_ = 1 << 14);

    void encode(vector<block> &keys, vector<block> &values, vector<block> &E_s, vector<block> &E_d, u64 numThreads = 0);

    vector<block> getDense(vector<block> &E);

    void computeIndex(vector<block> &keys, vector<block> &hashs, vector<vector<u64>> &idxs, u64 numThreads = 0);

    void decode(vector<block> &hashs, vector<vector<u64>> &idxs, vector<block> &values, vector<std::map<u64, block>> &E, u64 numThreads = 0);

    void getSparse(vector<block> &E, vector<block> &E_s);

    void getDense(vector<block> &E, vector<block> &E_d);

    u64 size();

    u64 sizeOfSparse();

    u64 sizeOfDense();

private:
    volePSI::Baxos paxos;
    volePSI::PaxosParam param;
};
