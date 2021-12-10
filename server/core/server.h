#ifndef _SERVER_H_
#define _SERVER_H_

#include <grpcpp/grpcpp.h>
//#include "../libs/grpc/include/grpc/impl/codegen/port_platform.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
//#include "table.h"

#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"

#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../secure-indices/core/common.h"
#include "server.h"

// #include <BgiPirClient.h>
// #include <BgiPirServer.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/TestCollection.h>

#include <map>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>

using namespace osuCrypto;
using namespace std;
using namespace dorydb;

using dbquery::CombinedFilter;
using dbquery::Aggregate;
using dbquery::MultRequest;
using dbquery::MultResponse;
using dbquery::InitSystemRequest;
using dbquery::InitSystemResponse;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::ServerAsyncResponseWriter;

enum RpcType {INIT, MULT};

class QueryServer {
    public:
        QueryServer(string addrs[], int serverID, int cores, bool malicious);
        void StartSystemInit(string addrs[]);
        void FinishSystemInit(const uint8_t *key);
        void AddValList(string id, uint32_t windowSize);
        void DCFAddTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious);
        void DPFAddTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious);
        void AggTreeAddIndex(string id, uint32_t depth, AggFunc aggFunc);
        void DPFUpdate(string id, uint32_t loc, const uint128_t *data0, const uint128_t *data1);
        void DCFUpdate(string id, uint32_t loc, const uint128_t *data0, const uint128_t *data1);
        void ValListUpdate(string id, uint32_t loc, uint128_t val0, uint128_t val1);
        uint128_t **AggTreeAppend1(string id, int *len);
        void AggTreeAppend2(string id, uint32_t idx, uint128_t *new_shares0, uint128_t *new_shares1);
        void DCFQuery(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len);
        void DCFQueryRSS(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len);
        void DPFQuery(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len);
        void DPFQueryRSS(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len);
        void RSSReshareInnerLoop(uint128_t *res0, uint128_t *res1, uint32_t numSets, uint32_t len, int idx);
        void RSSReshareGenRandCoeffs(uint128_t *rand_coeff_shares0, uint128_t *rand_coeff_shares1, uint32_t numSets, uint32_t len, int idx);
        void RSSReshare(uint128_t **res0, uint128_t **res1, uint32_t numSets, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        void AddToBatchMACCheck(uint128_t** x0, uint128_t** x1, uint128_t* coeff0, uint128_t* coeff1, uint32_t numSets, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        void AggTreeQuery(string id, const uint8_t *key0, const uint8_t *key1, uint128_t *res, uint128_t *mac, uint128_t *res_r, uint128_t *mac_r, int* dd);
        void Multiply(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        void AddToBatchMACCheckFromMult(uint128_t* x0, uint128_t* x1, uint128_t* coeff0, uint128_t* coeff1, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        void AndFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        void OrFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc);
        inline uint128_t GetNextSecretShareOfZero(int idx);
        inline void GetNextSecretShareOfRandCoeff(uint128_t *rand_coeff_shares0, uint128_t* rand_coeff_shares1, int idx);
        void AdjustPRFCounter(int amount);
        void FillZeroSharesPlusRandCoeff(uint128_t *zero_shares, uint128_t *rand_coeff_shares0, uint128_t* rand_coeff_shares1, int start_loc, int prf_idx, int chunk_size, int bgn);
        void FinishMultiply(const uint128_t *shares, int len);
        void EvalFilter(uint128_t **filter0, uint128_t **filter1, const CombinedFilter &filterSpec, uint128_t *lin_comb_accumulator, uint128_t *lin_comb_mac_accumulator);
        void AggFilterQuery(string aggID, const CombinedFilter &filterSpec, uint128_t *res, uint128_t *mac, uint128_t *lc, uint128_t *lc_mac);
        
        Aggregate::AsyncService *service;
        ServerCompletionQueue *cq;
        bool malicious;
        int cores;

    private:
        uint128_t prfKey0;
        uint128_t prfKey1;
        uint128_t prfCounter;
        map<string, pair<DPFTableServer*, DPFTableServer*>> DPFTables;
        map<string, pair<DCFTableServer*, DCFTableServer*>> DCFTables;
        map<string, pair<vector<uint128_t>, vector<uint128_t>>> ValLists;
        map<string, pair<AggTreeIndexServer*, AggTreeIndexServer*>> AggTrees;
        map<string, int> DPFTableWindowPtrs;
        map<string, int> DCFTableWindowPtrs;
        map<string, int> ValListWindowPtrs;
        unique_ptr<dbquery::Query::Stub> nextServerStub;
        unique_ptr<dbquery::Aggregate::Stub> multStub;
        int serverID;
        mutex multLock;
        condition_variable multCV;
        condition_variable orderCV;
        uint128_t *multReceivedShares;

};

class CallData {
    public:
        CallData(QueryServer &server, Aggregate::AsyncService *service, ServerCompletionQueue *cq, RpcType type);
        void Proceed();
    private:
        Aggregate::AsyncService *service;
        ServerCompletionQueue *cq;
        ServerContext ctx;
        MultRequest reqMult;
        MultResponse respMult;
        ServerAsyncResponseWriter<MultResponse> responderMult;
        InitSystemRequest reqInit;
        InitSystemResponse respInit;
        ServerAsyncResponseWriter<InitSystemResponse> responderInit;
        enum CallStatus {CREATE, PROCESS, FINISH};
        CallStatus status;
        RpcType type;
        QueryServer &server;
};

#endif
