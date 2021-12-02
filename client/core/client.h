#ifndef CLIENT_H
#define CLIENT_H

#include <grpcpp/grpcpp.h>
//#include "../libs/grpc/include/grpc/impl/codegen/port_platform.h"
#include "../../network/core/query.grpc.pb.h"
//#include "table.h"

#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"

#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../secure-indices/core/common.h"
#include "query.h"

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

#define UPDATE_CHUNK_SZ 10000

using namespace osuCrypto;
using namespace std;
using namespace dorydb;
using dbquery::Query;
using dbquery::Aggregate;
using dbquery::CombinedFilter;
using dbquery::BaseFilter;
using dbquery::UpdateDCFRequest;
using dbquery::UpdateDPFRequest;
using dbquery::UpdateListRequest;
using grpc::Channel;
using grpc::ClientContext;
typedef unsigned __int128 bgi_uint128_t;

class QueryClient
{
public:
    QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious = false);

    void AddDCFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data);
    void AddDPFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data);
    void AddValList(string id, uint32_t windowSize, vector<uint128_t> &data);
    void AddAggTree(string id, AggFunc aggFunc, int depth, map<uint64_t, uint128_t> &data);
    void DCFUpdate(string id, uint32_t idx, uint32_t val, UpdateDCFRequest *reqs[]);
    void RunDCFUpdate(string id, uint32_t idx, uint32_t val);
    void DPFUpdate(string id, uint32_t idx, uint32_t val, UpdateDPFRequest *reqs[]);
    void RunDPFUpdate(string id, uint32_t idx, uint32_t val);
    void ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[]);
    void AggTreeAppend(string id, uint64_t idx, uint128_t val);

    uint128_t *DCFQuery(string id, uint32_t left_x, uint32_t right_x, size_t ret_len);
    uint128_t AggTreeQuery(string id, uint128_t left_x, uint128_t right_x);

    uint128_t AggQuery(string agg_id, QueryObj &query);
    void GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[]);
    void GenerateBaseFilter(Condition *cond, BaseFilter *filters[]);
    void GenerateDPFFilter(string table_id, uint32_t x, BaseFilter *filters[]);
    void GenerateDCFFilter(string table_id, uint32_t left_x, uint32_t right_x, BaseFilter *filters[]);

    uint128_t GetMACAlpha();
private:
    vector<unique_ptr<dbquery::Query::Stub>> queryStubs;
    vector<unique_ptr<dbquery::Aggregate::Stub>> aggStubs;
    PRNG *prng;
    uint128_t modulus;
    bool malicious;
    uint128_t alpha;
    // std::unique_ptr<dbquery::QueryDCF::Stub> DCFstub_;
    map<string, DPFTableClient*> DPFTables;
    map<string, DCFTableClient*> DCFTables;
    map<string, AggTreeIndexClient*> AggTrees;

    uint8_t *RunCondition(Condition *cond, size_t ret_len);
    uint8_t *RecurseExpression(Expression *expr, size_t ret_len);

};
#endif
