#include <string>
#include <math.h>
#include <assert.h>

#include "client.h"
#include "query.h"
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::ClientAsyncResponseReader;

using dbquery::Query;
using dbquery::Aggregate;
using dbquery::InitDCFRequest;
using dbquery::InitDCFResponse;
using dbquery::InitDPFRequest;
using dbquery::InitDPFResponse;
using dbquery::InitListRequest;
using dbquery::InitListResponse;
using dbquery::InitATRequest;
using dbquery::InitATResponse;
using dbquery::UpdateDCFRequest;
using dbquery::BatchedUpdateDCFRequest;
using dbquery::UpdateDCFResponse;
using dbquery::BatchedUpdateDCFResponse;
using dbquery::UpdateDPFRequest;
using dbquery::BatchedUpdateDPFRequest;
using dbquery::UpdateDPFResponse;
using dbquery::BatchedUpdateDPFResponse;
using dbquery::UpdateListRequest;
using dbquery::BatchedUpdateListRequest;
using dbquery::UpdateListResponse;
using dbquery::BatchedUpdateListResponse;
using dbquery::AppendAT1Request;
using dbquery::AppendAT1Response;
using dbquery::AppendAT2Request;
using dbquery::AppendAT2Response;
using dbquery::QueryDCFRequest;
using dbquery::QueryDCFResponse;
using dbquery::QueryATRequest;
using dbquery::QueryATResponse;
using dbquery::QueryAggRequest;
using dbquery::QueryAggResponse;
using dbquery::BaseFilter;
using dbquery::CombinedFilter;

using namespace dorydb;
using namespace osuCrypto;
using namespace std;

QueryClient::QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious) {
    for (int i = 0; i < NUM_SERVERS; i++) {
        queryStubs.push_back(Query::NewStub(channels[i]));
        aggStubs.push_back(Aggregate::NewStub(channels[i]));
    }
    block seed = toBlock(rand(), rand());
    prng = new PRNG(seed);
    this->malicious = malicious;
}

void QueryClient::AddDCFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data) {
    int numBucketsLog = getDepth(numBuckets);
    DCFTables[id] = new DCFTableClient(id, numBucketsLog, windowSize, malicious);
    alpha = DCFTables[id]->alpha;

    /* Initialize table at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitDCFRequest req;
        InitDCFResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        req.set_num_buckets(numBuckets);
        req.set_malicious(malicious);
        queryStubs[i]->SendDCFInit(&ctx, req, &resp);
    }

    /* Load data. */
    assert(data.size() >= windowSize);

    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++) {
        BatchedUpdateDCFRequest reqs[NUM_SERVERS];
        printf("batch = %d/%d\n", batch, windowSize/UPDATE_CHUNK_SZ);
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++) {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateDCFRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->DCFUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateDCFResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendDCFBatchedUpdate(&ctx, reqs[i], &resp);
        }
        printf("finished batch %d/%d\n", batch, windowSize/UPDATE_CHUNK_SZ);
    }
}

void QueryClient::AddDPFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data) {
    //DCFTables[id] = new Table(id, windowSize, numBuckets);
    int numBucketsLog = getDepth(numBuckets);
    DPFTables[id] = new DPFTableClient(id, numBucketsLog, windowSize, malicious);
    alpha = DPFTables[id]->alpha;

    /* Initialize table at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitDPFRequest req;
        InitDPFResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        req.set_num_buckets(numBuckets);
        req.set_malicious(malicious);
        queryStubs[i]->SendDPFInit(&ctx, req, &resp);
    }

    /* Load data. */
    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++) {
        BatchedUpdateDPFRequest reqs[NUM_SERVERS];
        assert(data.size() >= windowSize);
        printf("batch = %d/%d\n", batch, windowSize/UPDATE_CHUNK_SZ);
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++) {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateDPFRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->DPFUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateDPFResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendDPFBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::AddValList(string id, uint32_t windowSize, vector<uint128_t> &data) {
    /* Initialize list at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitListRequest req;
        InitListResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        queryStubs[i]->SendListInit(&ctx, req, &resp);
    }

    /* Load data. */
    BatchedUpdateListRequest reqs[NUM_SERVERS];
    assert(data.size() >= windowSize);
    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++) {
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++) {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateListRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->ValListUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateListResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendListBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::AddAggTree(string id, AggFunc aggFunc, int depth, map<uint64_t, uint128_t> &data) {
    AggTrees[id] = new AggTreeIndexClient(aggFunc, id, depth, malicious);
    alpha = AggTrees[id]->alpha;

    /* Initialize aggregate tree at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitATRequest req;
        InitATResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_agg_func(aggFunc);
        req.set_depth(depth);
        queryStubs[i]->SendATInit(&ctx, req, &resp);
    }

    map<uint64_t, uint128_t>::iterator it;
    for (it = data.begin(); it != data.end(); it++) {
        this->AggTreeAppend(id, it->first, it->second);
    }
}

void QueryClient::DCFUpdate(string id, uint32_t idx, uint32_t val, UpdateDCFRequest *reqs[]) {
    uint128_t *raw_data = createIndicatorVector(val, DCFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DCFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDCFResponse resp;
        ClientContext ctx;

        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_data0((char *)data[i], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        reqs[i]->set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DCFTables[id]->numBuckets);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::RunDCFUpdate(string id, uint32_t idx, uint32_t val) {
    uint128_t *raw_data = createIndicatorVector(val, DCFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DCFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDCFRequest req;
        UpdateDCFResponse resp;
        ClientContext ctx;

        req.set_id(id);
        req.set_val(idx);
        req.set_data0((char *)data[i], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        req.set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        queryStubs[i]->SendDCFUpdate(&ctx, req, &resp);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}



void QueryClient::DPFUpdate(string id, uint32_t idx, uint32_t val, UpdateDPFRequest *reqs[]) {
    uint128_t *raw_data = createIndicatorVector(val, DPFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DPFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDPFRequest req;
        UpdateDPFResponse resp;
        ClientContext ctx;

        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_data0((char *)data[i], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        reqs[i]->set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DPFTables[id]->numBuckets);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::RunDPFUpdate(string id, uint32_t idx, uint32_t val) {
    uint128_t *raw_data = createIndicatorVector(val, DPFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DPFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDPFRequest req;
        UpdateDPFResponse resp;
        ClientContext ctx;

        req.set_id(id);
        req.set_val(idx);
        req.set_data0((char *)data[i], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        req.set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        queryStubs[i]->SendDPFUpdate(&ctx, req, &resp);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[]) {
    uint128_t shares[3];
    splitIntoSingleArithmeticShares(prng, val, shares);
    //cout << "val " << idx << " " << shares[0] << " " << shares[1] << " " << shares[2] << " " << shares[0] + shares[1] + shares[2] << endl;
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_share0((char *)&shares[i], sizeof(uint128_t));
        reqs[i]->set_share1((char *)&shares[(i + 1) % NUM_SERVERS], sizeof(uint128_t));
    }
}

void QueryClient::AggTreeAppend(string id, uint64_t idx, uint128_t val) {
    uint128_t *parents;
    uint128_t *parentShares[3];
    uint128_t *newAggVals;
    uint128_t *newAggValShares[3];
    AppendAT1Request req1[3];
    AppendAT2Request req2[3];
    AppendAT1Response resp1[3];
    AppendAT2Response resp2[3];
    int len;

    for (int i = 0; i < NUM_SERVERS; i++) {
        ClientContext ctx;
        req1[i].set_id(id);
        req1[i].set_idx(idx);
        queryStubs[i]->SendATAppend1(&ctx, req1[i], &resp1[i]);
        parentShares[i] = (uint128_t *)malloc(resp1[i].parent_shares_size() * sizeof(uint128_t));
        for (int j = 0; j < resp1[i].parent_shares_size(); j++) {
            memcpy((uint8_t *)&parentShares[i][j], resp1[i].parent_shares(j).c_str(), sizeof(uint128_t));
        }
    }

    len = resp1[0].parent_shares_size();
    parents = (uint128_t *)malloc(len * sizeof(uint128_t));
    newAggVals = (uint128_t *)malloc((len + 1) * sizeof(uint128_t));
    for (int i = 0; i < NUM_SERVERS; i++) {
        newAggValShares[i] = (uint128_t *)malloc((len + 1) * sizeof(uint128_t));
    }

    combineArithmeticShares(parents, len, parentShares, NUM_SERVERS, true);
    AggTrees[id]->propagateNewVal(val, parents, newAggVals, len + 1);
    splitIntoArithmeticShares(prng, newAggVals, len + 1, newAggValShares);

    for (int i = 0; i < NUM_SERVERS; i++) {
        ClientContext ctx;
        req2[i].set_id(id);
        req2[i].set_idx(idx);
        for (int j = 0; j < resp1[0].parent_shares_size() + 1; j++) {
            req2[i].add_new_shares0((uint8_t *)&newAggValShares[i][j], sizeof(uint128_t));
            req2[i].add_new_shares1((uint8_t *)&newAggValShares[(i + 1) % NUM_SERVERS][j], sizeof(uint128_t));
        }
        queryStubs[i]->SendATAppend2(&ctx, req2[i], &resp2[i]);
    }
    free(parents);
    free(newAggVals);
    for (int i = 0; i < NUM_SERVERS; i++) {
        free(parentShares[i]);
        free(newAggValShares[i]);
    }
}

void QueryClient::GenerateDPFFilter(string id, uint32_t x, BaseFilter *filters[]) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i]->set_id(id);
        filters[i]->set_key0(k[i][0], key_len);
        filters[i]->set_key1(k[i][1], key_len);
        filters[i]->set_is_point(true);
    }
}

void QueryClient::GenerateDCFFilter(string id, uint32_t left_x, uint32_t right_x, BaseFilter *filters[]) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize; 
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    //cout << "Created and serialized all DCF keys" << endl;
    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i]->set_id(id);
        filters[i]->set_key0(k[i][0], key_len);
        filters[i]->set_key1(k[i][1], key_len);
        filters[i]->set_is_point(false);
    }
}

void QueryClient::GenerateBaseFilter(Condition *cond, BaseFilter *filters[]) {
    if (cond->cond_type == POINT_COND) {
        GenerateDPFFilter(cond->table_id, cond->x, filters);
    } else if (cond->cond_type == RANGE_COND) {
        GenerateDCFFilter(cond->table_id, cond->left_x, cond->right_x, filters);
    }
}

void QueryClient::GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[]) {
    for (int i = 0; i < expr->conds.size(); i++) {
        cout << "generating filter for cond " << i << endl;
        BaseFilter *tmp[3];
        for (int j = 0; j < NUM_SERVERS; j++) {
            tmp[j] = filters[j]->add_base_filters();
        }
        GenerateBaseFilter(&expr->conds[i], tmp);
    }
    cout << "generated all base filters" << endl;
    filters[0]->set_op_is_and(expr->op_type == AND_OP);
    filters[1]->set_op_is_and(expr->op_type == AND_OP);
    filters[2]->set_op_is_and(expr->op_type == AND_OP);
}

uint128_t QueryClient::AggQuery(string agg_id, QueryObj &query) {
    CombinedFilter *filters[NUM_SERVERS];
    QueryAggRequest reqs[NUM_SERVERS];
    QueryAggResponse resps[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    Status status[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryAggResponse>> rpcs[NUM_SERVERS];
    uint128_t ret = 0;
    uint128_t mac = 0;
    uint128_t lin_comb = 0;
    uint128_t lin_comb_mac = 0;

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_filter();
    }
    cout << "going to generate combined filter" << endl;
    GenerateCombinedFilter(query.expr, filters);
    cout << "generated combined filter" << endl;

    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_agg_id(agg_id);
        cout << "Query size: " << reqs[i].ByteSizeLong() << "B" << endl;
        rpcs[i] = queryStubs[i]->AsyncSendAggQuery(&ctx[i], reqs[i], &cq[i]);
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
    }
 
    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                uint128_t res;
                uint128_t mac_res;
                uint128_t lc_share;
                uint128_t lc_mac_share;
                memcpy((uint8_t *)&res, (const uint8_t *)resps[i].res().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&mac_res, (const uint8_t *)resps[i].mac().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&lc_share, (const uint8_t *)resps[i].lin_comb().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&lc_mac_share, (const uint8_t *)resps[i].lin_comb_mac().c_str(), sizeof(uint128_t));
                ret += res;
                mac += mac_res;
                lin_comb += lc_share;
                lin_comb_mac += lc_mac_share;
            } else {
                cout << "ERROR receiving message " << status[i].error_message().c_str() << endl;
            }
        }
    }
    ret %= group_mod;
    mac %= group_mod;
    lin_comb %= group_mod;
    lin_comb_mac %= group_mod;
    if (malicious) {
        assert ((lin_comb * GetMACAlpha()) % group_mod == lin_comb_mac);
        assert ((ret * GetMACAlpha()) % group_mod == mac);
        cout << "MAC check passed" << endl;
    }

    return ret;
    
}


uint128_t *QueryClient::DCFQuery(string id, uint32_t left_x, uint32_t right_x, size_t ret_len) {
    uint128_t *ret = (uint128_t *)malloc(ret_len * sizeof(uint128_t));
    memset(ret, 0, ret_len * sizeof(uint128_t));

    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize; 
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    QueryDCFRequest reqs[NUM_SERVERS];
    QueryDCFResponse resps[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryDCFResponse>> rpcs[NUM_SERVERS];
    Status status[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_id(id);
        reqs[i].set_key0(k[i][0], key_len);
        reqs[i].set_key1(k[i][1], key_len);
        rpcs[i] = queryStubs[i]->AsyncSendDCFQuery(&ctx[i], reqs[i], &cq[i]);
    }
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                const uint128_t *res = (const uint128_t *)resps[i].res().c_str();
                for (int i = 0; i < ret_len; i++) {
                    ret[i] += res[i];
                }
            } else {
                printf("ERROR receiving message: %s\n", status[i].error_message().c_str());
            }
        }
    }
    for (int i = 0; i < ret_len; i++) {
        ret[i] %= group_mod;
    }

    return ret;
}

uint128_t QueryClient::AggTreeQuery(string id, uint128_t left_x, uint128_t right_x) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = (one << gout_bitsize);
    uint128_t ret;
    uint128_t mac;
    uint128_t ret_r;
    uint128_t mac_r;
    uint128_t retShares0[NUM_SERVERS];
    uint128_t macShares0[NUM_SERVERS];
    uint128_t retShares0_r[NUM_SERVERS];
    uint128_t macShares0_r[NUM_SERVERS];
    uint128_t retShares[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t macShares[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t retShares_r[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t macShares_r[NUM_SERVERS][AggTrees[id]->depth + 1];

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);

    QueryATRequest reqs[NUM_SERVERS];
    QueryATResponse resps[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryATResponse>> rpcs[NUM_SERVERS];
    Status status[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_id(id);
        reqs[i].set_key0(k[i][0], key_len);
        reqs[i].set_key1(k[i][1], key_len);
        rpcs[i] = queryStubs[i]->AsyncSendATQuery(&ctx[i], reqs[i], &cq[i]);
    }
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                memcpy((uint128_t *)&retShares[i], (const uint8_t *)resps[i].res().c_str(), (AggTrees[id]->depth+1) * sizeof(uint128_t));
                if (malicious) {
                    memcpy((uint128_t *)&macShares[i], (const uint8_t *)resps[i].mac().c_str(), (AggTrees[id]->depth + 1) * sizeof(uint128_t));
                }
                memcpy((uint128_t *)&retShares_r[i], (const uint8_t *)resps[i].res_r().c_str(), (AggTrees[id]->depth+1) * sizeof(uint128_t));
                if (malicious) {
                    memcpy((uint128_t *)&macShares_r[i], (const uint8_t *)resps[i].mac_r().c_str(), (AggTrees[id]->depth + 1) * sizeof(uint128_t));
                }
            } else {
                printf("ERROR receiving message: %s\n", status[i].error_message().c_str());
            }
        }
    }
    // simulating some computation here
    for (int i = 0; i < NUM_SERVERS; i++) {
        retShares0[i] = retShares[i][0];
        macShares0[i] = macShares[i][0];
        retShares0_r[i] = retShares_r[i][0];
        macShares0_r[i] = macShares_r[i][0];
    }
    for (int i = 0; i < AggTrees[id]->depth + 1; i++){
        // left
        ret = combineSingleArithmeticShares(retShares0, NUM_SERVERS, false);
        ret %= group_mod;
        // right
        ret_r = combineSingleArithmeticShares(retShares0_r, NUM_SERVERS, false);
        ret_r %= group_mod;
        if (malicious) {
            // left
            mac = combineSingleArithmeticShares(macShares0, NUM_SERVERS, false);
            mac %= group_mod;
            assert ((ret * GetMACAlpha()) % group_mod == mac);
            // right
            mac_r = combineSingleArithmeticShares(macShares0_r, NUM_SERVERS, false);
            mac_r %= group_mod;
            assert ((ret_r * GetMACAlpha()) % group_mod == mac_r);
        }
    }
    if (malicious) {
        cout << "MAC check passed" << endl;
    }

    return ret + ret_r;

}

uint128_t QueryClient::GetMACAlpha(){
    return alpha;
}
