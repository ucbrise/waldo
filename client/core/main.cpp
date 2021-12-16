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
using dbquery::InitDCFRequest;
using dbquery::InitDCFResponse;
using dbquery::UpdateDCFRequest;
using dbquery::UpdateDCFResponse;
using dbquery::QueryDCFRequest;
using dbquery::QueryDCFResponse;

using namespace dorydb;
using namespace osuCrypto;
using namespace std;

int main(int argc, char *argv[]) {
    string addrs[3] = { "127.0.0.1:12345", "127.0.0.1:12346", "127.0.0.1:12347" };
    uint32_t windowSize = 256;
    uint32_t numBuckets = 256;
    int depth = 4;
    string table_id_dcf = "test-dcf";
    string table_id_at = "test-aggtree";
    vector<uint32_t> data(windowSize, 1);
    map<uint64_t, uint128_t> aggTreeData;
    for (uint64_t i = 0; i < (1 << (depth - 1)); i++) {
        uint128_t one = 1;
        aggTreeData[i + 1] = one;
    }

    vector<shared_ptr<grpc::Channel>> channels;
    for (int i = 0; i < NUM_SERVERS; i++) {
        shared_ptr<grpc::Channel> channel = grpc::CreateChannel(addrs[i], grpc::InsecureChannelCredentials());
        channels.push_back(channel);
    }
    printf("going to create client\n");
    QueryClient *client = new QueryClient(channels);

    client->AddAggTree(table_id_at, sum, depth, aggTreeData);
    printf("Created Aggregate tree\n");
    uint128_t *ret;
    uint128_t *ret_r;
    client->AggTreeQuery(table_id_at, 3, 100, &ret, &ret_r);
    cout << "Done with aggregate query "<< endl;

}

