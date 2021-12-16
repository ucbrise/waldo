#include <string>
#include <vector>
#include <fstream>
#include "../core/client.h"
#include "../core/query.h"
#include "../../secure-indices/core/common.h"
#include "../../utils/json.hpp"
#include "../../utils/config.h"

using grpc::Channel;

using json = nlohmann::json;

using namespace dorydb;
using namespace std;

bool dpfAggTest(QueryClient *client, int numBuckets, int windowSize, int numConds, int reps, vector<uint32_t> &times) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dpf";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    client->AddValList(string("test_vals"), windowSize, dataVals);
    client->AddDPFTable(string("test_dpf"), windowSize, numBuckets, dcfVals);

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->AggQuery(q.agg_table_id, q);
        times.push_back(STOP_TIMER_());
    }
}

bool dpfThroughput(QueryClient *client, int numBuckets, int windowSize, int numConds, vector<uint32_t> &times, int numAppends, int numSearches, int seconds) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dpf";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    client->AddValList(string("test_vals"), windowSize, dataVals);
    client->AddDPFTable(string("test_dpf"), windowSize, numBuckets, dcfVals);

    uint32_t totalMs = 0.0;
    
    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t agg = client->AggQuery(q.agg_table_id, q);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->RunDPFUpdate("test_dpf", 0, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }
}



bool dcfAggTest(QueryClient *client, int numBuckets, int windowSize, int numConds, int reps, vector<uint32_t> &times) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dcf";
        cond.cond_type = RANGE_COND;
        cond.left_x = 8;
        cond.right_x = 4;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;
    cout << "finished making query object" << endl;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    client->AddValList(string("test_vals"), windowSize, dataVals);
    client->AddDCFTable(string("test_dcf"), windowSize, numBuckets, dcfVals);
    cout << "finished setup" << endl;

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->AggQuery(q.agg_table_id, q);
        times.push_back(STOP_TIMER_());
    }
}

bool dcfThroughput(QueryClient *client, int numBuckets, int windowSize, int numConds, vector<uint32_t> &times, int numAppends, int numSearches, int seconds) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dcf";
        cond.cond_type = RANGE_COND;
        cond.left_x = 8;
        cond.right_x = 4;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;
    cout << "finished making query object" << endl;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    client->AddValList(string("test_vals"), windowSize, dataVals);
    client->AddDCFTable(string("test_dcf"), windowSize, numBuckets, dcfVals);
    cout << "finished setup" << endl;
    uint32_t totalMs = 0.0;
    
    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t agg = client->AggQuery(q.agg_table_id, q);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->RunDCFUpdate("test_dcf", 0, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }
}



void aggTreeTest(QueryClient *client, int depth, int reps, vector <uint32_t> &times) {
    map<uint64_t, uint128_t> aggTreeData;
    int left_x = 6;
    string table_id = "test_aggtree";
    for (uint64_t i = 1; i < (1 << (depth - 1)); i++) {
        uint128_t one = 1;
        aggTreeData[i+1] = one;
    }

    client->AddAggTree(table_id, sum, depth, aggTreeData);
    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t *ret;
        uint128_t *ret_r;
        client->AggTreeQuery(table_id, left_x, 1, &ret, &ret_r);
        times.push_back(STOP_TIMER_());
    }
}

void aggTreeThroughput(QueryClient *client, int depth, int reps, vector <uint32_t> &times, int numAppends, int numSearches, int seconds) {
    map<uint64_t, uint128_t> aggTreeData;
    int left_x = 6;
    string table_id = "test_aggtree";
    for (uint64_t i = 1; i < (1 << (depth - 1)); i++) {
        uint128_t one = 1;
        aggTreeData[i+1] = one;
    }
    uint32_t totalMs = 0;
    client->AddAggTree(table_id, sum, depth, aggTreeData);

    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t *ret;
            uint128_t *ret_r;
            client->AggTreeQuery(table_id, left_x, 1, &ret, &ret_r);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->AggTreeAppend(table_id, -1, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }
}

int main(int argc, char *argv[]) {
    ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;

    vector<shared_ptr<grpc::Channel>> channels;
    for (int i = 0; i < NUM_SERVERS; i++) {
        shared_ptr<grpc::Channel> channel = grpc::CreateChannel(config[ADDRS][i], grpc::InsecureChannelCredentials());
        channels.push_back(channel);
    }
    QueryClient *client = new QueryClient(channels, config[MALICIOUS]);

    int logNumBuckets = config[LOG_NUM_BUCKETS];
    int logWindowSize = config[LOG_WINDOW_SZ];
    int numBuckets = 1 << logNumBuckets;
    int windowSize = 1 << logWindowSize;
    cout << "Num buckets: 2^" << logNumBuckets << " = " << numBuckets << endl;
    cout << "Window size: 2^" << logWindowSize << " = " << windowSize << endl;
    int numSearches = config[NUM_SEARCHES];
    int numAppends = config[NUM_APPENDS];
    int seconds = config[SECONDS];
    vector<uint32_t> times;
    if (config[TYPE] == "point") {
        dpfAggTest(client, numBuckets, windowSize, config[NUM_ANDS], config[REPS], times);
    } else if (config[TYPE] == "range") {
        dcfAggTest(client, numBuckets, windowSize, config[NUM_ANDS], config[REPS], times);
    } else if (config[TYPE] == "point-throughput") {
        dpfThroughput(client, numBuckets, windowSize, config[NUM_ANDS], times, numAppends, numSearches, seconds);
    } else if (config[TYPE] == "range-throughput") {
        dcfThroughput(client, numBuckets, windowSize, config[NUM_ANDS], times, numAppends, numSearches, seconds);
    } else if (config[TYPE] == "tree") {
        aggTreeTest(client, config[DEPTH], config[REPS], times);
    } else if (config[TYPE] == "tree-throughput") {
        aggTreeThroughput(client, config[DEPTH], config[REPS], times, numAppends, numSearches, seconds);
    }

    string expDir = config[EXP_DIR];
    ofstream file(expDir + "/results.dat");
    if (file.is_open()) {
        for (int i = 0; i < times.size(); i++) {
            file << "1 " << to_string(times[i]) << endl;
        }
    }

}
