#include "secure-indices/core/players.h"
#include <string>

using namespace std;
//using namespace osuCrypto;
using namespace dorydb;

//#define VERBOSE_PRINT

bool malicious = true;
int mac_factor = malicious ? 2 : 1;

void copy_keys_to_server(clkey* ckey, svkey* s0key, svkey* s1key){
    uint64_t dpf_size = ckey->dpf_size;
    uint64_t dcf_size = ckey->dcf_size;
    
    // DPF
    if(dpf_size > 0){
        s0key->dpf_key = (block*) malloc(dpf_size * sizeof(block));
        s1key->dpf_key = (block*) malloc(dpf_size * sizeof(block));
        s0key->dpf_g = (uint128_t*) malloc(dpf_size * sizeof(uint128_t));
        s1key->dpf_g = (uint128_t*) malloc(dpf_size * sizeof(uint128_t));
        memcpy(s0key->dpf_key, ckey->dpf_key0, dpf_size * sizeof(block)); 
        memcpy(s1key->dpf_key, ckey->dpf_key1, dpf_size * sizeof(block)); 
        memcpy(s0key->dpf_g, ckey->dpf_g0, dpf_size * sizeof(uint128_t)); 
        memcpy(s1key->dpf_g, ckey->dpf_g1, dpf_size * sizeof(uint128_t));
        if(malicious){
            s0key->dpf_mac_key = (block*) malloc(dpf_size * sizeof(block));
            s1key->dpf_mac_key = (block*) malloc(dpf_size * sizeof(block));
            s0key->dpf_mac_g = (uint128_t*) malloc(dpf_size * sizeof(uint128_t));
            s1key->dpf_mac_g = (uint128_t*) malloc(dpf_size * sizeof(uint128_t));
            memcpy(s0key->dpf_mac_key, ckey->dpf_mac_key0, dpf_size * sizeof(block));
            memcpy(s1key->dpf_mac_key, ckey->dpf_mac_key1, dpf_size * sizeof(block));
            memcpy(s0key->dpf_mac_g, ckey->dpf_mac_g0, dpf_size * sizeof(uint128_t));
            memcpy(s1key->dpf_mac_g, ckey->dpf_mac_g1, dpf_size * sizeof(uint128_t));
        }

    }
    s0key->dpf_size = dpf_size;
    s1key->dpf_size = dpf_size;
    
    // DCF
    if(dcf_size > 0){
        s0key->dcf_key = (block*) malloc(dcf_size * sizeof(block));
        s1key->dcf_key = (block*) malloc(dcf_size * sizeof(block));
        s0key->dcf_v = (uint128_t*) malloc(dcf_size * sizeof(uint128_t));
        s1key->dcf_v = (uint128_t*) malloc(dcf_size * sizeof(uint128_t));
        memcpy(s0key->dcf_key, ckey->dcf_key0, dcf_size * sizeof(block));
        memcpy(s1key->dcf_key, ckey->dcf_key1, dcf_size * sizeof(block));
        memcpy(s0key->dcf_v, ckey->dcf_v0, dcf_size * sizeof(uint128_t));
        memcpy(s1key->dcf_v, ckey->dcf_v1, dcf_size * sizeof(uint128_t));
        if(malicious){
            s0key->dcf_mac_key = (block*) malloc(dcf_size * sizeof(block));
            s1key->dcf_mac_key = (block*) malloc(dcf_size * sizeof(block));
            s0key->dcf_mac_v = (uint128_t*) malloc(dcf_size * sizeof(uint128_t));
            s1key->dcf_mac_v = (uint128_t*) malloc(dcf_size * sizeof(uint128_t));
            memcpy(s0key->dcf_mac_key, ckey->dcf_mac_key0, dcf_size * sizeof(block));
            memcpy(s1key->dcf_mac_key, ckey->dcf_mac_key1, dcf_size * sizeof(block));
            memcpy(s0key->dcf_mac_v, ckey->dcf_mac_v0, dcf_size * sizeof(uint128_t));
            memcpy(s1key->dcf_mac_v, ckey->dcf_mac_v1, dcf_size * sizeof(uint128_t));
        }
    }
    s0key->dcf_size = dcf_size;
    s1key->dcf_size = dcf_size;

    s0key->role = EVAL0;
    s1key->role = EVAL1;
    s0key->init = true; 
    s1key->init = true;
}

bool check_agg_tree_correctness(uint128_t left_x, uint128_t right_x, RootNode *tree, uint128_t* res1, uint128_t* res_child1, uint128_t* res2, uint128_t* res_child2, uint64_t depth, uint64_t size, bool use_modulus, uint128_t modulus, bool malicious, uint128_t alpha){
    uint64_t ctr = 0;
    uint64_t idx = 0;
 
    // Processing truth
#ifdef VERBOSE_PRINT
    for(int d=0; d<=depth; d++){
        std::cout<<"Truth || depth "<<d<<endl;
        for(int i=0; i<(1<<d); i++){
            std::cout<<(uint64_t)truth[ctr++]<<" ";
        } 
        std::cout<<endl;
    }
    ctr = 0;
#endif
    uint128_t* truth_res = (uint128_t*)malloc(sizeof(uint128_t)*(depth + 1));
    uint128_t* truth_res_child = (uint128_t*)malloc(sizeof(uint128_t)*(depth + 1));
    memset(truth_res, 0, sizeof(uint128_t)*(depth + 1));
    memset(truth_res_child, 0, sizeof(uint128_t)*(depth + 1));

    uint128_t* truth_res_r = (uint128_t*)malloc(sizeof(uint128_t)*(depth + 1));
    uint128_t* truth_res_child_r = (uint128_t*)malloc(sizeof(uint128_t)*(depth + 1));
    memset(truth_res_r, 0, sizeof(uint128_t)*(depth + 1));
    memset(truth_res_child_r, 0, sizeof(uint128_t)*(depth + 1));
    
    queue<Node *>next;
    int traversalIdx = 0;
    int levelIdx = 0;
    int currDepth = 0;
    next.push(tree->root);
    while (!next.empty()) {
        Node *front = next.front();
        next.pop();
        if (currDepth != front->depth) levelIdx = 0;
        int idx = (levelIdx << ((depth-1) - front->depth)) + (1ULL << ((depth-1) - front->depth)) - 1ULL;
        uint128_t activated_l = (idx < left_x) ? 1 : 0;
        uint128_t activated_r = (idx > right_x) ? 1 : 0;
        //cout << "activated? " << activated << endl;
        //cout << "Adding " << front->aggVal << " and " << front->getChildAggVals() << endl;
        truth_res_child[front->depth] += activated_l * front->getChildAggVals();
        truth_res[front->depth] += activated_l * front->aggVal;
        truth_res_child_r[front->depth] += activated_r * front->getChildAggVals();
        truth_res_r[front->depth] += activated_r * front->aggVal;
        if (use_modulus) {
            truth_res_child[front->depth] %= modulus;
            truth_res[front->depth] %= modulus;
            truth_res_child_r[front->depth] %= modulus;
            truth_res_r[front->depth] %= modulus;
        }
        if (front->leftChild) next.push(front->leftChild);
        if (front->rightChild) next.push(front->rightChild);
        levelIdx++;
        currDepth = front->depth;
    }
   
    // Processing secure protocol results
    uint128_t* res1_r = res1 + mac_factor*(depth+1);
    uint128_t* res_child1_r = res_child1 + mac_factor*(depth+1);
    uint128_t* res2_r = res2 + mac_factor*(depth+1);
    uint128_t* res_child2_r = res_child2 + mac_factor*(depth+1);

    for(int d=1; d<depth; d++){
        // truth
        truth_res[d] -= truth_res_child[d-1];
        truth_res[d] %= modulus;
        truth_res_r[d] -= truth_res_child_r[d-1];
        truth_res_r[d] %= modulus;
        // protocol
        res1[d] -= res_child1[d-1];
        res2[d] -= res_child2[d-1];
        res1[d] %= modulus;
        res2[d] %= modulus;
        res1_r[d] -= res_child1_r[d-1];
        res2_r[d] -= res_child2_r[d-1];
        res1_r[d] %= modulus;
        res2_r[d] %= modulus;
        if (malicious) {
            res1[d + depth] -= res_child1[(d-1) + depth];
            res2[d + depth] -= res_child2[(d-1) + depth];
            res1[d + depth] %= modulus;
            res2[d + depth] %= modulus;
            res1_r[d + depth] -= res_child1_r[(d-1) + depth];
            res2_r[d + depth] -= res_child2_r[(d-1) + depth];
            res1_r[d + depth] %= modulus;
            res2_r[d + depth] %= modulus;
        }
    }
    for(int d=0; d<depth; d++){
        cout << "res1 = " << res1[d] << "; res2 = " << res2[d] << endl;
        res1[d] += res2[d];
        res1[d] %= modulus;
        res1_r[d] += res2_r[d];
        res1_r[d] %= modulus;
        if (malicious) {
            res1[d + depth] += res2[d + depth];
            res1[d + depth] %= modulus;
            res1_r[d + depth] += res2_r[d + depth];
            res1_r[d + depth] %= modulus;
        }
        if(res1[d] != truth_res[d]){
            cout<<RED<<"Result mismatch from ground truth at depth "<<d<<RESET<<": "<<truth_res[d]<<" vs "<<res1[d]<<endl;
        }
        if (malicious) {
            if (((res1[d] * alpha) % modulus) != res1[d + depth]) {
                cout << RED << "MAC check failed at level " << d << RESET << ": result = " << res1[d] << ", alpha = " << alpha << ", MAC = " << res1[d + depth] << endl;
            }
        }
        if(res1_r[d] != truth_res_r[d]){
            cout<<RED<<"Result mismatch from ground truth at depth "<<d<<RESET<<": "<<truth_res_r[d]<<" vs "<<res1_r[d]<<endl;
        }
        if (malicious) {
            if (((res1_r[d] * alpha) % modulus) != res1_r[d + depth]) {
                cout << RED << "MAC check failed at level " << d << RESET << ": result = " << res1_r[d] << ", alpha = " << alpha << ", MAC = " << res1_r[d + depth] << endl;
            }
        }
#ifdef VERBOSE_PRINT
        std::cout<<"Protocol || depth "<<d<<endl;
        std::cout<<(uint64_t)res1[d]<<endl;
#endif
    }
    delete[] truth_res;
    delete[] truth_res_child;
    return true;
}

int main(int argc, char** argv){
    cout<<BLUE<<"Running test on AggTree..."<<RESET<<endl;
   
    int depth = 8;
    cout<<"Enter depth"<<endl;
    cin>>depth;
    //TODO: multithreading is creating issues with agg tree
    //TODO: DCF server eval function is not thread safe
    //TODO: Some state is shared across all threads in that function
    //TODO: which leads to error.
    cout<<"Depth = "<<depth<<endl;
    int ctr = 0;
    uint128_t query_left_x = 1000; // incorrect
    uint128_t query_right_x = 10; 
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = (one<<gout_bitsize);
    uint64_t size = (1ULL << (depth)) - 1;
    uint64_t leaves = (1ULL << ((depth) - 1));
    block seed;
    PRNG prng;
    int cores = 2;

    srand(time(NULL));
    seed = toBlock(rand(), rand());
    prng.SetSeed(seed);

    client* cl = new client();
    server* sv1 = new server(SERVER1);
    server* sv2 = new server(SERVER2);

    cout<<"Generating a random aggregate tree..."<<endl;    
    cl->agg_tree_oracle = new AggTreeIndexClient(mx, to_string(ctr), depth, malicious);
    cout<<"Generating DCF keys for aggregate tree..."<<endl;    
    cl->agg_tree_oracle->gen_agg_tree_keys(query_left_x, query_right_x, depth, gout_bitsize, true, group_mod);
    cout<<"Generated"<<endl;

    vector<uint128_t> aggVals;
    map<uint64_t, uint128_t> aggValMap;
    for (uint64_t i=0; i<leaves; i++){
        aggValMap[i] = (uint128_t)1;
        aggVals.push_back((uint128_t)1);
    }

    vector<uint128_t> childAggVals;
    for (uint64_t i=0; (2*i + 2) < leaves; i++){
        childAggVals.push_back(aggVals[2*i + 1] + aggVals[2*i + 2]);
    }
    for (uint64_t i=0; i<(1ULL << depth); i++){
        childAggVals.push_back(0ULL);
    }
  
    cout << "Setting up server state" << endl;
    sv1->agg_tree_oracle = new AggTreeIndexServer(to_string(ctr), depth, sum, cores, malicious);
    sv2->agg_tree_oracle = new AggTreeIndexServer(to_string(ctr), depth, sum, cores, malicious);
    for (uint64_t i = 0; i < leaves; i++) {
        uint128_t one = 1;
        sv1->agg_tree_oracle->append(i, one);
        sv2->agg_tree_oracle->append(i, one);
    }

    svkey *svk1_l = new svkey();
    svkey *svk2_l = new svkey();
    svkey *svk1_r = new svkey();
    svkey *svk2_r = new svkey();
    copy_keys_to_server(cl->agg_tree_oracle->key[2*ctr], svk1_l, svk2_l);
    copy_keys_to_server(cl->agg_tree_oracle->key[2*ctr + 1], svk1_r, svk2_r);
    cout << "Finished setting up server state" << endl;
    
    sv1->add_keys(AGG_Tree, svk1_l);
    sv2->add_keys(AGG_Tree, svk2_l);
    sv1->add_keys(AGG_Tree, svk1_r);
    sv2->add_keys(AGG_Tree, svk2_r);

/*    uint8_t *key0;
    uint8_t *key1;
    size_t sz;
    cl->agg_tree_oracle->serialize_keys(&key0, &key1, &sz);
    sv1->agg_tree_oracle->deserialize_key(key0, true);
    sv2->agg_tree_oracle->deserialize_key(key1, false);*/

    cout<<"Keys transferred to servers"<<endl;
    
    cout<<"Servers running aggregate tree evaluation..."<<endl;
    uint64_t tree_size = cl->agg_tree_oracle->size;
    int lf_factor = 2;
    uint128_t* res1 = (uint128_t*)malloc(lf_factor*mac_factor*sizeof(uint128_t)*(depth + 1));
    uint128_t* res_child1 = (uint128_t*)malloc(lf_factor*mac_factor*sizeof(uint128_t)*(depth + 1));
    uint128_t* res2 = (uint128_t*)malloc(lf_factor*mac_factor*sizeof(uint128_t)*(depth + 1));
    uint128_t* res_child2 = (uint128_t*)malloc(lf_factor*mac_factor*sizeof(uint128_t)*(depth + 1));
    memset(res1, 0, lf_factor*mac_factor * sizeof(uint128_t) * (depth + 1));
    memset(res_child1, 0, lf_factor*mac_factor * sizeof(uint128_t) * (depth + 1));
    memset(res2, 0, lf_factor*mac_factor * sizeof(uint128_t) * (depth + 1));
    memset(res_child2, 0, lf_factor*mac_factor * sizeof(uint128_t) * (depth + 1));

    INIT_TIMER;
    START_TIMER;
    cout<<"First server evaluation"<<endl;
    sv1->agg_tree_oracle->eval_agg_tree(res1, res_child1, gout_bitsize, true, group_mod, true);
    cout<<"Second server evaluation"<<endl;
    sv2->agg_tree_oracle->eval_agg_tree(res2, res_child2, gout_bitsize, true, group_mod, true);
    STOP_TIMER("Agg tree evaluation time for 1 party");
    cout<<"Aggregate tree evalation done"<<endl;

    cout<<"Testing correctness..."<<endl;
    assert(check_agg_tree_correctness(query_left_x, query_right_x, sv1->agg_tree_oracle->tree, res1, res_child1, res2, res_child2, depth, tree_size, true, group_mod, malicious, cl->agg_tree_oracle->alpha) == true && "Aggregate tree is incorrect!");
    cout<<GREEN<<"Aggregate tree correct!"<<RESET<<endl;
    cout<<"FSS keysize / server = "<<cl->agg_tree_oracle->key[2*ctr]->get_keysize()<<" bytes"<<endl;
    ctr++;

    delete cl;
    delete sv1;
    delete sv2;
    delete[] res1;
    delete[] res_child1;
    delete[] res2;
    delete[] res_child2;

    return 0;
}
