#include "AggTree.h"
#include "Tree.h"
#include <string>

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;

    // randomly fills up the tree
    AggTreeIndexClient::AggTreeIndexClient(AggFunc type, string id, int depth, bool malicious){
        assert(depth >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->type = type;
        this->id = id;
        this->depth = depth;
        this->size = (1ULL << (depth+1)) - 1;
        this->malicious = malicious;
        if (malicious) gen_fresh_MAC_key();
    }

    AggTreeIndexClient::~AggTreeIndexClient(){
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        key.clear();
    }

    void AggTreeIndexClient::gen_fresh_MAC_key() {
        assert(STAT_SEC <= 124 && "If input comes from Z_2, then MAX s allowed is 124");
        // generate fresh key of STAT_SEC bits
        block alp = prng.get<block>();
        uint128_t one = 1;
        memcpy((uint8_t*)&alpha, (uint8_t*)&alp, sizeof(block));
        alpha %= (one << STAT_SEC);
    }

    // TODO: take into account number of values in tree, not just depth, when
    // choosing range
    void AggTreeIndexClient::gen_agg_tree_keys(uint128_t left_x, uint128_t right_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        clkey* left_k = new clkey();
        clkey* right_k = new clkey();
        uint128_t payload = 1;
        left_k->dcf_generate(left_x, payload, depth, gout_bitsize, use_modulus, modulus, false, false, this->malicious, this->alpha);
        right_k->dcf_generate(right_x, payload, depth, gout_bitsize, use_modulus, modulus, false, true, this->malicious, this->alpha);
        key.clear();
        key.push_back(left_k);
        key.push_back(right_k);
    }

    void AggTreeIndexClient::propagateNewVal(uint128_t val, uint128_t *parents, uint128_t *newAggVals, int newAggLen) {
        newAggVals[0] = val;
        for (int i = 1; i < newAggLen; i++) {
            newAggVals[i] = computeAggregate(parents[i-1], val, type);
        }
    }

    void AggTreeIndexClient::serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size) {
        // Placing LT and GT key after one another. GT placed after LT.
        *key0 = (uint8_t *)malloc((key[0]->get_keysize() + key[1]->get_keysize()));
        *key1 = (uint8_t *)malloc((key[0]->get_keysize() + key[1]->get_keysize()));
        key[0]->dcf_serialize(depth, *key0, *key1);
        key[1]->dcf_serialize(depth, *key0 + key[0]->get_keysize(), *key1 + key[0]->get_keysize());
        *key_size = key[0]->get_keysize() + key[1]->get_keysize();
    }


    AggTreeIndexServer::AggTreeIndexServer(string id, int depth, AggFunc aggFunc, int cores, bool malicious) {
        assert(depth >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->type = type;
        this->id = id;
        this->depth = depth;
        this->size = (1ULL << (depth+1)) - 1;
        this->malicious = malicious;
        this->cores = cores;

        this->tree = new RootNode(depth, aggFunc);
        this->next_free = NULL;
    } 
    
    AggTreeIndexServer::AggTreeIndexServer(string id, int depth, AggFunc aggFunc, map<uint64_t, uint128_t> &aggVals, int cores, bool malicious) {
        assert(depth >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->type = type;
        this->id = id;
        this->depth = depth;
        this->size = (1ULL << (depth+1)) - 1;
        this->malicious = malicious;
        this->cores = cores;

        this->tree = new RootNode(depth, aggFunc, aggVals);
        this->next_free = NULL;
    }

    AggTreeIndexServer::~AggTreeIndexServer(){
        delete tree;
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        key.clear();
    }

    void AggTreeIndexServer::append(uint64_t idx, uint128_t val) {
        tree->append(idx, val);
    }

    // Must call finishAppend before calling getAppendPath again
    uint128_t *AggTreeIndexServer::getAppendPath(int *len) {
        assert(next_free == NULL);
        next_free = tree->getAppendParent();
        assert (next_free != NULL);
        *len = next_free->depth + 1;
        uint128_t *parents = (uint128_t *)malloc((next_free->depth + 1) * sizeof(uint128_t));
        Node *curr = next_free;
        int idx = 0;
        while (curr != NULL) {
            parents[idx] = curr->aggVal;
            curr = curr->parent;
            idx++;
        }
        return parents;
    }

    // Only call after getAppendPath
    void AggTreeIndexServer::finishAppend(uint32_t idx, uint128_t *newAggVals) {
        assert(next_free != NULL);
        tree->appendFromParent(idx, newAggVals[0], next_free, newAggVals + 1);
        next_free = NULL;
    }

    void AggTreeIndexServer::helper_agg_tree_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end){
        th_key->dcf_eval_contig(res+start, depth, start, end, gout_bitsize, use_modulus, modulus);
        if (malicious) {
            th_key->dcf_eval_contig(res + size + start, depth, start, end, gout_bitsize, use_modulus, modulus, malicious);
        }
    }
   
    void AggTreeIndexServer::helper_agg_tree_mult_routine(uint128_t* res, uint128_t* child_res, uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t th_id, int start_depth){
        int currDepth = -1;
        int levelIdx = 0;
        Node *start = tree->root;
        queue<Node *> nodes;
        queue<Node *> next;
        int numFound = 0;
        int numChunkNodes = (1 << (start_depth)) / cores;
        int numSkipped = 0;
        nodes.push(start);
        while (!nodes.empty() && numFound < numChunkNodes) {
            Node *front = nodes.front();
            nodes.pop();
            if (front->leftChild) nodes.push(front->leftChild);
            if (front->rightChild) nodes.push(front->rightChild);
            if (front->depth == start_depth) {
                if (numSkipped == (th_id * numChunkNodes)) {
                    next.push(front);
                    numFound++;
                } else {
                    numSkipped++;
                }

            }
        }

        /* Traverse subtree from starting points. */
        while (!next.empty()) {
            Node *front = next.front();
            next.pop();
            assert (front != NULL);
            int level_start = (1<<(front->depth)) - 1;    // need -1?
            if (currDepth != front->depth) {
                levelIdx = th_id * (1 << (front->depth)) / cores;
            }
            child_res[front->depth - start_depth] += dcf_res[level_start + levelIdx] * front->getChildAggVals();
            res[front->depth - start_depth] += dcf_res[level_start + levelIdx] * front->aggVal;
            if (malicious) {
                child_res[front->depth - start_depth + (depth - start_depth)] += dcf_res[level_start + levelIdx + size] * front->getChildAggVals();
                res[front->depth - start_depth + (depth - start_depth)] += dcf_res[level_start + levelIdx + size] * front->aggVal;
            }
            levelIdx++;
            currDepth = front->depth;
            if (front->leftChild) next.push(front->leftChild);
            if (front->rightChild) next.push(front->rightChild);
        }
    }
   
    void AggTreeIndexServer::eval_agg_tree(uint128_t* res, uint128_t* child_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool both){
        uint64_t idx = 0;
        int threading_minimum = 14; // The minimum depth to start threading
        uint64_t leaves = (1ULL << (depth - 1));
        uint8_t mac_factor = malicious ? 2 : 1;
        uint8_t lr_factor = both ? 2 : 1;
        uint128_t* dcf_res = (uint128_t*)malloc(mac_factor * lr_factor * sizeof(uint128_t)*size);
        uint128_t* dcf_res_r;
        uint128_t* res_r;
        uint128_t* child_res_r;
        memset(dcf_res, 0, mac_factor*lr_factor*sizeof(uint128_t)*size);
        INIT_TIMER;
        START_TIMER;
        // internal nodes = leaves - 1;
        
        // Threaded part
        // Evaluate all leaves
        if(depth > threading_minimum){
            int chunk_size = leaves / cores;
            vector<thread> workers;
            for(int th=0; th<cores; th++){
                if(th == (cores-1)){
                    workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_routine, this, dcf_res+(leaves-1), key[0], gout_bitsize, use_modulus, modulus, th*chunk_size, leaves-1));
                }
                else{
                    workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_routine, this, dcf_res+(leaves-1), key[0], gout_bitsize, use_modulus, modulus, th*chunk_size, (th+1)*chunk_size-1));
                }
            }
            for(int th=0; th<cores; th++){
                workers[th].join();
            }
        }
        else{
            // No threading
            key[0]->dcf_eval_contig(dcf_res+leaves-1, depth, 0, leaves-1, gout_bitsize, use_modulus, modulus);
            if (malicious) {
                key[0]->dcf_eval_contig(dcf_res+leaves-1+size, depth, 0, leaves-1, gout_bitsize, use_modulus, modulus, malicious);
            }
 
        }

        if(both){
            //dcf_res_r = dcf_res;
            dcf_res_r = dcf_res + (mac_factor*size);
            res_r = res + (mac_factor*(depth+1)); 
            child_res_r = child_res + (mac_factor*(depth+1)); 

            if(depth > threading_minimum){
                int chunk_size = leaves / cores;
                vector<thread> workers;
                for(int th=0; th<cores; th++){
                    if(th == (cores-1)){
                        workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_routine, this, dcf_res_r+(leaves-1), key[1], gout_bitsize, use_modulus, modulus, th*chunk_size, leaves-1));
                    }
                    else{
                        workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_routine, this, dcf_res_r+(leaves-1), key[1], gout_bitsize, use_modulus, modulus, th*chunk_size, (th+1)*chunk_size-1));
                    }
                }
                for(int th=0; th<cores; th++){
                    workers[th].join();
                }
            }
            else{
                // No threading
                key[1]->dcf_eval_contig(dcf_res_r+leaves-1, depth, 0, leaves-1, gout_bitsize, use_modulus, modulus);
                if (malicious) {
                    key[1]->dcf_eval_contig(dcf_res_r+leaves-1+size, depth, 0, leaves-1, gout_bitsize, use_modulus, modulus, malicious);
                }
     
            }

        } 

        STOP_TIMER("Just leaf DCF eval");
        START_TIMER;
        int mn = (depth >= threading_minimum)? threading_minimum : depth;
        int level_start;
        // Fill up internal nodes by projecting to leaf
        // Serial part
        // TODO: base projection on left_x and right_x values in tree to account for rollup
        for(int d = 0; d < depth - 1; d++){
            level_start = (1<<d) - 1;
            for(int i=0; i<(1<<d); i++){
                idx = i;
                // append 0s/1s to the idx
                idx <<= ((depth-1) - d);
                idx += (1ULL << ((depth-1) - d)) - 1ULL;
                dcf_res[level_start+i] = dcf_res[(leaves - 1) + idx];
                if (malicious) {
                    dcf_res[level_start+i+size] = dcf_res[(leaves - 1) + idx + size];
                }
            }
        }
        // separate to prevent abrupt accesses
        if(both){
            for(int d = 0; d < depth - 1; d++){
                level_start = (1<<d) - 1;
                for(int i=0; i<(1<<d); i++){
                    idx = i;
                    // append 0s/1s to the idx
                    idx <<= ((depth-1) - d);
                    idx += (1ULL << ((depth-1) - d)) - 1ULL;
                    dcf_res_r[level_start+i] = dcf_res_r[(leaves - 1) + idx];
                    if (malicious) {
                        dcf_res_r[level_start+i+size] = dcf_res_r[(leaves - 1) + idx + size];
                    }
                }
            }
        }

        STOP_TIMER("Filling internal nodes");
        START_TIMER;
        // Local mults and adds using DCF result
        // serial part
        queue<Node *>next;
        int traversalIdx = 0;
        next.push(tree->root);
        assert(tree->root != NULL);
        while (!next.empty() && next.front()->depth < mn) {
            Node *front = next.front();
            next.pop();
            child_res[front->depth] += dcf_res[traversalIdx] * front->getChildAggVals();
            res[front->depth] += dcf_res[traversalIdx] * front->aggVal;
            if (malicious) {
                child_res[front->depth + depth] += dcf_res[traversalIdx + size] * front->getChildAggVals();
                res[front->depth + depth] += dcf_res[traversalIdx + size] * front->aggVal;
            }

            if(both){
                child_res_r[front->depth] += dcf_res_r[traversalIdx] * front->getChildAggVals();
                res_r[front->depth] += dcf_res_r[traversalIdx] * front->aggVal;
                if (malicious) {
                    child_res_r[front->depth + depth] += dcf_res_r[traversalIdx + size] * front->getChildAggVals();
                    res_r[front->depth + depth] += dcf_res_r[traversalIdx + size] * front->aggVal;
                }
            }

            if (front->leftChild && front->leftChild->aggVal != -1) next.push(front->leftChild);
            if (front->rightChild && front->rightChild->aggVal != -1) next.push(front->rightChild);
            traversalIdx++;

        }
        // multithreaded part
        if(mn <= depth){
            printf("multithreaded projection\n");
            uint128_t** res_th = (uint128_t**)malloc(sizeof(uint128_t*)*cores);
            uint128_t** child_res_th = (uint128_t**)malloc(sizeof(uint128_t*)*cores);
            for(int th=0; th<cores; th++){
                res_th[th] = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * (depth-mn));
                child_res_th[th] = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * (depth-mn));
                memset(res_th[th], 0, mac_factor * (depth-mn) * sizeof(uint128_t));
                memset(child_res_th[th], 0, mac_factor * (depth-mn) * sizeof(uint128_t));
            }

            vector<thread> workers;
            for(int th=0; th<cores; th++){
                workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_mult_routine, this, res_th[th], child_res_th[th], dcf_res, gout_bitsize, use_modulus, modulus, th, mn));
            }
            for(int th=0; th<cores; th++){
                workers[th].join();
            }
            for(int d=mn; d<depth; d++){
                child_res[d] = 0ULL;
                res[d] = 0ULL;
                if (malicious) {
                    child_res[d + depth] = 0ULL;
                    res[d + depth] = 0ULL;
                }
                for(int th=0; th<cores; th++){
                    child_res[d] += child_res_th[th][d-mn];    
                    res[d] += res_th[th][d-mn];
                    if (malicious) {
                        child_res[d + depth] += child_res_th[th][d - mn + (depth - mn)];
                        res[d + depth] += res_th[th][d - mn + (depth - mn)];
                    } 
                }
            }
            for(int th=0; th<cores; th++){
                free(child_res_th[th]);
                free(res_th[th]);
            }
            free(child_res_th);
            free(res_th);
        }
        if(both){
            if(mn <= depth){
                uint128_t** res_th = (uint128_t**)malloc(sizeof(uint128_t*)*cores);
                uint128_t** child_res_th = (uint128_t**)malloc(sizeof(uint128_t*)*cores);
                for(int th=0; th<cores; th++){
                    res_th[th] = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * (depth-mn));
                    child_res_th[th] = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * (depth-mn));
                    memset(res_th[th], 0, mac_factor * (depth-mn) * sizeof(uint128_t));
                    memset(child_res_th[th], 0, mac_factor * (depth-mn) * sizeof(uint128_t));
                }

                vector<thread> workers;
                for(int th=0; th<cores; th++){
                    workers.push_back(std::thread(&dorydb::AggTreeIndexServer::helper_agg_tree_mult_routine, this, res_th[th], child_res_th[th], dcf_res_r, gout_bitsize, use_modulus, modulus, th, mn));
                }
                for(int th=0; th<cores; th++){
                    workers[th].join();
                }
                for(int d=mn; d<depth; d++){
                    child_res_r[d] = 0ULL;
                    res_r[d] = 0ULL;
                    if (malicious) {
                        child_res_r[d + depth] = 0ULL;
                        res_r[d + depth] = 0ULL;
                    }
                    for(int th=0; th<cores; th++){
                        child_res_r[d] += child_res_th[th][d-mn];    
                        res_r[d] += res_th[th][d-mn];
                        if (malicious) {
                            child_res_r[d + depth] += child_res_th[th][d - mn + (depth - mn)];
                            res_r[d + depth] += res_th[th][d - mn + (depth - mn)];
                        } 
                    }
                }
                for(int th=0; th<cores; th++){
                    free(child_res_th[th]);
                    free(res_th[th]);
                }
                free(child_res_th);
                free(res_th);
            }
        }

        STOP_TIMER("Local mult and add");
        free(dcf_res);
    
    }

    void AggTreeIndexServer::deserialize_key(const uint8_t *key_bytes, bool isFirst) {
        svkey *k_l = new svkey();
        svkey *k_r = new svkey();
        key.clear();
        // left key
        k_l->malicious = malicious;
        k_l->dcf_size = depth + 1;
        k_l->dcf_deserialize(depth, key_bytes);
        if (isFirst) {
            k_l->role = EVAL0;
        } else {
            k_l->role = EVAL1;
        }
        k_l->init = true;
        key.push_back(k_l);
        // right key
        k_r->malicious = malicious;
        k_r->dcf_size = depth + 1;
        k_r->dcf_deserialize(depth, key_bytes + k_l->get_keysize());
        if (isFirst) {
            k_r->role = EVAL0;
        } else {
            k_r->role = EVAL1;
        }
        k_r->init = true;
        key.push_back(k_r);
    }

}
