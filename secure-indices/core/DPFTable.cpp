#include "DPFTable.h"
#include "common.h"
#include <string>

namespace dorydb
{
     using namespace osuCrypto;
     using namespace std;

    DPFTableClient::DPFTableClient(string id, int depth, int windowSize, bool malicious){
        assert(depth >= 0 && windowSize >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->id = id;
        this->depth = depth;
        this->windowSize = windowSize;
        this->numBuckets = (1ULL << depth); 
        this->malicious = malicious;
        if(malicious) gen_fresh_MAC_key();
    }

    DPFTableClient::~DPFTableClient(){
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        key.clear();
    }

    void DPFTableClient::gen_fresh_MAC_key(){
        assert(STAT_SEC <= 124 && "If input comes from Z_2, then MAX s allowed is 124");
        // generate fresh key of STAT_SEC bits
        block alp = prng.get<block>();
        uint128_t one = 1;
        memcpy((uint8_t*)&alpha, (uint8_t*)&alp, sizeof(block));  
        alpha %= (one << STAT_SEC);
    }

    void DPFTableClient::gen_dpf_table_keys(uint128_t x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        INIT_TIMER;
        START_TIMER;
        clkey* k = new clkey();
        uint128_t payload = 1;
        // already includes MAC key in it along with the regular key.
        k->dpf_generate(x, payload, depth, gout_bitsize, use_modulus, modulus, this->malicious, this->alpha);
        key.push_back(k);
        STOP_TIMER("gen dpf key");
    }

    void DPFTableClient::serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size) {
        *key0 = (uint8_t *)malloc(key[0]->get_keysize());
        *key1 = (uint8_t *)malloc(key[0]->get_keysize());
        key[0]->dpf_serialize(depth, *key0, *key1);
        *key_size = key[0]->get_keysize();
    }
   
    DPFTableServer::DPFTableServer(string id, int depth, int windowSize, int cores, bool malicious) {
        assert(depth >= 0 && windowSize >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->id = id;
        this->depth = depth;
        this->windowSize = windowSize;
        this->numBuckets = (1ULL << depth); 
        this->malicious = malicious;
        this->cores = cores;
        this->table = (uint128_t**)malloc(sizeof(uint128_t*)*this->numBuckets);
        // fill
        for(uint64_t i=0; i<this->numBuckets; i++){
            this->table[i] = (uint128_t*)malloc(sizeof(uint128_t)*this->windowSize);
            memset(this->table[i], 0, sizeof(uint128_t) * this->windowSize);
        }
    }

    DPFTableServer::DPFTableServer(string id, int depth, int windowSize, uint128_t** table_share, int cores, bool malicious){
        assert(depth >= 0 && windowSize >= 0);
        // seed
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        // set
        this->id = id;
        this->depth = depth;
        this->windowSize = windowSize;
        this->numBuckets = (1ULL << depth); 
        this->malicious = malicious;
        this->cores = cores;
        this->table = (uint128_t**)malloc(sizeof(uint128_t*)*this->numBuckets);
        // fill
        for(uint64_t i=0; i<this->numBuckets; i++){
            this->table[i] = (uint128_t*)malloc(sizeof(uint128_t)*this->windowSize);
            memcpy(this->table[i], table_share[i], sizeof(uint128_t)*this->windowSize);
        }
    }

    DPFTableServer::~DPFTableServer(){
        for(int i=0; i<this->numBuckets; i++){
            delete[] this->table[i];
        }
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        delete[] table;
        key.clear();
    }

    void DPFTableServer::helper_dpf_table_eval_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end){
        th_key->dpf_eval_contig(res+start, depth, start, end, gout_bitsize, use_modulus, modulus);
        if(malicious){
            th_key->dpf_eval_contig(res + numBuckets + start, depth, start, end, gout_bitsize, use_modulus, modulus, malicious);
        }
    }
   
    void DPFTableServer::helper_dpf_table_routine(uint128_t *res, uint128_t *dpf_res, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end) {
        for (uint64_t i = start; i <= end; i++) {
            for (uint64_t j = 0; j < windowSize; j++) {
                res[j] += dpf_res[i] * table[i][j];
                if(malicious){
                    res[windowSize + j] += dpf_res[numBuckets + i] * table[i][j];
                }
            }
        }
    }

    void DPFTableServer::eval_dpf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, int idx){
        // make all DCF array sizes double when malicious
        // first half stores regular vals, later half stores their MACs.
        uint8_t mac_factor = (malicious)? 2 : 1;
        
        memset(res, 0, mac_factor * sizeof(uint128_t) * windowSize);
        uint128_t* dpf_res = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * numBuckets);
        memset(dpf_res, 0, mac_factor * sizeof(uint128_t) * numBuckets);
        uint128_t **th_res = (uint128_t **)malloc(sizeof(uint128_t *) * cores);
        for (int i = 0; i < cores; i++) {
            th_res[i] = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * windowSize);
            memset(th_res[i], 0, mac_factor * sizeof(uint128_t) * windowSize);
        }
        int threading_minimum = 14; // The minimum depth to start threading for DPF evals part only

        //INIT_TIMER;
        //START_TIMER;
        // Threaded part
        if(depth >= threading_minimum){
            int chunk_size = numBuckets / cores;
            vector<thread> workers;
            for(int th=0; th<cores; th++){
                if(th == (cores-1)){
                    workers.push_back(std::thread(&dorydb::DPFTableServer::helper_dpf_table_eval_routine, this, dpf_res, key[idx], gout_bitsize, use_modulus, modulus, th*chunk_size, numBuckets-1));
                }
                else{
                    workers.push_back(std::thread(&dorydb::DPFTableServer::helper_dpf_table_eval_routine, this, dpf_res, key[idx], gout_bitsize, use_modulus, modulus, th*chunk_size, (th+1)*chunk_size-1));
                }
            }
            for(int th=0; th<cores; th++){
                workers[th].join();
            }
        }
        else{
            // No threading
            key[idx]->dpf_eval_contig(dpf_res, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus);
            if(malicious){
                key[idx]->dpf_eval_contig(dpf_res + numBuckets, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus, malicious);
            }
        }

        //STOP_TIMER("Just DPF");
        //START_TIMER;

        // threaded part        
        vector<thread> workers;
        int chunk_size = numBuckets/cores;
        uint64_t chunk_end = 0;

        for(int th=0; th<cores; th++){
            chunk_end = (th == cores-1)? numBuckets : (th+1)*chunk_size;
            workers.push_back(std::thread(&dorydb::DPFTableServer::helper_dpf_table_routine, this, th_res[th], dpf_res, use_modulus, modulus, th*chunk_size, chunk_end - 1));
        }
        
        for(int th=0; th<cores; th++){
            workers[th].join();
            for (int i = 0; i < windowSize; i++) {
                res[i] += th_res[th][i];
            }
        }
        if(malicious){
            for(int th=0; th<cores; th++){
                for (int i = 0; i < windowSize; i++) {
                    res[i + windowSize] += th_res[th][i + windowSize];
                }
            }
        }
        
        //STOP_TIMER("Local AND/XOR with table bitmaps");
        delete[] dpf_res;
        for (int i = 0; i < cores; i++) {
            delete[] th_res[i];
        }
    }
    
    void DPFTableServer::parallel_eval_dpf_table(uint128_t **res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        int numEvals = key.size();
        vector<thread> workers;
        for (int i = 0; i < numEvals; i++) {
            workers.push_back(thread(&dorydb::DPFTableServer::eval_dpf_table, this, res[i], gout_bitsize, use_modulus, modulus, i));
        }
        for (int i = 0; i < numEvals; i++) {
            workers[i].join();
        }
        key.clear();
    }

    void DPFTableServer::deserialize_key(const uint8_t *key_bytes, bool isFirst) {
        svkey *k = new svkey();
        k->malicious = malicious;
        k->dpf_size = depth + 1;
        k->dpf_deserialize(depth, key_bytes);
        if (isFirst) {
            k->role = EVAL0;
        } else {
            k->role = EVAL1;
        }
        k->init = true;
        key.push_back(k);
    }

}
