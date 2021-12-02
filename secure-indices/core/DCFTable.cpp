#include "DCFTable.h"
#include "common.h"
#include <string>
#include <vector>

namespace dorydb
{
     using namespace osuCrypto;
     using namespace std;

    DCFTableClient::DCFTableClient(string id, int depth, int windowSize, bool malicious){
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

    DCFTableClient::~DCFTableClient(){
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        key.clear();
    }

    void DCFTableClient::gen_fresh_MAC_key(){
        assert(STAT_SEC <= 124 && "If input comes from Z_2, then MAX s allowed is 124");
        // generate fresh key of STAT_SEC bits
        block alp = prng.get<block>();
        uint128_t one = 1;
        memcpy((uint8_t*)&alpha, (uint8_t*)&alp, sizeof(block));  
        alpha %= (one << STAT_SEC);
    }

    void DCFTableClient::gen_dcf_table_keys(uint128_t left_x, uint128_t right_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        INIT_TIMER;
        START_TIMER;

        clkey* left_k = new clkey();
        clkey* right_k = new clkey();
        uint128_t payload = 1;
        // already includes MAC key in it along with the regular key.
        left_k->dcf_generate(left_x, payload, depth, gout_bitsize, use_modulus, modulus, false, false, this->malicious, this->alpha);
        right_k->dcf_generate(right_x, payload, depth, gout_bitsize, use_modulus, modulus, true, false, this->malicious, this->alpha);
        key.push_back(left_k);
        key.push_back(right_k);
        STOP_TIMER("Gen DCF key");
    }

    void DCFTableClient::serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size) {
        // Placing LT and GT key after one another. GT placed after LT.
        *key0 = (uint8_t *)malloc(key[0]->get_keysize() + key[1]->get_keysize());
        *key1 = (uint8_t *)malloc(key[0]->get_keysize() + key[1]->get_keysize());
        key[0]->dcf_serialize(depth, *key0, *key1);
        key[1]->dcf_serialize(depth, *key0 + key[0]->get_keysize(), *key1 + key[0]->get_keysize());
        *key_size = key[0]->get_keysize() + key[1]->get_keysize();
    }


    DCFTableServer::DCFTableServer(string id, int depth, int windowSize, int cores, bool malicious) {
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

    DCFTableServer::DCFTableServer(string id, int depth, int windowSize, uint128_t** table_share, int cores, bool malicious){
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

    DCFTableServer::~DCFTableServer(){
        for(int i=0; i<this->numBuckets; i++){
            delete[] this->table[i];
        }
        for(int i=0; i<key.size(); i++){
            delete key[i];
        }
        delete[] table;
        key.clear();
    }
    
    void DCFTableServer::helper_dcf_table_eval_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end){
        th_key->dcf_eval_contig(res+start, depth, start, end, gout_bitsize, use_modulus, modulus);
        if(malicious){
            th_key->dcf_eval_contig(res + numBuckets + start, depth, start, end, gout_bitsize, use_modulus, modulus, malicious);
        }
    }
   
    void DCFTableServer::helper_dcf_table_routine(uint128_t *res, uint128_t *dcf_res, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end){
        for(uint64_t i = start; i <= end; i++){
            for (uint64_t j  = 0; j < windowSize; j++) {
                res[j] += (dcf_res[i] * table[i][j]);
                if (malicious) {
                    res[windowSize + j] += (dcf_res[numBuckets + i] * table[i][j]);
                }
            }
        }
    }
    
    void DCFTableServer::eval_dcf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t lt_gt){
        assert((lt_gt & 1) == lt_gt && "lt_gt is indicator of whether the evaluation to be done on left or right side");
        
        // make all DCF array sizes double when malicious
        // first half stores regular vals, later half stores their MACs.
        uint8_t mac_factor = (malicious)? 2 : 1;
        
        memset(res, 0, mac_factor * sizeof(uint128_t) * windowSize);
        uint128_t* dcf_res = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * numBuckets);
        memset(dcf_res, 0, mac_factor * sizeof(uint128_t) * numBuckets);
        uint128_t **th_res = (uint128_t **)malloc(sizeof(uint128_t *) * cores);;
        for (int th = 0; th < cores; th++) {
            th_res[th] = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * windowSize);
            memset(th_res[th], 0, mac_factor * sizeof(uint128_t) * windowSize);
        }
        int threading_minimum = 14; // The minimum depth to start threading for DCF evals part only
        
        // Threaded part
        if(depth >= threading_minimum){
            int chunk_size = numBuckets / cores;
            vector<thread>workers;
            for(int th=0; th<cores; th++){
                if(th == (cores-1)){
                    workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_eval_routine, this, dcf_res, key[lt_gt], gout_bitsize, use_modulus, modulus, th*chunk_size, numBuckets-1));
                }
                else{
                    workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_eval_routine, this, dcf_res, key[lt_gt], gout_bitsize, use_modulus, modulus, th*chunk_size, (th+1)*chunk_size-1));
                }
            }
            for(int th=0; th<cores; th++){
                workers[th].join();
            }
        }
        else{
            // No threading
            key[lt_gt]->dcf_eval_contig(dcf_res, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus);
            if(malicious){
                key[lt_gt]->dcf_eval_contig(dcf_res + numBuckets, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus, malicious);
            }
        }

        //START_TIMER;

        // threaded part        
        vector<thread> workers;
        int chunk_size = numBuckets/cores;
        uint64_t chunk_end = 0;

        for(int th=0; th<cores; th++){
            chunk_end = (th == cores-1)? numBuckets : (th+1)*chunk_size;
            workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_routine, this, th_res[th], dcf_res, use_modulus, modulus, th*chunk_size, chunk_end - 1));
        }
        for (int th=0; th<cores; th++) {
            workers[th].join();
            for (int i = 0; i < windowSize; i++) {
                res[i] += th_res[th][i];
            }
        }
        if(malicious){
            for (int th=0; th<cores; th++) {
                for (int i = 0; i < windowSize; i++) {
                    res[i + windowSize] += th_res[th][i + windowSize];
                }
            }
        }
        
        //STOP_TIMER("Local AND/XOR with table bitmaps");
        delete[] dcf_res;
    }

    void DCFTableServer::eval_dcf_table_part_a(uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, int idx, uint8_t lt_gt){
        assert((lt_gt & 1) == lt_gt && "lt_gt is indicator of whether the evaluation to be done on left or right side");
        
        // make all DCF array sizes double when malicious
        // first half stores regular vals, later half stores their MACs.
        
        int threading_minimum = 14; // The minimum depth to start threading for DCF evals part only
        
        INIT_TIMER;
        START_TIMER;
        // Threaded part
        if(depth >= threading_minimum){
            int chunk_size = numBuckets / cores;
            vector<thread> workers;
            for(int th=0; th<cores; th++){
                if(th == (cores-1)){
                    workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_eval_routine, this, dcf_res, key[lt_gt + 2*idx], gout_bitsize, use_modulus, modulus, th*chunk_size, numBuckets-1));
                }
                else{
                    workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_eval_routine, this, dcf_res, key[lt_gt + 2*idx], gout_bitsize, use_modulus, modulus, th*chunk_size, (th+1)*chunk_size-1));
                }
            }
            for(int th=0; th<cores; th++){
                workers[th].join();
            }
        }
        else{
            // No threading
            key[lt_gt + 2*idx]->dcf_eval_contig(dcf_res, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus);
            if(malicious){
                key[lt_gt + 2*idx]->dcf_eval_contig(dcf_res + numBuckets, depth, 0, numBuckets-1, gout_bitsize, use_modulus, modulus, malicious);
            }
        }

        STOP_TIMER("Just DCF");
    }
    
    void DCFTableServer::eval_dcf_table_part_b(uint128_t* res, uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        // make all DCF array sizes double when malicious
        // first half stores regular vals, later half stores their MACs.
        uint8_t mac_factor = (malicious)? 2 : 1;
        
        memset(res, 0, mac_factor * sizeof(uint128_t) * windowSize);
        uint128_t **th_res = (uint128_t **)malloc(sizeof(uint128_t *) * cores);
        for (int th = 0; th < cores; th++) {
            th_res[th] = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * windowSize);
            memset(th_res[th], 0, mac_factor * sizeof(uint128_t) * windowSize);
        }
        
        INIT_TIMER;
        START_TIMER;
        // threaded part
        vector<thread> workers;
        int chunk_size = numBuckets/cores;
        uint64_t chunk_end = 0;

        for(int th=0; th<cores; th++){
            // this chunk_end calc looks weird?
            chunk_end = (th == cores-1)? numBuckets : (th+1)*chunk_size;
            workers.push_back(std::thread(&dorydb::DCFTableServer::helper_dcf_table_routine, this, th_res[th], dcf_res, use_modulus, modulus, th*chunk_size, chunk_end - 1));
        }
        for (int th=0; th<cores; th++) {
            workers[th].join();
            for (int i = 0; i < windowSize; i++) {
                res[i] += th_res[th][i];
            }
        }
        if(malicious){
            for (int th=0; th<cores; th++) {
                for (int i = 0; i < windowSize; i++) {
                    res[i + windowSize] += th_res[th][i + windowSize];
                }
            }
        }
        
        STOP_TIMER("Local AND/XOR with table bitmaps");
        
        for (int th=0; th<cores; th++){
            delete[] th_res[th];
        }
    }
    
    // optimized IC call where left and right are joined before local mult and add
    void DCFTableServer::ic_eval_dcf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both, int idx){
        if(!both){
            // IC not used; single sided range
            assert(key.size() >= 1);
            eval_dcf_table(res, gout_bitsize, use_modulus, modulus, 0);
        } 
        else{
            // IC used.
            // Assumption: if both is set, then use IC. If unset, use LT by default and not GT.
            assert(key.size() >= 2);
            // make all DCF array sizes double when malicious
            // first half stores regular vals, later half stores their MACs.
            uint8_t mac_factor = (malicious)? 2 : 1;
            uint128_t* dcf_res_l = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * numBuckets);
            uint128_t* dcf_res_r = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * numBuckets);
            memset(dcf_res_l, 0, mac_factor * sizeof(uint128_t) * numBuckets);
            memset(dcf_res_r, 0, mac_factor * sizeof(uint128_t) * numBuckets);
            // No need to do any parallelization in this function. Do either to the caller of this
            // or inside the callee of this
            // left
            eval_dcf_table_part_a(dcf_res_l, gout_bitsize, use_modulus, modulus, idx, 0);
            // right
            eval_dcf_table_part_a(dcf_res_r, gout_bitsize, use_modulus, modulus, idx, 1);
            // combine DCF answers of left and right
            for(int i=0; i<numBuckets; i++){
                dcf_res_l[i] += dcf_res_r[i];
            }
            if(malicious){
                for(int i=0; i<numBuckets; i++){
                    dcf_res_l[i + numBuckets] += dcf_res_r[i + numBuckets];
                }
            }
            // local multiplication and addition part
            eval_dcf_table_part_b(res, dcf_res_l, gout_bitsize, use_modulus, modulus);
            
            delete[] dcf_res_l;
            delete[] dcf_res_r;
        }
    }
    
    void DCFTableServer::ic_eval_dcf_table_unopt(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both, int idx){
        if(!both){
            // IC not used; single sided range
            assert(key.size() >= 1);
            eval_dcf_table(res, gout_bitsize, use_modulus, modulus, 0);
        } 
        else{
            // IC used.
            // Assumption: if both is set, then use IC. If unset, use LT by default and not GT.
            assert(key.size() >= 2);
            // make all DCF array sizes double when malicious
            // first half stores regular vals, later half stores their MACs.
            uint8_t mac_factor = (malicious)? 2 : 1;
            uint128_t* res_r = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * windowSize);
            thread workers[2];
            // left
            workers[0] = thread(&dorydb::DCFTableServer::eval_dcf_table, this, res, gout_bitsize, use_modulus, modulus, 0);
            workers[1] = thread(&dorydb::DCFTableServer::eval_dcf_table, this, res_r, gout_bitsize, use_modulus, modulus, 1);
            //eval_dcf_table(res, gout_bitsize, use_modulus, modulus, 0);
            // right
            //eval_dcf_table(res_r, gout_bitsize, use_modulus, modulus, 1);
            workers[0].join();
            workers[1].join();
            for(int i=0; i<windowSize; i++){
                res[i] += res_r[i];
            }
            if(malicious){
                for(int i=0; i<windowSize; i++){
                    res[i + windowSize] += res_r[i + windowSize];
                }
            }
            delete[] res_r;
        }
    }

    void DCFTableServer::parallel_ic_eval_dcf_table(uint128_t **res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both) {
        int numEvals = key.size() / 2;
        vector<thread> workers;
        INIT_TIMER;
        START_TIMER;
        for (int i = 0; i < numEvals; i++) {
            workers.push_back(thread(&dorydb::DCFTableServer::ic_eval_dcf_table, this, res[i], gout_bitsize, use_modulus, modulus, both, i)); 
        }
        for (int i = 0; i < numEvals; i++) {
            workers[i].join();
        }
        STOP_TIMER("IC eval");
        key.clear();
    }

    void DCFTableServer::deserialize_key(const uint8_t *key_bytes, bool isFirst) {
        svkey *k_l = new svkey();
        svkey *k_r = new svkey();
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
