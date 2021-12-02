#include "keys.h"
#include "DCFTable.h"
#ifndef DPF_TABLE_H__
#define DPF_TABLE_H__

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;
    
    class DPFTableClient
    {
    public:
            string id;
            // depth denotes the log of the max value that a field can take, i.e. log(N)
            int depth = 0;
            // numBuckets = 1<<depth;
            uint64_t numBuckets = 0;
            // windowSize denotes the current number of records
            uint64_t windowSize = 0;
           
            // toggle malicious 
            bool malicious = false;

            // random gen
            block seed;
            PRNG prng;
            
            // keys
            std::vector<clkey*> key;
            // MAC key
            uint128_t alpha = 0; 

            DPFTableClient(string id, int depth, int windowSize, bool malicious = false);
            ~DPFTableClient(); 
            void gen_fresh_MAC_key();
            void gen_dpf_table_keys(uint128_t x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
            void serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size);
    };

    class DPFTableServer
    {
    public:
            string id;
            // depth denotes the log of the max value that a field can take, i.e. log(N)
            int depth = 0;
            // N = 1<<depth;
            uint64_t numBuckets = 0;
            // windowSize denotes the current number of records
            uint64_t windowSize = 0;
            
            // toggle malicious 
            bool malicious = false;

            int cores;
            
            // to better take the AVX2 support, tables are stored in numBuckets x PACKED_WIN_SIZE(windowSize) format.
            uint128_t** table;
            
            // random gen
            block seed;
            PRNG prng;

            // keys
            std::vector<svkey*> key;
           
            DPFTableServer(string id, int depth, int windowSize, int cores, bool malicious = false);
            DPFTableServer(string id, int depth, int windowSize, uint128_t** table_share, int cores, bool malicious = false);
            ~DPFTableServer(); 
            void eval_dpf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, int idx);
            void parallel_eval_dpf_table(uint128_t **res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus);
            void helper_dpf_table_eval_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end);
            void helper_dpf_table_routine(uint128_t *res, uint128_t *dpf_res, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end);
             void deserialize_key(const uint8_t *key_bytes, bool isFirst);
    };
}
#endif
