#include "keys.h"
#include <string>
#include <immintrin.h>

#ifndef DCF_TABLE_H__
#define DCF_TABLE_H__

// ceil; 255 (ideally 31 should work?) to make sure that AVX_copy 256 bit chunks doesn't cause a fault
#define PACKED_WIN_SIZE(WIN_SIZE) (WIN_SIZE + 255) / 8

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;
    
    class DCFTableClient{
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
           
            DCFTableClient(string id, int depth, int windowSize, bool malicious = false);
            ~DCFTableClient(); 
            void gen_fresh_MAC_key();
            void gen_dcf_table_keys(uint128_t left_x, uint128_t right_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
            void serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size);
    };

    class DCFTableServer{
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
            int cores = 2;
            
            // to better take the AVX2 support, tables are stored in numBuckets x PACKED_WIN_SIZE(windowSize) format.
            uint128_t** table;
            
            // random gen
            block seed;
            PRNG prng;

            // keys
            std::vector<svkey*> key;
           
            DCFTableServer(string id, int depth, int windowSize, int cores, bool malicious = false);
            DCFTableServer(string id, int depth, int windowSize, uint128_t** table_share, int cores, bool malicious = false);
            ~DCFTableServer(); 
            void eval_dcf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t lt_gt = 0);
            void eval_dcf_table_part_a(uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, int idx, uint8_t lt_gt = 0);
            void eval_dcf_table_part_b(uint128_t* res, uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus);
            void ic_eval_dcf_table(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both, int idx);
            void ic_eval_dcf_table_unopt(uint128_t* res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both, int idx);
            void parallel_ic_eval_dcf_table(uint128_t** res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint8_t both);
            void helper_dcf_table_eval_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end);
            void helper_dcf_table_routine(uint128_t *res, uint128_t *dcf_res, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end);
             void deserialize_key(const uint8_t *key_bytes, bool isFirst);

    };

}
#endif
