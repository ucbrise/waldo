#include "keys.h"
#include "Tree.h"
#include <string>
#include <vector>

#ifndef AGG_TREE_H__
#define AGG_TREE_H__

void test_fullDomain_DCF_agg_tree();

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;
    
    class AggTreeIndexClient{
        public:
            AggFunc type;
            string id;
            int depth = 0;
            // size is 2^{depth+1} - 1.
            uint64_t size = 0;
            bool malicious = false;
            uint128_t alpha = 0;
            
            // random gen
            block seed;
            PRNG prng;
            
            // keys
            std::vector<clkey*> key;
           
            AggTreeIndexClient(AggFunc type, string id, int depth, bool malicious = false);
            ~AggTreeIndexClient();
            void gen_fresh_MAC_key(); 
            void gen_agg_tree_keys(uint128_t left_x, uint128_t right_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
            void propagateNewVal(uint128_t val, uint128_t *parents, uint128_t *newAggVals, int newAggLen);
            void serialize_keys(uint8_t **key0, uint8_t **key1, size_t *key_size);
    };

    class AggTreeIndexServer{
        public:
            AggFunc type;
            string id;
            int depth = 0;
            // size is 2^{depth+1} - 1.
            uint64_t size = 0;
            RootNode *tree;
            bool malicious;
            int cores;

            Node *next_free;

            // random gen
            block seed;
            PRNG prng;

            // keys
            std::vector<svkey*> key;
           
            AggTreeIndexServer(string id, int depth, AggFunc aggFunc, int cores, bool malicious = false);
            AggTreeIndexServer(string id, int depth, AggFunc aggFunc, map<uint64_t, uint128_t> &aggVals, int cores, bool malicious = false);
            ~AggTreeIndexServer();

            void append(uint64_t idx, uint128_t val);
            uint128_t *getAppendPath(int *len);
            void finishAppend(uint32_t idx, uint128_t *newAggVals);

            void eval_agg_tree(uint128_t* res, uint128_t* child_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool both);
            void helper_agg_tree_routine(uint128_t* res, svkey* th_key, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t start, uint64_t end);
            void helper_agg_tree_fill_routine(uint128_t* dcf_res, uint64_t th_id, int cur_depth);
            void helper_agg_tree_mult_routine(uint128_t* res, uint128_t* child_res, uint128_t* dcf_res, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t th_id, int cur_depth);

            void deserialize_key(const uint8_t *key_bytes, bool isFirst);

    };

}
#endif
