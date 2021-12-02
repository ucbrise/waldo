#include "keys.h"
#include <string>
#include <map>

#ifndef TREE_H__
#define TREE_H__

void test_fullDomain_DCF_agg_tree();

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;
    
    // list of aggregate functions supported
    enum AggFunc { sum, avg, mx, mn };
    
    uint128_t computeAggregate(uint128_t agg1, uint128_t agg2, AggFunc agg_func);

    class Node {
        public:
            Node(uint64_t idx, uint128_t agg_val, Node *parent, int depth);
            uint128_t getChildAggVals();

            uint128_t aggVal;

            Node *leftChild;
            Node *rightChild;
            Node *parent;
            
            uint64_t leftIdx;
            uint64_t midIdx;
            uint64_t rightIdx;
            
            int depth;
    };

    class RootNode {
        public:
            RootNode(int maxDepth, AggFunc aggFunc);
            RootNode(int maxDepth, AggFunc aggFunc, map<uint64_t, uint128_t> &values);
            ~RootNode();
            void append(uint64_t idx, uint128_t aggVal);
            Node *getAppendParent();
            void appendFromParent(uint64_t idx, uint128_t aggVal, Node *next_free, uint128_t *newAggVals);

            Node *root;
            int maxDepth;
            AggFunc aggFunc;

        private:
            Node *rollup();
            void fillEmptySubtree(Node *base);

    };


}
#endif
