#include "Tree.h"
#include <string>

namespace dorydb
{
    using namespace osuCrypto;
    using namespace std;

    Node::Node(uint64_t idx, uint128_t aggVal, Node *parent, int depth) {
        this->leftIdx = idx;
        this->midIdx = idx;
        this->rightIdx = idx;
        this->parent = parent;
        this->depth = depth;
        this->aggVal = aggVal;
        this->leftChild = NULL;
        this->rightChild = NULL;
    }

    void RootNode::fillEmptySubtree(Node *base) {
        queue<Node *>next;
        next.push(base);
        while (!next.empty()) {
            Node *front = next.front();
            next.pop();
            if (front->depth == maxDepth - 2) {
                // Don't fill in bottom level of tree
                return;
            }
            Node *left = new Node(-1, -1, front, front->depth + 1);
            Node *right = new Node(-1, -1, front, front->depth + 1);
            front->leftChild = left;
            front->rightChild = right;
            next.push(left);
            next.push(right);
        }
    }

    RootNode::RootNode(int maxDepth, AggFunc aggFunc) {
        this->maxDepth = maxDepth;
        this->aggFunc = aggFunc;
        root = new Node(-1, -1, NULL, 0);
        fillEmptySubtree(root);
    }

    RootNode::RootNode(int maxDepth, AggFunc aggFunc, map<uint64_t, uint128_t> &values) {
        assert(values.size() == 1 << (maxDepth - 1));
        this->maxDepth = maxDepth;
        this->aggFunc = aggFunc;

        queue<Node *> next;
        map<uint64_t, uint128_t>::iterator it;
        for (it = values.begin(); it != values.end(); it++) {
            next.push(new Node(it->first, it->second, NULL, maxDepth - 1));
        }
        while (next.size() >= 2) {
            Node *left = next.front();
            next.pop();
            Node *right = next.front();
            next.pop();
            Node *parent = new Node(left->leftIdx, computeAggregate(left->aggVal, right->aggVal, aggFunc), NULL, left->depth - 1);
            parent->midIdx = right->leftIdx;
            parent->rightIdx = right->rightIdx;
            left->parent = parent;
            right->parent = parent;
            parent->leftChild = left;
            parent->rightChild = right;
            next.push(parent);
        }
        this->root = next.front();
        assert(this->root->depth == 0);
    }

    RootNode::~RootNode() {
        queue<Node *>next;
        next.push(root);
        while (!next.empty()) {
            Node *front = next.front();
            next.pop();
            if (front->leftChild) next.push(front->leftChild);
            if (front->rightChild) next.push(front->rightChild);
            delete front;
        }
    }

    uint128_t Node::getChildAggVals() {
        uint128_t leftVal = 0;
        uint128_t rightVal = 0;
        if (leftChild != NULL) {
            leftVal = leftChild->aggVal;
        }
        if (rightChild != NULL) {
            rightVal = rightChild->aggVal;
        }
        return leftVal + rightVal;
    }

    uint128_t computeAggregate(uint128_t agg1, uint128_t agg2, AggFunc aggFunc) {
        if (agg1 == -1) return agg2;
        if (agg2 == -1) return agg1;
        if (aggFunc == sum) {
            return agg1 + agg2;
        } else if (aggFunc == mx) {
            return max(agg1, agg2);
        } else if (aggFunc == mn) {
            return min(agg1, agg2);
        } else {
            printf("ERROR: unknown aggregate function type %d\n", aggFunc);
            assert(false);
        }
        return -1;
    }

    Node *RootNode::rollup() {
        /* rotate left */
        Node *old_root = root;
        root = root->rightChild;
        root->parent = NULL;
        root->depth = 0;
        Node *tmp = root->leftChild;
        root->leftChild = old_root;
        old_root->rightChild = tmp;
        old_root->rightChild->parent = old_root;
        old_root->rightChild->depth = 2;
        old_root->depth = 1;
        old_root->parent = root;
        old_root->rightIdx = old_root->rightChild->rightIdx;
        old_root->midIdx = old_root->rightChild->leftIdx;
        root->midIdx = min(root->leftChild->rightIdx, root->rightChild->leftIdx);
        root->leftIdx = root->leftChild->leftIdx;
        old_root->aggVal = computeAggregate(old_root->leftChild->aggVal, old_root->rightChild->aggVal, aggFunc);
        root->aggVal = computeAggregate(root->leftChild->aggVal, root->rightChild->aggVal, aggFunc);
        /* put all nodes on right into separate subtree */
        Node *newRightChild = new Node(root->rightIdx, root->rightChild->aggVal, root, 1);
        newRightChild->leftChild = root->rightChild;
        newRightChild->leftChild->parent = newRightChild;
        newRightChild->leftIdx = newRightChild->leftChild->leftIdx;
        newRightChild->midIdx = newRightChild->leftChild->rightIdx;
        newRightChild->rightIdx = newRightChild->midIdx;
        newRightChild->aggVal = newRightChild->leftChild->aggVal;
        root->rightChild = newRightChild;
        newRightChild->parent = root;
        newRightChild->depth = 1;
        newRightChild->leftChild->depth = 2;
        newRightChild->rightChild = new Node(-1, -1, newRightChild, 2);
        /* make new subtree for new nodes */
        fillEmptySubtree(newRightChild->rightChild);
        /* set depth correctly in root->right->left subtree */
        queue<Node *>next;
        next.push(root->rightChild->leftChild);
        while (!next.empty()) {
            Node *front = next.front();
            next.pop();
            front->depth = front->parent->depth + 1;
            if (front->leftChild != NULL) next.push(front->leftChild);
            if (front->rightChild != NULL) next.push(front->rightChild);
        }
        /* delete rolled up nodes */
        next = queue<Node *>();
        next.push(root->leftChild);
        while (!next.empty()) {
            Node *front = next.front();
            next.pop();
            assert (front != newRightChild->rightChild);
            assert (front != newRightChild);
            front->depth = front->parent->depth + 1;
            if (front->depth == maxDepth) {
                if (front->parent->leftChild == front) {
                    front->parent->leftChild = NULL;
                } else {
                    front->parent->rightChild = NULL;
                }
                delete front;
            } else {
                if (front->leftChild != NULL) next.push(front->leftChild);
                if (front->rightChild != NULL) next.push(front->rightChild);
            }
        }
        /* Get next free node and return it */
        assert(newRightChild->rightChild != NULL);
        Node *curr = newRightChild->rightChild;
        while (curr->depth < maxDepth - 2) {
            curr = curr->leftChild;
        }
        assert(curr->leftChild == NULL && curr->rightChild == NULL);
        return curr;
    }

    void RootNode::append(uint64_t idx, uint128_t aggVal) {
        Node *next_free = getAppendParent();

        uint128_t *newAggVals = (uint128_t *)malloc((next_free->depth + 1) * sizeof(uint128_t));
        Node *parent = next_free;
        int ctr = 0;
        while (parent != NULL) {
            newAggVals[ctr] = computeAggregate(parent->aggVal, aggVal, aggFunc);
            parent = parent->parent;
            ctr++;
        }
 
        appendFromParent(idx, aggVal, next_free, newAggVals);
        free(newAggVals);
    }

    Node *RootNode::getAppendParent() {
        /* Look for next free spot */
        Node *parent = root;
        bool full = false;
        while ((parent->rightChild != NULL || parent->leftChild != NULL) && !full && parent->depth < maxDepth - 2) {
            if (parent->leftChild != NULL && parent->midIdx == -1) {
                parent = parent->leftChild;
            } else if (parent->rightChild != NULL && parent->rightIdx == -1) {
                parent = parent->rightChild;
            } else {
                full = true;
                break;
            }
        }
        
        Node *next_free = parent;

        /* No space, do roll up. */
        if (full) {
            next_free = rollup();
            // TODO: implement rollup
        }
        assert(next_free->depth == maxDepth - 2);
        return next_free;
    }

    void RootNode::appendFromParent(uint64_t idx, uint128_t aggVal, Node *next_free, uint128_t *newAggVals) {

        Node *curr = new Node(idx, aggVal, next_free, maxDepth - 1);
        /* Fill from left first. */
        if (next_free->leftChild == NULL) {
            next_free->leftChild = curr;
        } else if (next_free->rightChild == NULL) {
            next_free->rightChild = curr;
        } else {
            assert (false);
        }

        /* Update parent nodes. */
        Node *parent = next_free;
        Node *child = curr;
        int ctr = 0;
        while (parent != NULL) {
            if (parent->leftChild == child) {
                parent->leftIdx = parent->leftIdx == -1 ? child->leftIdx : min(parent->leftIdx, child->leftIdx);
                if (child->rightChild != NULL && child->rightChild->rightIdx != -1) {
                    parent->midIdx = parent->midIdx == -1 ? child->rightIdx + 1 : max(parent->midIdx, child->rightIdx + 1);
                }
            } else if (parent->rightChild == child) {
                parent->midIdx = parent->midIdx == -1 ? child->leftIdx : min(parent->midIdx, child->leftIdx);
                parent->rightIdx = parent->rightIdx == -1 ? child->rightIdx : max(parent->rightIdx, child->rightIdx);
            }
            parent->aggVal = newAggVals[ctr];
            assert(parent->parent != parent);
            parent = parent->parent;
            child = child->parent;
            ctr++;
        }
        assert(child == root);
        assert(ctr == maxDepth - 1);
    }

}
