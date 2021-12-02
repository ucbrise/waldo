#include "secure-indices/core/AggTree.h"

using namespace std;
using namespace dorydb;

RootNode *fillTree(int maxDepth, AggFunc aggFunc) {
    int numLeaves = 1 << (maxDepth - 1);
    RootNode *root = new RootNode(maxDepth, aggFunc);
    printf("Made root node\n");
    for (uint64_t i = 0; i < numLeaves; i++) {
        uint128_t val = 1;
        printf("appending %d/%d\n", i+1, numLeaves);
        root->append(i+1, val);
    }
    return root;
}

int main(int argc, char **argv) {
    int maxDepth = 8;
    AggFunc aggFunc = sum;
    RootNode *tree = fillTree(maxDepth, aggFunc);
    if (tree->root->aggVal != (1 << (maxDepth - 1))) {
        cout << RED << "ERROR: root has value " << tree->root->aggVal << " not " << (1<<(maxDepth-1)) << RESET << endl;
    } else {
        cout << GREEN << "Root has expected value " << tree->root->aggVal << RESET << endl;
    }

    uint128_t prevAgg = 128;
    for (int i = 0; i < 128; i++) {
        uint128_t val = 1;
        tree->append((1 << (maxDepth-1)) + i + 1, val);
        assert(prevAgg < tree->root->aggVal);
        assert(tree->root->leftChild->aggVal + tree->root->rightChild->aggVal == tree->root->aggVal);
        prevAgg = tree->root->aggVal;
    }

    uint128_t expectedVal = (1 << (maxDepth - 1)) + 128;
    if (tree->root->aggVal != expectedVal) {
        cout << RED << "ERROR: root has value " << tree->root->aggVal << " not " << expectedVal << RESET << endl;
    } else {
        cout << GREEN << "Root has expected value " << tree->root->aggVal << RESET << endl;
    }
    queue<Node *>next;
    next.push(tree->root);
    while (!next.empty()) {
        Node *front = next.front();
        next.pop();
        if (front->rightIdx >= 0 && front->leftIdx >= 0) {
            if (front->depth == maxDepth - 1) assert(front->leftChild == NULL && front->rightChild == NULL);
            cout << "Depth=" << front->depth << "; left " << front->leftIdx << " mid " << front->midIdx << " right " << front->rightIdx << endl;
            if (front->rightIdx - front->leftIdx + 1 == front->aggVal) {
                cout << GREEN << "Node has expected value " << front->aggVal << RESET << endl;
            } else {
                cout << RED << "ERROR: Node has value " << front->aggVal << " not " << front->rightIdx - front->leftIdx + 1 << RESET << endl;
            }
            if (front->leftChild) next.push(front->leftChild);
            if (front->rightChild) next.push(front->rightChild);
        }
        
    }

}
