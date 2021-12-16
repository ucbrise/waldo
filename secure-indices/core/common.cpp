#include <math.h>
#include <string.h>
#include "fss-core/libPSI/libPSI/PIR/BgiPirClient.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>
#include "common.h"

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

using namespace std;
using namespace osuCrypto;

int getDepth(int x) {
    return ceil(log2(x));
}

/* Check if bit == 1. */
bool isBitOne(const uint8_t *buf, int bitIndex) {
    int byteIndex = bitIndex / 8;
    return buf[byteIndex] & (1 << (bitIndex % 8));
}

/* Set bit in buf to 1. */
void setBitOne(uint8_t *buf, int bitIndex) {
    int byteIndex = bitIndex / 8;
    buf[byteIndex] |= 1 << (bitIndex % 8); 
}

/* Copy bit from dst to src. */
void copyBit(uint8_t *dst, int dstBitIndex, uint8_t *src, int srcBitIndex) {
    uint8_t srcBit = src[srcBitIndex / 8] & (1 << (srcBitIndex % 8));
    srcBit = srcBit >> (srcBitIndex % 8); 
    dst[dstBitIndex / 8] |= srcBit << (dstBitIndex % 8); 
}

/* XOR in into out. */
void xorIn(uint8_t *out, const uint8_t *in, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = out[i] ^ in[i];
    }   
}

/* Set a column in the table. */
void setTableColumn(uint128_t **table, int column, const uint128_t *in, int len) {
    for (int i = 0; i < len; i++) {
        table[i][column] = in[i];
    }
}

void splitIntoBinaryShares(PRNG *prng, uint8_t *in_data, int len, uint8_t *out_data[]) {
    for (int i = 0; i < len; i++) {
       out_data[0][i] = prng->get<uint8_t>();
       out_data[1][i] = prng->get<uint8_t>();
       out_data[2][i] = out_data[0][i] ^ out_data[1][i] ^ in_data[i];
    }
}

uint128_t *createIndicatorVector(int idx, int bit_len) {
    uint128_t *ret;
    ret = (uint128_t *)malloc(sizeof(uint128_t) * bit_len);
    memset(ret, 0, sizeof(uint128_t) * bit_len);
    ret[idx] = 1;
    return ret;
}


void combineArithmeticShares(uint128_t *vals, int len, uint128_t *valShares[], int dim, bool ignoreNegOne) {
    for (int i = 0; i < len; i++) {
        vals[i] = 0;
        if (ignoreNegOne && valShares[0][i] == -1) {
            vals[i] = -1;
            assert(valShares[1][i] == -1);
        } else {
            for (int j = 0; j < dim; j++) {
                vals[i] += valShares[j][i];
            }
        }
    }
}

uint128_t combineSingleArithmeticShares(uint128_t valShares[], int dim, bool ignoreNegOne) {
    uint128_t val = 0;
    if (ignoreNegOne && valShares[0] == -1) {
        return -1;
    }
    for (int i = 0; i < dim; i++) {
        val += valShares[i];
    }    
    return val;
}

void splitIntoArithmeticShares(PRNG *prng, uint128_t *vals, int len, uint128_t *valShares[]) {
    for (int i = 0; i < len; i++) {
        //valShares[0][i] = 0;
        valShares[0][i] = randFieldElem(prng);
        //valShares[1][i] = 0;
        valShares[1][i] = randFieldElem(prng);
        valShares[2][i] = vals[i] - (valShares[0][i] + valShares[1][i]);
        //valShares[2][i] = vals[i];
    }

}

void splitIntoSingleArithmeticShares(PRNG *prng, uint128_t val, uint128_t valShares[]) {
    //valShares[0] = 0;
    valShares[0] = randFieldElem(prng);
    //valShares[1] = 0;
    valShares[1] = randFieldElem(prng);
    valShares[2] = val - (valShares[0] + valShares[1]);
    //valShares[2] = val;
}

// TODO: rejection sampling if don't end up using power of 2 rings
uint128_t randFieldElem(PRNG *prng) {
    uint128_t ret= prng->get<uint64_t>();
    return ret;
}

uint128_t prfFieldElem(uint128_t key, uint128_t input) {
    block keyBlock;
    block inputBlock;
    uint128_t res;
    memcpy((uint8_t *)&keyBlock, (uint8_t *)&key, sizeof(uint128_t));
    memcpy((uint8_t *)&inputBlock, (uint8_t *)&input, sizeof(uint128_t));
    AES aes(keyBlock);
    block resBlock = aes.ecbEncBlock(inputBlock);
    memcpy((uint8_t *)&res, (uint8_t *)&resBlock, sizeof(uint128_t));
    return res;
}

void printBuffer(char *label, const uint8_t *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void printByteBinary(char byte) {
    printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(byte));
}

// Used by testing functions only.
// Pack a table with 8 bits stored in a uint8_t var.
void pack_table(uint8_t** p_table, uint128_t** u_table, uint64_t numBuckets, uint64_t windowSize){
    for(int i=0; i<numBuckets; i++){
        for(int j=0; j<windowSize; j+=8){
            p_table[i][j/8] = 0;
            for(int k=0; (k<8) && (j+k < windowSize); k++){
                p_table[i][j/8] ^= (((uint8_t)u_table[i][j+k] & 1) << k);
            }
        }
    }
}

// Unpack a table to each bit taking a full uint128_t var
// TODO: make each bit take uint8_t. 128_t is too much.
void unpack_table(uint128_t** u_table, uint8_t** p_table, uint64_t numBuckets, uint64_t windowSize){
    for(int i=0; i<numBuckets; i++){
        for(int j=0; j<windowSize; j+=8){
            for(int k=0; (k<8) && (j+k < windowSize); k++){
                u_table[i][j + k] = (uint128_t)((p_table[i][j / 8] >> k) & 1);
            }
        }
    }
}

