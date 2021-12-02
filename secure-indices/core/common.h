#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include "fss-core/libPSI/libPSI/PIR/BgiPirClient.h"
#include "keys.h"

#define NUM_SERVERS 3

#define APPEND_LOC -1

//typedef unsigned __int128 uint128_t;

using namespace std;
using namespace osuCrypto;

int getDepth(int x);
bool isBitOne(const uint8_t *buf, int bitIndex);
void setBitOne(uint8_t *buf, int bitIndex);
void copyBit(uint8_t *dst, int dstBitIndex, uint8_t *src, int srcBitIndex);
void xorIn(uint8_t *out, const uint8_t *in, int len);
void setTableColumn(uint128_t **table, int column, const uint128_t *in, int len);

void splitIntoBinaryShares(PRNG *prng, uint8_t *in_data, int len, uint8_t *out_data[]);
uint128_t *createIndicatorVector(int idx, int len);
void combineArithmeticShares(uint128_t *vals, int len, uint128_t *valShares[], int dim, bool ignoreNegOne);
uint128_t combineSingleArithmeticShares(uint128_t valShares[], int dim, bool ignoreNegOne);
void splitIntoArithmeticShares(PRNG *prng, uint128_t *vals, int len, uint128_t *valShares[]);
void splitIntoSingleArithmeticShares(PRNG *prng, uint128_t val, uint128_t valShares[]);
uint128_t randFieldElem(PRNG *prng);
uint128_t prfFieldElem(uint128_t key, uint128_t input);

void printBuffer(char *label, const uint8_t *buf, int len);
void printByteBinary(char byte);

// Only used by testing functions
// p_table is the packed table which is numBuckets x PACKED_WIN_SIZE(windowSize)
// u_table is the unpacked table which is numBuckets x windowSize
void pack_table(uint8_t** p_table, uint128_t** u_table, uint64_t numBuckets, uint64_t windowSize);
void unpack_table(uint128_t** u_table, uint8_t** p_table, uint64_t numBuckets, uint64_t windowSize);


#endif
