#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include "fss-core/common/common.h"
#include "fss-core/common/defines.h"

#ifndef _EVAL_ROLES_
#define _EVAL_ROLES_
#define EVAL0 0
#define EVAL1 1
#endif

namespace osuCrypto
{

	class DCFServer
	{
	public:
        static uint8_t evalOneDCF(uint128_t idx, block* k, uint8_t* v, u64 depth);
        // v_share is the accumulator v which holds final output share
        // and v is the v_CW key part. 
        static block traversePathDCF(uint128_t idx, block* k, u8* v_share, u8* v, uint64_t depth);
        static block traverseOneDCF(const block& s, const block& cw, const u8 &keep, bool print, u8* v_share, u8* v, uint64_t level, uint64_t depth);
        
        // party_id is either 0 or 1
        static uint128_t evalOneDCFMAC(uint128_t idx, block* k, uint128_t* v, u64 depth, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
        // v_share is the accumulator v which holds final output share
        // and v is the v_CW key part. 
        static block traversePathDCFMAC(uint128_t idx, block* k, uint128_t* v_share, uint128_t* v, uint64_t depth, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
        static block traverseOneDCFMAC(const block& s, const block& cw, const u8 &keep, bool print, uint128_t* v_share, uint128_t* v, uint64_t level, uint64_t depth, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
        // default params correspond to when with_MAC is set to false.
        static void FullDomainDCF(uint8_t* res_bitmap, uint128_t* res_MAC, block* k, uint8_t* v, bool with_MAC, block* k_MAC, uint128_t* v_MAC, u64 depth, uint8_t party_id = EVAL0, uint64_t gout_bitsize = 1, bool use_modulus = true, uint128_t modulus = 0);
        static void FullDomainDCFLargeOut(uint128_t* res, block* k, uint128_t* v, u64 depth, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
        static void contigEvalOneDCFLarge(uint128_t* res, block* k, uint128_t* v, block s, uint128_t v_cuml, u64 depth, u64 curDepth, u64 start, u64 range, u64 end, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, uint64_t &ctr);
        // Contiguous domain evaluation
        static void ContigDomainDCFLargeOutOptimized(uint128_t* res, block* k, uint128_t* v, u64 depth, u64 start, u64 end, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus);
	};

}
#endif
