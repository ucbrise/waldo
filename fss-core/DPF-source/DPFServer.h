#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include "fss-core/common/defines.h"

#ifndef _EVAL_ROLES_
#define _EVAL_ROLES_
#define EVAL0 0
#define EVAL1 1
#endif

namespace osuCrypto
{

	class DPFServer
	{
	public:
        
        // party_id is either 0 or 1
        static uint128_t evalOneDPF(uint128_t idx, block* k, uint128_t* g, u64 depth, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
        static block traversePathDPF(uint128_t idx, block* k, uint128_t* g, uint128_t* res_share, uint64_t depth,
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus);
		static block traverseOneDPF(const block &s, const block&k, const u8 &keep);
        static void contigEvalOneDPFLarge(uint128_t* res, block* k, uint128_t* g, block s, u64 depth, u64 curDepth, u64 start, u64 range, u64 end, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, u64 &ctr);
        static  void ContigDomainDPFLargeOutOptimized(uint128_t* res, block* k, uint128_t* g, u64 depth, u64 start, u64 end, uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus);

	};

}
#endif
