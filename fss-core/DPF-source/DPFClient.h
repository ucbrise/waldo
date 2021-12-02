#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "utils/timer.h"
#include "utils/colors.h"
#include "fss-core/common/defines.h"
#include "fss-core/common/common.h"

namespace osuCrypto
{
    
    class DPFClient
    {
    public:
        // k0, k1 have size depth + 1. g0, g1 are single output group elements.
        static void keyGenDPF(uint128_t idx, uint128_t payload, block seed, block* k0, uint128_t* g0, block* k1, uint128_t* g1, u64 depth, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0);
    
    };

}
#endif
