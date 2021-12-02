#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "utils/timer.h"
#include "utils/colors.h"
#include "utils/dorydbconfig.h"
#include "fss-core/common/common.h"
#include "fss-core/common/defines.h"

namespace osuCrypto
{
    
    class DCFClient
    {
    public:
        static uint128_t bytesToUint128_t(const span<u8>& data);

        // assumes that uin8_t is enough to hold output group.
        // v0 and v1 have size of depth + 1.
        static void keyGenDCF(uint128_t idx, uint8_t payload, block seed, block* k0, uint8_t* v0, block* k1, uint8_t* v1, u64 depth, bool greaterThan = false);
        // v0 and v1 have size of depth + 1.
        static void keyGenDCFMAC(uint128_t idx, uint128_t payload, block seed, block* k0, uint128_t* v0, block* k1, uint128_t* v1, u64 depth, uint64_t gout_bitsize, bool use_modulus = true, uint128_t modulus = 0, bool greaterThan = false);
    
    };

}
#endif
