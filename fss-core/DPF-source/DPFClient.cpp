#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI
#include "DPFClient.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{
    static inline u8 lsb(const block& b)
	{
		return  _mm_cvtsi128_si64x(b) & 1;
	}

    // v0 and v1 have size of depth + 1.
    void DPFClient::keyGenDPF(uint128_t idx, uint128_t payload, block seed, block* k0, uint128_t* g0, block* k1, uint128_t* g1, 
            u64 depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
    {
        assert((gout_bitsize <= 125) && "Bitsize greater than 125 is not supported");
        assert((use_modulus == true) && "Not yet implemented");

        static const block notOneBlock = toBlock(~0, ~1);
		static const block notThreeBlock = toBlock(~0, ~3);

		u64 groupSize = 1;
		auto kIdx = idx / (groupSize * 128);
		u64 gIdx = static_cast<u64>(idx % (groupSize * 128));

		u64 kDepth = depth;
		std::array<std::array<block, 2>, 2> si;
		std::array<block, 2> s = PRNG(seed).get<std::array<block, 2>>();
		
		// make sure that s[0]'s bottom bit is the opposite of s[1]
		// This bottom bit will represent the t values
		s[0] = (s[0] & notOneBlock) // take the bits [127,1] bits of  s[0]
			^ ((s[1] & OneBlock) ^ OneBlock); // take the bits in [0, 0] of ~s[1]

		k0[0] = s[0];
		k1[0] = s[1];

		static AES aes0(ZeroBlock);
		static AES aes1(OneBlock);

		for (u64 i = 0, shift = kDepth - 1; i < kDepth; ++i, --shift)
		{
			const u8 keep = static_cast<u8>(kIdx >> shift) & 1;
			auto a = toBlock(keep);
			
			auto ss0 = s[0] & notThreeBlock;
			auto ss1 = s[1] & notThreeBlock;

			aes0.ecbEncBlock(ss0, si[0][0]);
			aes1.ecbEncBlock(ss0, si[0][1]);
			aes0.ecbEncBlock(ss1, si[1][0]);
			aes1.ecbEncBlock(ss1, si[1][1]);
			si[0][0] = si[0][0] ^ ss0;
			si[0][1] = si[0][1] ^ ss0;
			si[1][0] = si[1][0] ^ ss1;
			si[1][1] = si[1][1] ^ ss1;

			std::array<block, 2> siXOR{ si[0][0] ^ si[1][0], si[0][1] ^ si[1][1] };

			// get the left and right t_CW bits
			std::array<block, 2> t{
				(OneBlock & siXOR[0]) ^ a ^ OneBlock,
					(OneBlock & siXOR[1]) ^ a };

			// take scw to be the bits [127, 2] as scw = s0_loss ^ s1_loss
			auto scw = siXOR[keep ^ 1] & notThreeBlock;

			k0[i + 1] = k1[i + 1] = scw // set bits [127, 2] as scw = s0_loss ^ s1_loss
				^ (t[0] << 1) // set bit 1 as tL
				^ t[1];          // set bit 0 as tR

			// get the the conditional XOR bits t^L_CW, t^R_CW
			auto ti0 = *(u8 *)&s[0] & 1;
			auto ti1 = *(u8 *)&s[1] & 1;

			auto si0Keep = si[0][keep];
			auto si1Keep = si[1][keep];

			// extract the t^Keep_CW bit
			auto TKeep = t[keep];

			// set the next level of s,t
			s[0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
			s[1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

		}

		std::vector<block> temp(1 * 4);
		auto s0 = temp.data();
		auto s1 = temp.data() + 1;
		auto gs0 = temp.data() + 1 * 2;
		auto gs1 = temp.data() + 1 * 3;

		for (u64 i = 0; i < u64(1); ++i)
		{
			// To get more than 128 bits out of aes later if g0.size > 1.
			s0[i] = (s[0] & notThreeBlock) ^ toBlock(i);
			s1[i] = (s[1] & notThreeBlock) ^ toBlock(i);
		}
		
		// These lines are commented because PRG for Convert() is only
		// needed if output group is bigger than 2^{128}.

		// Here we are finishing the last step of Convert() function
		// where we are using fixed-key AES as a correlation robust hash function.
		for (u64 i = 0; i < u64(1); ++i)
		{
			gs0[i] = s0[i];
			gs1[i] = s1[i];
		}
	    
        uint128_t gs0_val, gs1_val;
        memcpy((uint8_t*)(&gs0_val), (uint8_t*)gs0, sizeof(block));
        memcpy((uint8_t*)(&gs1_val), (uint8_t*)gs1, sizeof(block));
        

		if(gout_bitsize == 1){
            g0[0] = (payload ^ gs0_val ^ gs1_val);  
            memcpy(g1, g0, sizeof(uint128_t));
		}	
		else if(!use_modulus){
            throw std::invalid_argument("Not yet implemented");
            g0[0] = (payload - (((uint128_t*)gs0))[0] + (((uint128_t*)gs1))[0]);  
            if(lsb(s[1]) == 1){
                g0[0] *= -1;
            }	
            memcpy(g1, g0, sizeof(uint128_t));
		}
		else{ //use modulus
			g0[0] = payload - gs0_val + gs1_val;  
			if(lsb(s[1]) == 1){
				g0[0] *= -1;
			}
            g0[0] = g0[0] % modulus;    
			memcpy(g1, g0, sizeof(uint128_t));
		}
    }

}
#endif
