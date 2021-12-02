#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI
#include "DCFClient.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{

    uint128_t DCFClient::bytesToUint128_t(const span<u8>& data)
    {
        if (data.size() > 16)  throw std::runtime_error("inputsize is too large, 128 bit max. " LOCATION);

        using boost::multiprecision::cpp_int;
        uint128_t idx(0);
        BitIterator bit(data.data(), 0);
        for (u32 i = 0; i < u32(data.size() * 8); ++i)
        {
            if (*bit++) bit_set(idx, i);
        }
        return idx;
    }

    // assumes that uin8_t is enough to hold output group.
    // v0 and v1 have size of depth + 1.
    void DCFClient::keyGenDCF(uint128_t idx, uint8_t payload, block seed, block* k0, uint8_t* v0, block* k1, uint8_t* v1, u64 depth, bool greaterThan)
    {

        static const block notOneBlock = toBlock(~0, ~1);
		static const block notThreeBlock = toBlock(~0, ~3);
		static const block TwoBlock = toBlock(0, 2);
		static const block ThreeBlock = toBlock(0, 3);

        u64 groupSize = 1;
        auto kIdx = idx / (groupSize * 128);

        u64 kDepth = depth;
        // To store the s values obtained by expanding the PRG.
        std::array<std::array<block, 2>, 2> si;
        // For CW_{n + 1}
        std::array<uint8_t, 2> s_convert;
        // Sample random s for the tree root.
        std::array<block, 2> s = PRNG(seed).get<std::array<block, 2>>();
        std::array<block, 2> s_wo_t;
        std::array<std::array<block, 2>, 2> vi;
		std::array<std::array<block, 2>, 2> vi_pre_convert;
		std::array<std::array<uint8_t, 2>, 2> vi_convert;
        uint8_t v_alpha = 0;
        
        std::cout<<"The tree depth is: "<<kDepth<<std::endl;

        // make sure that s[0]'s bottom bit is the opposite of s[1]
        // This bottom bit will represent the t values
        s[0] = (s[0] & notOneBlock)           // take the bits [127,1] bits of  s[0]
            ^ ((s[1] & OneBlock) ^ OneBlock); // take the bits [0  ,0] bits of ~s[1]

        k0[0] = s[0];
        k1[0] = s[1];

        static AES aes0(ZeroBlock);
        static AES aes1(OneBlock);
        static AES aes2(TwoBlock);
		static AES aes3(ThreeBlock);
        
        for (u64 i = 0, shift = kDepth - 1; i < kDepth; ++i, --shift)
        {
            const u8 keep = static_cast<u8>(kIdx >> shift) & 1;
            auto a = toBlock(keep);

            // ss means the s-only component of s. s also has a t component.
            auto ss0 = s[0] & notThreeBlock;
            auto ss1 = s[1] & notThreeBlock;

            aes0.ecbEncBlock(ss0, si[0][0]);
			aes1.ecbEncBlock(ss0, si[0][1]);
			aes2.ecbEncBlock(ss0, vi[0][0]);
			aes3.ecbEncBlock(ss0, vi[0][1]);
			aes0.ecbEncBlock(ss1, si[1][0]);
			aes1.ecbEncBlock(ss1, si[1][1]);
			aes2.ecbEncBlock(ss1, vi[1][0]);
			aes3.ecbEncBlock(ss1, vi[1][1]);
			si[0][0] = si[0][0] ^ ss0;
			si[0][1] = si[0][1] ^ ss0;
			si[1][0] = si[1][0] ^ ss1;
			si[1][1] = si[1][1] ^ ss1;
			vi[0][0] = vi[0][0] ^ ss0;
			vi[0][1] = vi[0][1] ^ ss0;
			vi[1][0] = vi[1][0] ^ ss1;
			vi[1][1] = vi[1][1] ^ ss1;

            vi_pre_convert[0][0] = vi[0][0];
			vi_pre_convert[0][1] = vi[0][1];
			vi_pre_convert[1][0] = vi[1][0];
			vi_pre_convert[1][1] = vi[1][1];
			
			vi_convert[0][0] = ((uint8_t*)&(vi_pre_convert[0][0]))[0];
			vi_convert[0][1] = ((uint8_t*)&(vi_pre_convert[0][1]))[0];
			vi_convert[1][0] = ((uint8_t*)&(vi_pre_convert[1][0]))[0];
			vi_convert[1][1] = ((uint8_t*)&(vi_pre_convert[1][1]))[0];

            // ti are t from previous level of the tree.
            auto ti0 = *(u8 *)&s[0] & 1;
			auto ti1 = *(u8 *)&s[1] & 1;
            // Sign not used when output group is just a bit.
			//T sign = (ti1 == 1)?-1:+1;

			// Assuming gout_bitsize == 1
            v0[i] = (vi_convert[1][(keep ^ 1)] ^ vi_convert[0][(keep ^ 1)] ^ v_alpha);
            v1[i] = v0[i];
            if(keep == 1){
                // Lose is L
                v0[i] = v0[i] ^ ((1^greaterThan) & payload);
            }
            else{
                // Lose is R
                v0[i] = v0[i] ^ (greaterThan & payload);
            }

            v1[i] = v0[i];
	        v_alpha = v_alpha ^ vi_convert[1][keep] ^ vi_convert[0][keep] ^ v0[i]; 

            std::array<block, 2> siXOR{ si[0][0] ^ si[1][0], si[0][1] ^ si[1][1] };

            //std::cout << "s0*[" << i << "]    " << stt(si[0][0]) << " " << stt(si[0][1]) << std::endl;
            //std::cout << "s1*[" << i << "]    " << stt(si[1][0]) << " " << stt(si[1][1]) << std::endl;

            // get the left and right t_CW bits
            std::array<block, 2> t{
                (OneBlock & siXOR[0]) ^ a ^ OneBlock,
                (OneBlock & siXOR[1]) ^ a };

            // take scw to be the bits [127, 2] as scw = s0_loss ^ s1_loss
            auto scw = siXOR[keep ^ 1] & notThreeBlock;

            //std::cout << "scw[" << i << "]    " << stt(scw) << std::endl;
            //std::cout << "tL[" << i << "]     " << t1(t[0]) << std::endl;
            //std::cout << "tR[" << i << "]     " << t1(t[1]) << std::endl;

            k0[i + 1] = k1[i + 1] = scw              // set bits [127, 2] as scw = s0_loss ^ s1_loss
                ^ (t[0] << 1) // set bit 1 as tL
                ^ t[1];          // set bit 0 as tR

            //std::cout << "CW[" << i << "]     " << stt(k0[i + 1]) << std::endl;

            auto si0Keep = si[0][keep];
            auto si1Keep = si[1][keep];

            // extract the t^Keep_CW bit
            auto TKeep = t[keep];

            // set the next level of s,t
            s[0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
            s[1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

            //std::cout << "s0[" << i + 1 << "]     " << stt(s[0]) << std::endl;
            //std::cout << "s1[" << i + 1 << "]     " << stt(s[1]) << std::endl;
        }
        s_wo_t[0] = s[0] & notThreeBlock;
        s_wo_t[1] = s[1] & notThreeBlock;

        // Assuming gout_bitsize == 1
		s_convert[0] = ((uint8_t*)&(s_wo_t[0]))[0];
		s_convert[1] = ((uint8_t*)&(s_wo_t[1]))[0];
        
        v0[kDepth] = (s_convert[1] ^ s_convert[0] ^ v_alpha);
        v1[kDepth] = v0[kDepth];
    }

    // v0 and v1 have size of depth + 1.
    void DCFClient::keyGenDCFMAC(uint128_t idx, uint128_t payload, block seed, block* k0, uint128_t* v0, block* k1, uint128_t* v1, 
            u64 depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool greaterThan)
    {
        assert((gout_bitsize <= 125) && "Bitsize greater than 125 is not supported");
        assert((use_modulus == true) && "Not yet implemented");

        greaterThan %= 2;
        static const block notOneBlock = toBlock(~0, ~1);
		static const block notThreeBlock = toBlock(~0, ~3);
		static const block TwoBlock = toBlock(0, 2);
		static const block ThreeBlock = toBlock(0, 3);

		u64 groupSize = 1;
		auto kIdx = idx / (groupSize * 128);

		u64 kDepth = depth;
        // To store the s values obtained by expanding the PRG.
        std::array<std::array<block, 2>, 2> si;
        // For CW_{n + 1}
        std::array<uint128_t, 2> s_convert;
        // Sample random s for the tree root.
        std::array<block, 2> s = PRNG(seed).get<std::array<block, 2>>();
        std::array<block, 2> s_wo_t;
        std::array<std::array<block, 2>, 2> vi;
		std::array<std::array<block, 2>, 2> vi_pre_convert;
		std::array<std::array<uint128_t, 2>, 2> vi_convert;
        uint128_t v_alpha = 0;

        //std::cout<<"The tree depth is: "<<kDepth<<std::endl;
		
		// make sure that s[0]'s bottom bit is the opposite of s[1]
		// This bottom bit will represent the t values
		s[0] = (s[0] & notOneBlock) // take the bits [127,1] bits of  s[0]
			^ ((s[1] & OneBlock) ^ OneBlock); // take the bits [0  ,0] bits of ~s[1]

		k0[0] = s[0];
		k1[0] = s[1];

		static AES aes0(ZeroBlock);
		static AES aes1(OneBlock);
		static AES aes2(TwoBlock);
		static AES aes3(ThreeBlock);

		for (u64 i = 0, shift = kDepth - 1; i < kDepth; ++i, --shift)
		{
			//std::cout<<"Tree Level #"<<i+1<<std::endl;
			const u8 keep = static_cast<u8>(kIdx >> shift) & 1;
			auto a = toBlock(keep);
			
			auto ss0 = s[0] & notThreeBlock;
			auto ss1 = s[1] & notThreeBlock;

			aes0.ecbEncBlock(ss0, si[0][0]);
			aes1.ecbEncBlock(ss0, si[0][1]);
			aes2.ecbEncBlock(ss0, vi[0][0]);
			aes3.ecbEncBlock(ss0, vi[0][1]);
			aes0.ecbEncBlock(ss1, si[1][0]);
			aes1.ecbEncBlock(ss1, si[1][1]);
			aes2.ecbEncBlock(ss1, vi[1][0]);
			aes3.ecbEncBlock(ss1, vi[1][1]);
			si[0][0] = si[0][0] ^ ss0;
			si[0][1] = si[0][1] ^ ss0;
			si[1][0] = si[1][0] ^ ss1;
			si[1][1] = si[1][1] ^ ss1;
			vi[0][0] = vi[0][0] ^ ss0;
			vi[0][1] = vi[0][1] ^ ss0;
			vi[1][0] = vi[1][0] ^ ss1;
			vi[1][1] = vi[1][1] ^ ss1;

			vi_pre_convert[0][0] = vi[0][0];
			vi_pre_convert[0][1] = vi[0][1];
			vi_pre_convert[1][0] = vi[1][0];
			vi_pre_convert[1][1] = vi[1][1];
			
            memcpy((uint8_t*)(&vi_convert[0][0]), (uint8_t*)(&vi_pre_convert[0][0]), sizeof(block));
            memcpy((uint8_t*)(&vi_convert[0][1]), (uint8_t*)(&vi_pre_convert[0][1]), sizeof(block));
            memcpy((uint8_t*)(&vi_convert[1][0]), (uint8_t*)(&vi_pre_convert[1][0]), sizeof(block));
            memcpy((uint8_t*)(&vi_convert[1][1]), (uint8_t*)(&vi_pre_convert[1][1]), sizeof(block));
            
            // ti are t from previous level of the tree.
			auto ti0 = *(u8 *)&s[0] & 1;
			auto ti1 = *(u8 *)&s[1] & 1;
			uint128_t sign = (ti1 == 1)?-1:+1;

            v0[i] = sign*(vi_convert[1][keep ^ 1] - vi_convert[0][keep ^ 1] - v_alpha);
            v0[i] = v0[i] % modulus;
            if(keep == 1){
                // Lose is L
                v0[i] = v0[i] + (sign * ((1 ^ greaterThan) * payload));
            }
            else{
                // Lose is R
                v0[i] = v0[i] + (sign * (greaterThan * payload));
            }
            v0[i] = v0[i] % modulus;
            v1[i] = v0[i];
            
            v_alpha = v_alpha - vi_convert[1][keep] + vi_convert[0][keep] + (sign*v0[i]);
            v_alpha = v_alpha % modulus; 

			std::array<block, 2> siXOR{ si[0][0] ^ si[1][0], si[0][1] ^ si[1][1] };
			
			// get the left and right t_CW bits
			std::array<block, 2> t{
				(OneBlock & siXOR[0]) ^ a ^ OneBlock,
					(OneBlock & siXOR[1]) ^ a };

			// take scw to be the bits [127, 2] as scw = s0_loss ^ s1_loss
			auto scw = siXOR[keep ^ 1] & notThreeBlock;

			k0[i + 1] = k1[i + 1] = scw // set bits [127, 2] as scw = s0_loss ^ s1_loss
				^ (t[0] << 1) // set bit 1 as tL
				^ t[1];  // set bit 0 as tR

			auto si0Keep = si[0][keep];
			auto si1Keep = si[1][keep];

			// extract the t^Keep_CW bit
			auto TKeep = t[keep];

			// set the next level of s,t
			s[0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
			s[1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

		}
        s_wo_t[0] = s[0] & notThreeBlock;
        s_wo_t[1] = s[1] & notThreeBlock;
        
        memcpy((uint8_t*)(&s_convert[0]), (uint8_t*)(&s_wo_t[0]), sizeof(block));
        memcpy((uint8_t*)(&s_convert[1]), (uint8_t*)(&s_wo_t[1]), sizeof(block));
		auto ti1 = *(u8 *)&s[1] & 1;
		uint128_t sign = (ti1 == 1)?-1:+1;
        
        v0[kDepth] = sign*(s_convert[1] - s_convert[0] - v_alpha);
        v0[kDepth] %= modulus;
        v1[kDepth] = v0[kDepth];
        
    }


}
#endif
