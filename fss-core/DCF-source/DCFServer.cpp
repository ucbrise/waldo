#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI
#include "DCFServer.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Matrix.h>
#include "DCFClient.h"
#include <libOTe/Tools/Tools.h>

namespace osuCrypto
{

	static AES aes0(toBlock(u64(0)));
	static AES aes1(toBlock(1));
	static const block notThreeBlock = toBlock(~0, ~3);
	static const block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
    static const block TwoBlock = toBlock(0, 2);
	static const block ThreeBlock = toBlock(0, 3);
	static AES aes2(TwoBlock);
	static AES aes3(ThreeBlock);

	extern std::string ss(block b);
	extern std::string t1(block b);
	extern std::string t2(block b);
	extern std::string stt(block b);

	inline u8 lsb(const block& b)
	{
		return  _mm_cvtsi128_si64x(b) & 1;
	}

    uint8_t DCFServer::evalOneDCF(uint128_t idx, block* k, uint8_t* v, u64 depth)
	{
		u64 kDepth = depth;
		auto kIdx = idx / (1 * 128);

        // Assuming output group is a single bit.
		uint8_t result_share = 0;

		traversePathDCF(kIdx, k, &result_share, v, kDepth);
	
		return result_share;	
	}

    // v_share is the accumulator v which holds final output share
    // and v is the v_CW key part. 
    block DCFServer::traversePathDCF(uint128_t idx, block* k, u8* v_share, u8* v, uint64_t depth)
	{
		block s = k[0];

		for (u64 i = 0, shift = depth - 1; i < depth; ++i, --shift)
		{
			const u8 keep = static_cast<u8>(idx >> shift) & 1;
			s = traverseOneDCF(s, k[i + 1], keep, true, v_share, v, i, depth);
		}
		
        auto s_last = s & notThreeBlock;
		uint8_t s_converted = ((uint8_t*)&(s_last))[0];
		uint8_t t_last = *(uint8_t *)(&s) & 1;

        v_share[0] ^= s_converted ^ (t_last & v[(int)depth]);	

		return s;
	}
    
    // v_share is the accumulator v which holds final output share
    // and v is the v_CW key part. 
    block DCFServer::traverseOneDCF(const block& s, const block& cw, const u8 &keep, bool print, u8* v_share, u8* v, uint64_t level, uint64_t depth)

	{

		std::array<block, 2> tau, stcw, v_this_level, v_pre_converted;
		uint8_t v_converted;
		auto ss = s & notThreeBlock;
		aes0.ecbEncBlock(ss, tau[0]);
		aes1.ecbEncBlock(ss, tau[1]);
		aes2.ecbEncBlock(ss, v_this_level[0]);
		aes3.ecbEncBlock(ss, v_this_level[1]);
		tau[0] = tau[0] ^ ss;
		tau[1] = tau[1] ^ ss;
		v_this_level[0] = v_this_level[0] ^ ss;
		v_this_level[1] = v_this_level[1] ^ ss;

		// These lines are commented because PRG for Convert() is only
		// needed if output group is bigger than 2^{128}.
		//aes0.ecbEncBlock(v_this_level[0], v_pre_converted[0]);
		//aes0.ecbEncBlock(v_this_level[1], v_pre_converted[1]);
		//v_pre_converted[0] ^= v_this_level[0];
		//v_pre_converted[1] ^= v_this_level[1];
		
		v_pre_converted[0] = v_this_level[0];
		v_pre_converted[1] = v_this_level[1];

		const auto scw = (cw & notThreeBlock);

        // If t_(i-1) = t_previous = lsb(x) is 1, then mask is all 1s, otherwise it is all 0s.
		const auto mask = zeroAndAllOne[lsb(s)];

        // s_CW||t^L_CW
		auto d0 = ((cw >> 1) & OneBlock);
        // s_CW||t^R_CW
		auto d1 = (cw & OneBlock);
        // t_(i-1).s_CW||t^L_CW
		auto c0 = ((scw ^ d0) & mask);
        // t_(i-1).s_CW||t^R_CW
		auto c1 = ((scw ^ d1) & mask);

		// This is what parsed tau finally is.
        stcw[0] = c0 ^ tau[0];
		stcw[1] = c1 ^ tau[1];

		uint8_t t0_corr_val, t1_corr_val, t_previous;
		t0_corr_val = *(u8 *)&d0 & 1;
		t1_corr_val = *(u8 *)&d1 & 1;
		t_previous = *(uint8_t *)(&s) & 1;

		// Set v_share cumulatively
		v_converted = ((uint8_t*)&(v_pre_converted[keep]))[0];
		// Not needed when working with single bit outputs.
        // T sign = (party == SERVER1)?-1:1;
		// Assuming gout_bitsize == 1
        v_share[0] ^= v_converted ^ (t_previous & v[(int)level]);	
		
        return stcw[keep];
	}

    // party_id is either 0 or 1
    boost::multiprecision::uint128_t DCFServer::evalOneDCFMAC(uint128_t idx, block* k, uint128_t* v, u64 depth, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
	{
        assert((gout_bitsize <= 125) && "Bitsize greater than 125 is not supported");
        assert((use_modulus == true) && "Not yet implemented");
        assert((party_id < 2) && "Party ID can be either 0 or 1");
		
        u64 kDepth = depth;
		auto kIdx = idx / (1 * 128);

        // Assuming output group is a single bit.
		uint128_t result_share = 0;

		traversePathDCFMAC(kIdx, k, &result_share, v, kDepth, party_id, gout_bitsize, use_modulus, modulus);
	
		return result_share;	
	}

    // v_share is the accumulator v which holds final output share
    // and v is the v_CW key part. 
    // party_id is either 0 or 1
    block DCFServer::traversePathDCFMAC(uint128_t idx, block* k, uint128_t* v_share, uint128_t* v, uint64_t depth,
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
	{
        if(k == nullptr){
            std::cout<<"Key is null"<<std::endl;
        }
        block s = k[0];

		for (u64 i = 0, shift = depth - 1; i < depth; ++i, --shift)
		{
			const u8 keep = static_cast<u8>(idx >> shift) & 1;
			s = traverseOneDCFMAC(s, k[i + 1], keep, true, v_share, v, i, depth, party_id, gout_bitsize, use_modulus, modulus);
		}
		
        auto s_last = s & notThreeBlock;
		uint128_t s_converted;
        memcpy((uint8_t*)(&s_converted), (uint8_t*)(&s_last), sizeof(block));
		
        uint8_t t_last = *(uint8_t *)(&s) & 1;
        uint128_t sign = (party_id == 1)?-1:+1;

        v_share[0] = v_share[0] + sign*(s_converted + (t_last * v[(int)depth]));	
        v_share[0] = v_share[0] % modulus;

		return s;
	}
    
    // v_share is the accumulator v which holds final output share
    // and v is the v_CW key part. 
    // party_id is either 0 or 1
    block DCFServer::traverseOneDCFMAC(const block& s, const block& cw, const u8 &keep, bool print, uint128_t* v_share, uint128_t* v, uint64_t level, uint64_t depth, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)

	{

		std::array<block, 2> tau, stcw, v_this_level, v_pre_converted;
		uint128_t v_converted;
		auto ss = s & notThreeBlock;
		aes0.ecbEncBlock(ss, tau[0]);
		aes1.ecbEncBlock(ss, tau[1]);
		aes2.ecbEncBlock(ss, v_this_level[0]);
		aes3.ecbEncBlock(ss, v_this_level[1]);
		tau[0] = tau[0] ^ ss;
		tau[1] = tau[1] ^ ss;
		v_this_level[0] = v_this_level[0] ^ ss;
		v_this_level[1] = v_this_level[1] ^ ss;

		// These lines are commented because PRG for Convert() is only
		// needed if output group is bigger than 2^{128}.
		//aes0.ecbEncBlock(v_this_level[0], v_pre_converted[0]);
		//aes0.ecbEncBlock(v_this_level[1], v_pre_converted[1]);
		//v_pre_converted[0] ^= v_this_level[0];
		//v_pre_converted[1] ^= v_this_level[1];
		
		v_pre_converted[0] = v_this_level[0];
		v_pre_converted[1] = v_this_level[1];

		const auto scw = (cw & notThreeBlock);

        // If t_(i-1) = t_previous = lsb(x) is 1, then mask is all 1s, otherwise it is all 0s.
		const auto mask = zeroAndAllOne[lsb(s)];

        // s_CW||t^L_CW
		auto d0 = ((cw >> 1) & OneBlock);
        // s_CW||t^R_CW
		auto d1 = (cw & OneBlock);
        // t_(i-1).s_CW||t^L_CW
		auto c0 = ((scw ^ d0) & mask);
        // t_(i-1).s_CW||t^R_CW
		auto c1 = ((scw ^ d1) & mask);

		// This is what parsed tau finally is.
        stcw[0] = c0 ^ tau[0];
		stcw[1] = c1 ^ tau[1];

		uint8_t t0_corr_val, t1_corr_val, t_previous;
		t0_corr_val = *(u8 *)&d0 & 1;
		t1_corr_val = *(u8 *)&d1 & 1;
		t_previous = *(uint8_t *)(&s) & 1;

		// Set v_share cumulatively
        memcpy((uint8_t*)(&v_converted), (uint8_t*)(&v_pre_converted[keep]), sizeof(block));
        
        uint128_t sign = (party_id == 1)?-1:+1;
        v_share[0] = v_share[0] + sign*(v_converted + (t_previous * v[(int)level]));	
        v_share[0] = v_share[0] % modulus;
        return stcw[keep];
	}

    // party_id is either 0 or 1
    // Put nullptr wherever required in the function call.
    void DCFServer::FullDomainDCF(uint8_t* res_bitmap, uint128_t* res_MAC, block* k, uint8_t* v, 
            bool with_MAC, block* k_MAC, uint128_t* v_MAC, u64 depth, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
    {
        uint64_t domain_size = (1ULL<<depth);
        uint64_t group_size_blocks = 1;
        uint128_t mod = group_size_blocks*128;
        for(uint64_t i=0; i<domain_size; i++){
            if(i % (1<<16) == 0) std::cout<<"On bit DCF iteration #"<<i<<std::endl;
            res_bitmap[i] = evalOneDCF(i*mod, k, v, depth);
        }
        if(with_MAC){
            for(uint64_t i=0; i<domain_size; i++){
                if(i % (1<<16) == 0) std::cout<<"On MAC DCF iteration #"<<i<<std::endl;
                res_MAC[i] = evalOneDCFMAC(i*mod, k_MAC, v_MAC, depth, party_id, gout_bitsize, use_modulus, modulus);
            }
        }
    }

    void DCFServer::FullDomainDCFLargeOut(uint128_t* res, block* k, uint128_t* v, 
            u64 depth, uint8_t party_id, uint64_t gout_bitsize, 
            bool use_modulus, uint128_t modulus)
    {
        uint64_t domain_size = (1ULL<<depth);
        uint64_t group_size_blocks = 1;
        uint128_t mod = group_size_blocks*128;
        for(uint64_t i=0; i<domain_size; i++){
            res[i] = evalOneDCFMAC(i*mod, k, v, depth, party_id, gout_bitsize, use_modulus, modulus);
        }
    }

    void DCFServer::contigEvalOneDCFLarge(uint128_t* res, block* k, uint128_t* v, block s, uint128_t v_cuml,
            u64 depth, u64 curDepth, u64 start, u64 range, u64 end, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, u64 &ctr)
	{
        assert((gout_bitsize <= 125) && "Bitsize greater than 125 is not supported");
        assert((use_modulus == true) && "Not yet implemented");
        assert((party_id < 2) && "Party ID can be either 0 or 1");
        u64 idx = start;

        // Base conditions to kill recursion
        if(start > end){
            return;
        }
        if(curDepth > depth){
            return;
        }
        // main body starts

        const u8 keep = static_cast<u8>(idx >> (depth - curDepth)) & 1;
        //INIT_TIMER;
        //START_TIMER; 
        s = traverseOneDCFMAC(s, k[curDepth], keep, true, &v_cuml, v, curDepth-1, depth, party_id, gout_bitsize, use_modulus, modulus);
        //STOP_TIMER("DCF Traversal"); 

        if(curDepth == depth){
            auto s_last = s & notThreeBlock;
            uint128_t s_converted;
            memcpy((uint8_t*)(&s_converted), (uint8_t*)(&s_last), sizeof(block));
            uint8_t t_last = *(uint8_t *)(&s) & 1;
            uint128_t sign = (party_id == 1)?-1:+1;

            v_cuml = v_cuml + sign*(s_converted + (t_last * v[(int)depth]));	
            v_cuml = v_cuml % modulus;
            res[0] = v_cuml;	
        }
        
        // Left subchild recursive
        contigEvalOneDCFLarge(res, k, v, s, v_cuml, depth, curDepth + 1, start, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        if(range > 1){
            // Right subchild recursive
            contigEvalOneDCFLarge(res + range/2, k, v, s, v_cuml, depth, curDepth + 1, start + range/2, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        }
        

        return;
	}

    // Contiguous domain evaluation
    void DCFServer::ContigDomainDCFLargeOutOptimized(uint128_t* res, block* k, uint128_t* v, 
            u64 depth, u64 start, u64 end, uint8_t party_id, uint64_t gout_bitsize, 
            bool use_modulus, uint128_t modulus)
    {
        if(k == nullptr){
            std::cout<<"Key is null"<<std::endl;
            throw std::invalid_argument("Null key");
        }
        u64 range = (end - start + 1);
        assert(((range & (range-1)) == 0) && "Implementation assumes balanced tree");
        // curDepth at beginning is 1 because root doesn't need any computation.
        u64 curDepth = 1;
        u64 v_cuml = 0;
        u64 ctr = 0;
        
        // depth 0 part
        block s = k[0];
        
        //INIT_TIMER;
        //START_TIMER; 
        // Left 
        contigEvalOneDCFLarge(res, k, v, s, v_cuml, depth, curDepth, start, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        // Right
        contigEvalOneDCFLarge(res + range/2, k, v, s, v_cuml, depth, curDepth, start + range/2, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        //STOP_TIMER("DCF Recursion");
    }

}
#endif
