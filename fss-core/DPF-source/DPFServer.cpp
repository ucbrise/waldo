#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI
#include "DPFServer.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Matrix.h>
#include "DPFClient.h"
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

    // party_id is either 0 or 1
    boost::multiprecision::uint128_t DPFServer::evalOneDPF(uint128_t idx, block* k, uint128_t* g, u64 depth, 
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
	{
        assert((gout_bitsize <= 125) && "Bitsize greater than 125 is not supported");
        assert((use_modulus == true) && "Not yet implemented");
        assert((party_id < 2) && "Party ID can be either 0 or 1");
		
        u64 kDepth = depth;
		auto kIdx = idx / (1 * 128);

		uint128_t result_share = 0;

		traversePathDPF(kIdx, k, g, &result_share, kDepth, party_id, gout_bitsize, use_modulus, modulus);
	
		return result_share;	
	}

    // party_id is either 0 or 1
    block DPFServer::traversePathDPF(uint128_t idx, block* k, uint128_t* g, uint128_t* res_share, uint64_t depth,
            uint8_t party_id, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus)
	{
		block s = k[0];

		for (u64 i = 0, shift = depth - 1; i < depth; ++i, --shift)
		{
			const u8 keep = static_cast<u8>(idx >> shift) & 1;
			s = traverseOneDPF(s, k[i + 1], keep);
		}
        
        block s_last = s & notThreeBlock;
        uint128_t s_converted;
        memcpy((uint8_t*)(&s_converted), (uint8_t*)(&s_last), sizeof(block));
        uint8_t t_last = *(uint8_t *)(&s) & 1;
        uint128_t sign = (party_id == 1)?-1:+1;

		if(gout_bitsize == 1){
            res_share[0] = s_converted ^ ((uint128_t)t_last & g[0]);
		}
		else{
            res_share[0] = sign*(s_converted + ((uint128_t)t_last * g[0]));
		}
        res_share[0] = res_share[0] % modulus;

		return s;
	}
    
    // party_id is either 0 or 1
    block DPFServer::traverseOneDPF(const block& s, const block& cw, const u8 &keep)

	{
        std::array<block, 2> tau, stcw;
		auto ss = s & notThreeBlock;
		aes0.ecbEncBlock(ss, tau[0]);
		aes1.ecbEncBlock(ss, tau[1]);
		tau[0] = tau[0] ^ ss;
		tau[1] = tau[1] ^ ss;

		const auto scw = (cw & notThreeBlock);
		const auto mask = zeroAndAllOne[lsb(s)];

		auto d0 = ((cw >> 1) & OneBlock);
		auto d1 = (cw & OneBlock);
		auto c0 = ((scw ^ d0) & mask);
		auto c1 = ((scw ^ d1) & mask);

		stcw[0] = c0 ^ tau[0];
		stcw[1] = c1 ^ tau[1];

		return stcw[keep];
	}

    void DPFServer::contigEvalOneDPFLarge(uint128_t* res, block* k, uint128_t* g, block s,
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
        s = traverseOneDPF(s, k[curDepth], keep);
        //STOP_TIMER("DPF traversal");

        if(curDepth == depth){
            block s_last = s & notThreeBlock;
            uint128_t s_converted;
            memcpy((uint8_t*)(&s_converted), (uint8_t*)(&s_last), sizeof(block));
            uint8_t t_last = *(uint8_t *)(&s) & 1;
            uint128_t sign = (party_id == 1)?-1:+1;

            if(gout_bitsize == 1){
                res[0] = s_converted ^ ((uint128_t)t_last & g[0]);
            }
            else{
                res[0] = sign*(s_converted + ((uint128_t)t_last * g[0]));
            }
            res[0] %= modulus;
        }
        
        // Left subchild recursive
        contigEvalOneDPFLarge(res, k, g, s, depth, curDepth + 1, start, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        if(range > 1){
            // Right subchild recursive
            contigEvalOneDPFLarge(res + range/2, k, g, s, depth, curDepth + 1, start + range/2, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        }
        

        return;
	}

    // Contiguous domain evaluation
    void DPFServer::ContigDomainDPFLargeOutOptimized(uint128_t* res, block* k, uint128_t* g, 
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
        u64 ctr = 0;
        
        // depth 0 part
        block s = k[0];
      
        //INIT_TIMER;
        //START_TIMER; 
        // Left 
        contigEvalOneDPFLarge(res, k, g, s, depth, curDepth, start, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        // Right
        contigEvalOneDPFLarge(res + range/2, k, g, s, depth, curDepth, start + range/2, range/2, end, party_id, gout_bitsize, use_modulus, modulus, ctr);
        //STOP_TIMER("DPF Recursion");
    }

}
#endif
