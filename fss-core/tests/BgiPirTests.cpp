#include "BgiPirTests.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/TestCollection.h>
#include "utils/timer.h"

using namespace osuCrypto;

u64 crude_log(u64 x)
{
    for (u64 i=0; i<x; i++){
        if((1ULL << i) == x){
            return i;
        }
    }
    return -1;
}

void BgiPir_FullDomain_bench()
{
#ifdef ENABLE_DRRN_PSI
	//std::vector<std::array<u64, 2>> params{ {2,1}, {2, 6}, {5, 1}, {5, 5}, {5,8} };
	std::vector<std::array<u64, 1>> params{ {8}, {10}, {12}, {14}, {16}, {18}, {20}, {22}, {24}}; // log(domain size), OutputGroupBlockCount, Gout bits
    
    u64 ctr = 0;
	for (auto param : params)
	{
        ctr++;
		//u64 depth = param[0], groupBlkSize = param[1];
		//u64 domain = (1ull << depth) * groupBlkSize * 128;
		//u64 trials = 10;
        //groupBlkSize = (Gout bits / 128). How many blocks of 128-bits does Gout need.
        //If your Gout size is 1 bit, then you have to accordingly reduce depth.
        //TODO: I think thet are using a byte to store a bit. So, you cannot 
        //pack more than 16 bits of your Gout in a 128-bit block.
        //Below formulas need some work.
        //TODO: Findings - They always truncate the last 3 levels, so 
        //the max Gout size can be 16. Even if you Gout size is 1, you still
        //can only pack 8 bits in 128 bit output mask because that is how it 
        //is implemented. Gout = 1 or 16 is the same here basically.
        //
        //------------------------------------------------------------
        // Variables and their meaning: 
        // This function performs a PIR instance where you fetch 
        // secret shares of a database entry depending on shares 
        // of index (x) that both parties hold.
        // 1. Depth: This is the truncated depth, i.e. the actual FSS tree
        // depth that you want (actual depth - truncated subtree depth).
        // 2. Domain: domain size of input, i.e. how many elements to do
        // evalAll on.
        // 3. groupBlkSize: This is Gout size in terms of no. of 128-bit
        // blocks needed. This is 1 for Gout <= 128, then 2 for up to 256.
        // The code has different tree traversal logic for depth < 3 
        // and >+ 3.
        // The code does max packing, i.e. each leaf handles 128 data 
        // entries, where masks are each 16-bits long and there are 8
        // such masks per leaf.
        // bIdx refers to the index of the bit (out of 128) that is 
        // being processed in the leaf.
        // bitIdx refers to the index of the mask (out of 8) corresponding
        // to BIdx.
        // byteIdx refers to the index inside the mask (out of 16) corresponding
        // to bIdx.
        //------------------------------------------------------------
        //

        u64 domain = (1ULL<<param[0]), groupBlkSize = 1, goutBits = 1;
        u64 depth = param[0] - crude_log((128 * groupBlkSize) / goutBits);
		u64 trials = 1;

        
        std::cout << "\n<><><><><><><><><><> Test #" << ctr << " [Truncating last 7 levels of tree]\n" <<
            std::endl;
        std::cout << "Params inside FullDomainEval: " <<
            "Depth = " << depth << ", Domain = " << domain << std::endl;
        //std::cout << "Params inside FullDomainEval: " <<
            //"Depth = " << depth << ", GroupBlockSize = " << groupBlkSize << 
            //", Domain = " << domain << ", trials = " << trials << std::endl;

		std::vector<block> data(domain);
		for (u64 i = 0; i < data.size(); ++i)
			data[i] = toBlock(i);



		std::vector<block> k0(depth + 1), k1(depth + 1);
		std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

		PRNG prng(ZeroBlock);
		for (u64 i = 0; i < trials; ++i)
		{
			//i = 1024;

			//for (u64 j = 0; j < 2; ++j) //TODO: What is j?
            for (u64 j = 1; j < 2; ++j) //TODO: What is j?
			{
				auto idx = (i + j * prng.get<int>()) % domain;
                std::cout << "Punctured Index is " << idx << std::endl;
                INIT_TIMER;
                START_TIMER;
				BgiPirClient::keyGen(idx, toBlock(idx), k0, g0, k1, g1);
                STOP_TIMER("KeyGen");

                START_TIMER;
				auto b0 = BgiPirServer::fullDomain(data, k0, g0);
				STOP_TIMER("P0 FullDomainEval");
                START_TIMER;
                auto b1 = BgiPirServer::fullDomain(data, k1, g1);
                STOP_TIMER("P1 FullDomainEval");

				if (neq(b0 ^ b1, data[idx]))
				{
					//auto vv = bv0 ^ bv1;
					std::cout << "target " << data[idx] << " " << idx <<
						"\n  " << (b0^b1) << "\n = " << b0 << " ^ " << b1 <<
						//"\n   weight " << vv.hammingWeight() <<
						//"\n vv[target] = " << vv[idx] <<
						std::endl;
					throw std::runtime_error(LOCATION);
				}

			}
		}
	}
#else
throw UnitTestSkipped("Not enabled");
#endif
}

