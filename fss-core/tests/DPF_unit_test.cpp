#include "fss-core/DPF-source/DPFClient.h"
#include "fss-core/DPF-source/DPFServer.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

using namespace std;
typedef boost::multiprecision::uint128_t uint128_t;

//#define PRINT

// globals
uint64_t depth = 64;
uint64_t alpha = 1; // will be set randomly in the respective functions
uint64_t group_size_blocks = 1;
int reps = 10000;
uint128_t mod = group_size_blocks*128;
uint128_t punctured_index = alpha*mod;
osuCrypto::block seed;
osuCrypto::PRNG prng;

void test_DPF(){
	cout<<"Running DPF Dealer"<<endl;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    //uint128_t group_mod = 2199023190017;
    uint128_t group_mod = (one<<gout_bitsize);
    
    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint64_t>();
    punctured_index = alpha*mod;
    uint128_t payload = prng.get<uint64_t>() % group_mod;

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint128_t* g0 = new uint128_t[group_size_blocks];
    uint128_t* g1 = new uint128_t[group_size_blocks];
    cout<<"======= Point Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DPFClient::keyGenDPF(punctured_index, payload, prng.get<osuCrypto::block>(), key0, g0, key1, g1, depth, gout_bitsize, true, group_mod);

    cout<<"DPF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res_final = new uint128_t[2];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;
    cout<<"Running "<<reps<<" reps"<<endl;
    for(int i=0; i<reps; i++){
        res_final[0] = osuCrypto::DPFServer::evalOneDPF(0, key0, g0, depth, EVAL0, gout_bitsize, true, group_mod);
    }
    STOP_TIMER("Total evaluation time of all reps combined [libPSI]");
    
    uint64_t start_point, end_point;
    for(int l=0; l<3; l++){
        assert((depth > 9) && "Depth should be more than 9 for some test hardcoded params to work");
        if(l == 0){
            // Testing for some points from 0 and so on...
            start_point = 0;
            end_point = (1<<8)-1;
        }
        else if(l == 1){
            //Testing for some points around alpha...
            if(alpha > (1<<7)) start_point = alpha - (1<<7);
            else start_point = 0;
            if(alpha < ((1ULL<<depth) - (1ULL<<7))) end_point = alpha + (1<<7)-1;
            else end_point = -1ULL;
        }
        else{
            // Testing for some points at the end...
            start_point = -(1ULL<<8);
            end_point = -1ULL;
        }
        for(uint64_t i=start_point; i<end_point; i++){
            uint128_t index_input = i*mod;
            // Server 1
            res_final[0] = osuCrypto::DPFServer::evalOneDPF(index_input, key0, g0, depth, EVAL0, gout_bitsize, true, group_mod); 
            // Server 2
            res_final[1] = osuCrypto::DPFServer::evalOneDPF(index_input, key1, g1, depth, EVAL1, gout_bitsize, true, group_mod); 
#ifdef PRINT
            cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
                <<osuCrypto::neg_mod((res_final[0] + res_final[1]), group_mod)<<endl;
#endif
            if(index_input == punctured_index){
                assert(osuCrypto::neg_mod((res_final[0] + res_final[1]), group_mod) == payload);
            }
            else{
                assert(osuCrypto::neg_mod((res_final[0] + res_final[1]), group_mod) == 0);
            }
        }
    }

    cout<<GREEN<<"Single DPF is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] g0;
    delete[] g1;
}

void test_fullDomainOptimized_DPF(){
	cout<<"Running DPF Dealer"<<endl;
    depth = 24;
    assert((depth < 25) && "Cannot support very large domains due to memory constraints");
    uint64_t domain_size = (1ULL<<depth);
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    //uint128_t group_mod = 2199023190017;
    uint128_t group_mod = (one<<gout_bitsize);
    
    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint16_t>() % domain_size;
    punctured_index = alpha*mod;
	uint128_t payload = prng.get<uint64_t>() % group_mod;

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint128_t* g0 = new uint128_t[group_size_blocks];
    uint128_t* g1 = new uint128_t[group_size_blocks];
    cout<<"======= Point Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DPFClient::keyGenDPF(punctured_index, payload, prng.get<osuCrypto::block>(), key0, g0, key1, g1, depth, gout_bitsize, true, group_mod);

    cout<<"DPF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res = new uint128_t[2*domain_size];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;

    // Optimized EvalAll
    osuCrypto::DPFServer::ContigDomainDPFLargeOutOptimized(res, key0, g0, 
            depth, 0, domain_size-1, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DPFServer::ContigDomainDPFLargeOutOptimized(res + domain_size, key1, g1, 
            depth, 0, domain_size-1, EVAL1, gout_bitsize, true, group_mod);
    STOP_TIMER("+ Optim: Total evaluation time of both servers combined [libPSI]");

    cout<<"Checking correctness..."<<endl;
    for(uint64_t i=0; i<domain_size; i++){
        //cout<<i<<endl;
        uint128_t index_input = i*mod;
#ifdef PRINT
        cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
            <<((res[i] + res[domain_size + i]) % group_mod)<<endl;
#endif
        if(index_input == punctured_index){
            assert(((res[i] + res[domain_size + i]) % group_mod) == payload);
        }
        else{
            assert(((res[i] + res[domain_size + i]) % group_mod) == 0);
        }
    }
    cout<<GREEN<<"OptimizedFullDomain DPF large is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] g0;
    delete[] g1;
    delete[] res;
}


int main(int argc, char** argv){
    cout<<BLUE<<"Running test on Single DPF..."<<RESET<<endl;
    test_DPF();
    cout<<BLUE<<"Running test on FullDomain DPF Optimized..."<<RESET<<endl;
    test_fullDomainOptimized_DPF();
	return 0;
}
