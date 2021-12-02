#include "fss-core/DCF-source/DCFClient.h"
#include "fss-core/DCF-source/DCFServer.h"
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

void test_bit_DCF(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 64;

    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint64_t>();
    punctured_index = alpha*mod;
	uint8_t payload = 1;

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint8_t* v0 = new uint8_t[depth + 1];
    uint8_t* v1 = new uint8_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<+payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCF(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint8_t* res_final = new uint8_t[2];
	cout<<"Running servers now"<<endl;
    
    uint8_t one = 1;
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
            res_final[0] = osuCrypto::DCFServer::evalOneDCF(index_input, key0, v0, depth); 
            // Server 2
            res_final[1] = osuCrypto::DCFServer::evalOneDCF(index_input, key1, v1, depth); 
#ifdef PRINT
            cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
                <<((res_final[0] ^ res_final[1])&one)<<endl;
#endif
            if(index_input < punctured_index){
                assert((res_final[0]&one) == ((payload ^ res_final[1])&one));
            }
            else{
                assert((res_final[0]&one) == (res_final[1]&one));
            }
        }
    }
    cout<<GREEN<<"Bit DCF is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
}

void test_MAC_DCF(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 64;
    uint64_t gout_bitsize = 123;
    uint128_t one = 1;
    uint128_t group_mod = (one<<gout_bitsize);
    
    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint64_t>();
    punctured_index = alpha*mod;
	uint128_t payload = prng.get<uint64_t>();

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint128_t* v0 = new uint128_t[depth + 1];
    uint128_t* v1 = new uint128_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCFMAC(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth, gout_bitsize, true, group_mod);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res_final = new uint128_t[2];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;
    cout<<"Running "<<reps<<" reps"<<endl;
    for(int i=0; i<reps; i++){
        res_final[0] = osuCrypto::DCFServer::evalOneDCFMAC(0, key0, v0, depth, EVAL0, gout_bitsize, true, group_mod);
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
            res_final[0] = osuCrypto::DCFServer::evalOneDCFMAC(index_input, key0, v0, depth, EVAL0, gout_bitsize, true, group_mod); 
            // Server 2
            res_final[1] = osuCrypto::DCFServer::evalOneDCFMAC(index_input, key1, v1, depth, EVAL1, gout_bitsize, true, group_mod); 
#ifdef PRINT
            cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
                <<((res_final[0] + res_final[1]) % group_mod)<<endl;
#endif
            if(index_input < punctured_index){
                assert(((res_final[0] + res_final[1]) % group_mod) == payload);
            }
            else{
                assert(((res_final[0] + res_final[1]) % group_mod) == 0);
            }
        }
    }

    cout<<GREEN<<"MAC DCF is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
}

void test_fullDomain_DCF(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 16;
    assert((depth < 20) && "Cannot support very large domains due to memory constraints");
    uint64_t domain_size = (1ULL<<depth);
    uint64_t gout_bitsize = 123;
    uint128_t one = 1;
    uint128_t group_mod = (one<<gout_bitsize);
    
    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint16_t>();
    punctured_index = alpha*mod;
    uint8_t payload = 1;
	uint128_t payload_MAC = prng.get<uint64_t>();

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint8_t* v0 = new uint8_t[depth + 1];
    uint8_t* v1 = new uint8_t[depth + 1];
	osuCrypto::block* key0_MAC = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1_MAC = new osuCrypto::block[depth + 1];
	uint128_t* v0_MAC = new uint128_t[depth + 1];
    uint128_t* v1_MAC = new uint128_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payloads (bit, MAC) = "<<+payload<<" and "<<payload_MAC<<endl;
    
    osuCrypto::DCFClient::keyGenDCF(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth);
    osuCrypto::DCFClient::keyGenDCFMAC(punctured_index, payload_MAC, prng.get<osuCrypto::block>(), key0_MAC, v0_MAC, key1_MAC, v1_MAC, depth, gout_bitsize, true, group_mod);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint8_t* res_bitmap = new uint8_t[2*domain_size];
    uint128_t* res_MAC = new uint128_t[2*domain_size];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;
    osuCrypto::DCFServer::FullDomainDCF(res_bitmap, res_MAC, key0, v0, true, key0_MAC, v0_MAC, 
            depth, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DCFServer::FullDomainDCF(res_bitmap + domain_size, res_MAC + domain_size, 
            key1, v1, true, key1_MAC, v1_MAC, 
            depth, EVAL1, gout_bitsize, true, group_mod);
    STOP_TIMER("Total evaluation time of both servers combined [libPSI]");

    cout<<"Checking correctness..."<<endl;
    uint8_t one_val = 1;
    for(uint64_t i=0; i<domain_size; i++){
        //cout<<i<<endl;
        uint128_t index_input = i*mod;
        // For bit DCFs
#ifdef PRINT
        cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
            <<((res_bitmap[i] ^ res_bitmap[domain_size + i])&one_val)<<endl;
        cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
            <<((res_MAC[i] + res_MAC[domain_size + i]) % group_mod)<<endl;
#endif
        if(index_input < punctured_index){
            assert((res_bitmap[i]&one_val) == ((payload ^ res_bitmap[domain_size + i])&one_val));
        }
        else{
            assert((res_bitmap[i]&one_val) == (res_bitmap[domain_size + i]&one_val));
        }
        // For MAC DCFs
        if(index_input < punctured_index){
            assert(((res_MAC[i] + res_MAC[domain_size + i]) % group_mod) == payload_MAC);
        }
        else{
            assert(((res_MAC[i] + res_MAC[domain_size + i]) % group_mod) == 0);
        }
    }
    cout<<GREEN<<"FullDomain DCF (bitmap with MAC) is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
    delete[] key0_MAC;
    delete[] key1_MAC;
    delete[] v0_MAC;
    delete[] v1_MAC;
    delete[] res_bitmap;
    delete[] res_MAC;
}

void test_fullDomainOptimized_DCF(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 20;
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
	uint128_t* v0 = new uint128_t[depth + 1];
    uint128_t* v1 = new uint128_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCFMAC(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth, gout_bitsize, true, group_mod);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res_naive = new uint128_t[2*domain_size];
    uint128_t* res = new uint128_t[2*domain_size];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;

    // Running naive full domain for runtime comparison
    osuCrypto::DCFServer::FullDomainDCFLargeOut(res_naive, key0, v0, 
            depth, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DCFServer::FullDomainDCFLargeOut(res_naive + domain_size, key1, v1, 
            depth, EVAL1, gout_bitsize, true, group_mod);
    STOP_TIMER("- Naive: Total evaluation time of both servers combined [libPSI]");

    START_TIMER;
    // Optimized EvalAll
    osuCrypto::DCFServer::ContigDomainDCFLargeOutOptimized(res, key0, v0, 
            depth, 0, domain_size-1, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DCFServer::ContigDomainDCFLargeOutOptimized(res + domain_size, key1, v1, 
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
        if(index_input < punctured_index){
            assert(((res[i] + res[domain_size + i]) % group_mod) == payload);
        }
        else{
            assert(((res[i] + res[domain_size + i]) % group_mod) == 0);
        }
    }
    cout<<GREEN<<"OptimizedFullDomain DCF large is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
    delete[] res_naive;
    delete[] res;
}

void test_bit_DCF_GT(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 64;

    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint64_t>();
    punctured_index = alpha*mod;
	uint8_t payload = 1;

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint8_t* v0 = new uint8_t[depth + 1];
    uint8_t* v1 = new uint8_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<+payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCF(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth, true);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint8_t* res_final = new uint8_t[2];
	cout<<"Running servers now"<<endl;
    
    uint8_t one = 1;
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
            res_final[0] = osuCrypto::DCFServer::evalOneDCF(index_input, key0, v0, depth); 
            // Server 2
            res_final[1] = osuCrypto::DCFServer::evalOneDCF(index_input, key1, v1, depth); 
#ifdef PRINT
            cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
                <<((res_final[0] ^ res_final[1])&one)<<endl;
#endif
            if(index_input > punctured_index){
                assert((res_final[0]&one) == ((payload ^ res_final[1])&one));
            }
            else{
                assert((res_final[0]&one) == (res_final[1]&one));
            }
        }
    }
    cout<<GREEN<<"Bit DCF GT is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
}

void test_MAC_DCF_GT(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 64;
    uint64_t gout_bitsize = 123;
    uint128_t one = 1;
    uint128_t group_mod = (one<<gout_bitsize);
    
    // Seeding PRG
    srand(time(NULL));
    seed = osuCrypto::toBlock(rand(), rand());
    prng.SetSeed(seed);

    alpha = prng.get<uint64_t>();
    punctured_index = alpha*mod;
	uint128_t payload = prng.get<uint64_t>();

	osuCrypto::block* key0 = new osuCrypto::block[depth + 1];
	osuCrypto::block* key1 = new osuCrypto::block[depth + 1];
	uint128_t* v0 = new uint128_t[depth + 1];
    uint128_t* v1 = new uint128_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCFMAC(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth, gout_bitsize, true, group_mod, true);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res_final = new uint128_t[2];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;
    cout<<"Running "<<reps<<" reps"<<endl;
    for(int i=0; i<reps; i++){
        res_final[0] = osuCrypto::DCFServer::evalOneDCFMAC(0, key0, v0, depth, EVAL0, gout_bitsize, true, group_mod);
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
            res_final[0] = osuCrypto::DCFServer::evalOneDCFMAC(index_input, key0, v0, depth, EVAL0, gout_bitsize, true, group_mod); 
            // Server 2
            res_final[1] = osuCrypto::DCFServer::evalOneDCFMAC(index_input, key1, v1, depth, EVAL1, gout_bitsize, true, group_mod); 
#ifdef PRINT
            cout<<"alpha = "<<alpha<<" | query = "<<i<<" | output = "
                <<((res_final[0] + res_final[1]) % group_mod)<<endl;
#endif
            if(index_input > punctured_index){
                assert(((res_final[0] + res_final[1]) % group_mod) == payload);
            }
            else{
                assert(((res_final[0] + res_final[1]) % group_mod) == 0);
            }
        }
    }

    cout<<GREEN<<"MAC DCF GT is correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
}

void test_fullDomainOptimized_DCF_GT(){
	cout<<"Running DCF Dealer"<<endl;
    depth = 16;
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
	uint128_t* v0 = new uint128_t[depth + 1];
    uint128_t* v1 = new uint128_t[depth + 1];
    cout<<"======= Comparison Function Description ======="<<endl;
	cout<<"alpha = "<<alpha<<" | payload = "<<payload<<endl;
    
    osuCrypto::DCFClient::keyGenDCFMAC(punctured_index, payload, prng.get<osuCrypto::block>(), key0, v0, key1, v1, depth, gout_bitsize, true, group_mod, true);

    cout<<"DCF keys generated"<<endl;
	cout<<"Emulating send to the servers"<<endl;

    uint128_t* res_naive = new uint128_t[2*domain_size];
    uint128_t* res = new uint128_t[2*domain_size];
	cout<<"Running servers now"<<endl;
    
    INIT_TIMER;
    START_TIMER;

    // Running naive full domain for runtime comparison
    osuCrypto::DCFServer::FullDomainDCFLargeOut(res_naive, key0, v0, 
            depth, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DCFServer::FullDomainDCFLargeOut(res_naive + domain_size, key1, v1, 
            depth, EVAL1, gout_bitsize, true, group_mod);
    STOP_TIMER("- Naive: Total evaluation time of both servers combined [libPSI]");

    START_TIMER;
    // Optimized EvalAll
    osuCrypto::DCFServer::ContigDomainDCFLargeOutOptimized(res, key0, v0, 
            depth, 0, domain_size-1, EVAL0, gout_bitsize, true, group_mod);
    osuCrypto::DCFServer::ContigDomainDCFLargeOutOptimized(res + domain_size, key1, v1, 
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
        if(index_input > punctured_index){
            //assert(((res_naive[i] + res_naive[domain_size + i]) % group_mod) == payload);
            assert(((res[i] + res[domain_size + i]) % group_mod) == payload);
        }
        else{
            //assert(((res_naive[i] + res_naive[domain_size + i]) % group_mod) == 0);
            assert(((res[i] + res[domain_size + i]) % group_mod) == 0);
        }
    }
    cout<<GREEN<<"OptimizedFullDomain DCF GT large is correct!"<<RESET<<endl;
    //cout<<GREEN<<"OptimizedFullDomain and NaiveFullDomain DCF large are both correct!"<<RESET<<endl;
    delete[] key0;
    delete[] key1;
    delete[] v0;
    delete[] v1;
    delete[] res_naive;
    delete[] res;
}

int main(int argc, char** argv){
    cout<<BLUE<<"Running test on Bit DCF..."<<RESET<<endl;
    test_bit_DCF();
    cout<<BLUE<<"Running test on MAC DCF..."<<RESET<<endl;
    test_MAC_DCF();
    cout<<BLUE<<"Running test on FullDomain DCF..."<<RESET<<endl;
    test_fullDomain_DCF();
    cout<<BLUE<<"Running test on FullDomain DCF Optimized..."<<RESET<<endl;
    test_fullDomainOptimized_DCF();
    cout<<BLUE<<"Running test on Bit DCF GT..."<<RESET<<endl;
    test_bit_DCF_GT();
    cout<<BLUE<<"Running test on MAC DCF GT..."<<RESET<<endl;
    test_MAC_DCF_GT();
    cout<<BLUE<<"Running test on FullDomain DCF GT Optimized..."<<RESET<<endl;
    test_fullDomainOptimized_DCF_GT();
	return 0;
}
