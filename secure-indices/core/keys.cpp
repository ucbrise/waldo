#include "keys.h"

// typedef unsigned __int128 bgi_uint128_t;

namespace dorydb{

    clkey::clkey(){
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
    }

    clkey::~clkey(){
        if(dpf_size > 0){
            delete[] dpf_key0;
            delete[] dpf_key1;
            delete[] dpf_g0;
            delete[] dpf_g1;
            if(malicious){
                delete[] dpf_mac_key0;
                delete[] dpf_mac_key1;
                delete[] dpf_mac_g0;
                delete[] dpf_mac_g1;
            }
        }
        if(dcf_size > 0){
            delete[] dcf_key0;
            delete[] dcf_key1;
            delete[] dcf_v0;
            delete[] dcf_v1;
            if(malicious){
                delete[] dcf_mac_key0;
                delete[] dcf_mac_key1;
                delete[] dcf_mac_v0;
                delete[] dcf_mac_v1;
            }
        }
    }

    void clkey::dpf_generate(uint128_t punctured_x, uint128_t payload, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool malicious, uint128_t alpha){
        this->malicious = malicious;
        assert(!(alpha == 0 && malicious));
        this->dpf_size = depth + 1;
        this->dpf_key0 = new block[depth + 1];
        this->dpf_key1 = new block[depth + 1];
        this->dpf_g0 = new uint128_t[1];
        this->dpf_g1 = new uint128_t[1];
        // keygen
        DPFClient::keyGenDPF(punctured_x*128, payload, prng.get<osuCrypto::block>(), dpf_key0, dpf_g0, dpf_key1, dpf_g1, depth, gout_bitsize, use_modulus, modulus); 
        if(malicious){
            this->dpf_mac_key0 = new block[depth + 1];
            this->dpf_mac_key1 = new block[depth + 1];
            this->dpf_mac_g0 = new uint128_t[1];
            this->dpf_mac_g1 = new uint128_t[1];
            // keygen
            DPFClient::keyGenDPF(punctured_x*128, alpha*payload, prng.get<osuCrypto::block>(), dpf_mac_key0, dpf_mac_g0, dpf_mac_key1, dpf_mac_g1, depth, gout_bitsize, use_modulus, modulus); 
        }
    }

    void clkey::dcf_generate(uint128_t punctured_x, uint128_t payload, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool greaterThan, bool striclyGT, bool malicious, uint128_t alpha){
        this->malicious = malicious;
        assert(!(alpha == 0 && malicious));
        // mallocs
        this->dcf_size = depth + 1;
        this->dcf_key0 = new block[depth + 1];
        this->dcf_key1 = new block[depth + 1];
        this->dcf_v0 = new uint128_t[depth + 1];
        this->dcf_v1 = new uint128_t[depth + 1];
        uint128_t minus_one = -1;
        // keygen
        if(greaterThan){
            // Assumption: whenever greaterThan is set, the client is querying for double-sided range.
            // use IC
            DCFClient::keyGenDCFMAC((punctured_x+1)*128, minus_one*payload, prng.get<osuCrypto::block>(), dcf_key0, dcf_v0, dcf_key1, dcf_v1, depth, gout_bitsize, use_modulus, modulus); 
        }
        else{
            // IC not used
            DCFClient::keyGenDCFMAC(punctured_x*128, payload, prng.get<osuCrypto::block>(), dcf_key0, dcf_v0, dcf_key1, dcf_v1, depth, gout_bitsize, use_modulus, modulus, striclyGT); 
        }
        if(malicious){
            this->dcf_mac_key0 = new block[depth + 1];
            this->dcf_mac_key1 = new block[depth + 1];
            this->dcf_mac_v0 = new uint128_t[depth + 1];
            this->dcf_mac_v1 = new uint128_t[depth + 1];
            // keygen
            if(greaterThan){
                // Assumption: whenever greaterThan is set, the client is querying for double-sided range.
                // use IC
                DCFClient::keyGenDCFMAC((punctured_x+1)*128, minus_one*alpha*payload, prng.get<osuCrypto::block>(), dcf_mac_key0, dcf_mac_v0, dcf_mac_key1, dcf_mac_v1, depth, gout_bitsize, use_modulus, modulus); 
            }
            else{
                DCFClient::keyGenDCFMAC(punctured_x*128, alpha*payload, prng.get<osuCrypto::block>(), dcf_mac_key0, dcf_mac_v0, dcf_mac_key1, dcf_mac_v1, depth, gout_bitsize, use_modulus, modulus, striclyGT); 
            }
        }
    }

    uint64_t clkey::get_keysize(){
        assert((dpf_size == 0) || (dcf_size == 0));
        
        uint64_t mac_factor = (malicious)? 2 : 1;
        
        if(dpf_size > 0){
            return mac_factor * (this->dpf_size*(sizeof(block)) + sizeof(uint128_t));
        }
        else{
            return mac_factor * (this->dcf_size*(sizeof(block) + sizeof(uint128_t)));
        }
    }
    
    void clkey::dcf_serialize(uint64_t depth, uint8_t *key0, uint8_t *key1) {
        memcpy(key0, dcf_key0, sizeof(block) * (depth + 1));
        memcpy(key0 + (sizeof(block) * (depth + 1)), dcf_v0, sizeof(uint128_t) * (depth + 1));

        if(malicious){
            memcpy(key0 + (depth + 1)*(sizeof(block) + sizeof(uint128_t)), dcf_mac_key0, sizeof(block) * (depth + 1));
            memcpy(key0 + (depth + 1)*(sizeof(block) + sizeof(uint128_t)) + (sizeof(block) * (depth + 1)), dcf_mac_v0, sizeof(uint128_t) * (depth + 1));
        }
        
        memcpy(key1, dcf_key1, sizeof(block) * (depth + 1));
        memcpy(key1 + (sizeof(block) * (depth + 1)), dcf_v1, sizeof(uint128_t) * (depth + 1));
        
        if(malicious){
            memcpy(key1 + (depth + 1)*(sizeof(block) + sizeof(uint128_t)), dcf_mac_key1, sizeof(block) * (depth + 1));
            memcpy(key1 + (depth + 1)*(sizeof(block) + sizeof(uint128_t)) + (sizeof(block) * (depth + 1)), dcf_mac_v1, sizeof(uint128_t) * (depth + 1));
        }
    }

    void clkey::dpf_serialize(uint64_t depth, uint8_t *key0, uint8_t *key1) {
        memcpy(key0, dpf_key0, sizeof(block) * (depth + 1));
        memcpy(key0 + (sizeof(block) * (depth + 1)), dpf_g0, sizeof(uint128_t));
        
        if(malicious){
            memcpy(key0 + (depth + 1)*(sizeof(block)) + sizeof(uint128_t), dpf_mac_key0, sizeof(block) * (depth + 1));
            memcpy(key0 + (depth + 1)*(sizeof(block)) + sizeof(uint128_t) + (sizeof(block) * (depth + 1)), dpf_mac_g0, sizeof(uint128_t));
        }
        
        memcpy(key1, dpf_key1, sizeof(block) * (depth + 1));
        memcpy(key1 + (sizeof(block) * (depth + 1)), dpf_g1, sizeof(uint128_t));
        
        if(malicious){
            memcpy(key1 + (depth + 1)*(sizeof(block)) + sizeof(uint128_t), dpf_mac_key1, sizeof(block) * (depth + 1));
            memcpy(key1 + (depth + 1)*(sizeof(block)) + sizeof(uint128_t) + (sizeof(block) * (depth + 1)), dpf_mac_g1, sizeof(uint128_t));
        }
    }

    svkey::svkey(bool malicious){
        this->malicious = malicious;
    }

    svkey::~svkey(){
        if(dpf_size > 0){
            delete[] dpf_key;
            delete[] dpf_g;
            if(malicious){
                delete[] dpf_mac_key;
                delete[] dpf_mac_g;
            }
        }
        if(dcf_size > 0){
            delete[] dcf_key;
            delete[] dcf_v;
            if(malicious){
                delete[] dcf_mac_key;
                delete[] dcf_mac_v;
            }
        }
    }
    
    uint64_t svkey::get_keysize(){
        assert((dpf_size == 0) || (dcf_size == 0));
        
        uint64_t mac_factor = (malicious)? 2 : 1;
        
        if(dpf_size > 0){
            return mac_factor * (this->dpf_size*(sizeof(block)) + sizeof(uint128_t));
        }
        else{
            return mac_factor * (this->dcf_size*(sizeof(block) + sizeof(uint128_t)));
        }
    }


    uint128_t svkey::dcf_eval(uint128_t input_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        assert(malicious == false && "Not implemented");
        assert(init == true && "First copy the keys from client to server");
        assert(role < 2 && "Eval role can only be EVAL0 or EVAL1");
        return DCFServer::evalOneDCFMAC(input_x*128, dcf_key, dcf_v, depth, role, gout_bitsize, use_modulus, modulus);
    }
    
    void svkey::dcf_eval(uint128_t res, uint128_t input_x, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        assert(malicious == false && "Not implemented");
        assert(init == true && "First copy the keys from client to server");
        assert(role < 2 && "Eval role can only be EVAL0 or EVAL1");
        res = DCFServer::evalOneDCFMAC(input_x*128, dcf_key, dcf_v, depth, role, gout_bitsize, use_modulus, modulus);
    }

    // Calls to unoptimized version
    void svkey::dcf_evalfull(uint128_t* res, uint64_t depth, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus){
        assert(malicious == false && "Not implemented");
        assert(init == true && "First copy the keys from client to server");
        assert(role < 2 && "Eval role can only be EVAL0 or EVAL1");
        std::cout<<"Warning: using naive EvalAll function. Use dcf_eval_contig for optimized version"<<std::endl;
        DCFServer::FullDomainDCFLargeOut(res, dcf_key, dcf_v, depth, role, gout_bitsize, use_modulus, modulus);
    }

    // Calls to optimized version    
    void svkey::dpf_eval_contig(uint128_t* res, uint64_t depth, uint64_t start, uint64_t end, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool malicious_run){
        assert(init == true && "First copy the keys from client to server");
        assert(role < 2 && "Eval role can only be EVAL0 or EVAL1");
        if(malicious_run){
            DPFServer::ContigDomainDPFLargeOutOptimized(res, dpf_mac_key, dpf_mac_g, depth, start, end, role, gout_bitsize, use_modulus, modulus);
        }
        else{
            DPFServer::ContigDomainDPFLargeOutOptimized(res, dpf_key, dpf_g, depth, start, end, role, gout_bitsize, use_modulus, modulus);
        }
    }

    void svkey::dcf_eval_contig(uint128_t* res, uint64_t depth, uint64_t start, uint64_t end, uint64_t gout_bitsize, bool use_modulus, uint128_t modulus, bool malicious_run){
        assert(init == true && "First copy the keys from client to server");
        assert(role < 2 && "Eval role can only be EVAL0 or EVAL1");
        if(malicious_run){
            DCFServer::ContigDomainDCFLargeOutOptimized(res, dcf_mac_key, dcf_mac_v, depth, start, end, role, gout_bitsize, use_modulus, modulus);
        }
        else{
            DCFServer::ContigDomainDCFLargeOutOptimized(res, dcf_key, dcf_v, depth, start, end, role, gout_bitsize, use_modulus, modulus);
        }
    }

    void svkey::dcf_deserialize(uint64_t depth, const uint8_t *key) {
        dcf_key = (block *)malloc(sizeof(block) * (depth + 1));
        dcf_v = (uint128_t *)malloc(sizeof(uint128_t) * (depth + 1));
        memcpy(dcf_key, key, sizeof(block) * (depth + 1));
        memcpy(dcf_v, key + (sizeof(block) * (depth + 1)), sizeof(uint128_t) * (depth + 1));

        if(malicious){
            dcf_mac_key = (block *)malloc(sizeof(block) * (depth + 1));
            dcf_mac_v = (uint128_t *)malloc(sizeof(uint128_t) * (depth + 1));
            memcpy(dcf_mac_key, key + (depth + 1)*(sizeof(block) + sizeof(uint128_t)), sizeof(block) * (depth + 1));
            memcpy(dcf_mac_v, key + (depth + 1)*(sizeof(block) + sizeof(uint128_t)) + (sizeof(block) * (depth + 1)), sizeof(uint128_t) * (depth + 1));
        }
    }

    void svkey::dpf_deserialize(uint64_t depth, const uint8_t *key) {
        dpf_key = (block *)malloc(sizeof(block) * (depth + 1));
        dpf_g = (uint128_t *)malloc(sizeof(uint128_t));
        memcpy(dpf_key, key, sizeof(block) * (depth + 1));
        memcpy(dpf_g, key + (sizeof(block) * (depth + 1)), sizeof(uint128_t));

        if(malicious){
            dpf_mac_key = (block *)malloc(sizeof(block) * (depth + 1));
            dpf_mac_g = (uint128_t *)malloc(sizeof(uint128_t));
            memcpy(dpf_mac_key, key + (depth + 1)*(sizeof(block)) + sizeof(uint128_t), sizeof(block) * (depth + 1));
            memcpy(dpf_mac_g, key + (depth + 1)*(sizeof(block)) + sizeof(uint128_t) + (sizeof(block) * (depth + 1)), sizeof(uint128_t));
        }
    }

}
