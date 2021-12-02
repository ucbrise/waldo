#include "keys.h"
#include "AggTree.h"
#include "DPFTable.h"
#include "DCFTable.h"

#ifndef PLAYERS_H__
#define PLAYERS_H__

#define CLIENT 0
#define SERVER1 1
#define SERVER2 2
#define SERVER3 3

namespace dorydb{
    using namespace osuCrypto; 
    class server;

    enum key_type { DPF_Table, DCF_Table, AGG_Tree };

    class client{
        public:
            // random gen
            block seed;
            PRNG prng;
            
            // server refs
            server* sv[3];

            // keys
            // stored by id and index type
            std::vector<clkey*> dpf_table_keys = {};

            // oracles for secure indices
            AggTreeIndexClient* agg_tree_oracle;
            DPFTableClient* dpf_table_oracle;
            DCFTableClient* dcf_table_oracle;

            client();
            ~client();
            
    };

    class server{
        public:
            // random gen
            block seed;
            PRNG prng;

            // which one of the tree servers
            int id;

            // client ref
            client* cl;
            
            // keys
            // stored by id and index type
            std::vector<svkey*> dpf_table_keys = {};
            
            // oracles for secure indices
            AggTreeIndexServer* agg_tree_oracle;
            DPFTableServer* dpf_table_oracle;
            DCFTableServer* dcf_table_oracle;

            server(int id);
            ~server();
            void add_keys(key_type ktype, svkey* k);
    };
}
#endif


