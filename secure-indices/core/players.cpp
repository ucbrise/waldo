#include "players.h"
#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"

namespace dorydb
{

    client::client()
    {
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
    }

    client::~client()
    {
        delete agg_tree_oracle;
        delete dpf_table_oracle;
        delete dcf_table_oracle;
    }

    server::server(int id)
    {
        srand(time(NULL));
        this->seed = toBlock(rand(), rand());
        this->prng.SetSeed(seed);
        this->id = id;
    }

    server::~server()
    {
        delete agg_tree_oracle;
        delete dpf_table_oracle;
        delete dcf_table_oracle;
    }

    void server::add_keys(key_type ktype, svkey *k)
    {
        switch (ktype)
        {
        case DPF_Table:
            dpf_table_oracle->key.push_back(k);
            break;
        case DCF_Table:
            dcf_table_oracle->key.push_back(k);
            break;
        case AGG_Tree:
            agg_tree_oracle->key.push_back(k);
            break;
        }
    }
}
