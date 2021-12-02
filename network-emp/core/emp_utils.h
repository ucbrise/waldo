#ifndef EMP_UTILS_H__
#define EMP_UTILS_H__

#include <string>
#include <sstream>
#include <cstddef>//https://gcc.gnu.org/gcc-4.9/porting_to.html
#include <iostream>
#include <cassert>

const static int NETWORK_BUFFER_SIZE2 = 1024*32;
const static int NETWORK_BUFFER_SIZE = 1024*16;
//const static int NETWORK_BUFFER_SIZE = 1024*1024;

inline void parse_party_and_port(char ** arg, int * party, int * port) {
	*party = atoi (arg[1]);
	*port = atoi (arg[2]);
}

inline void parse_party_and_port(char ** arg, int argc, int * party, int * port) {
    if (argc == 1)
        assert(false && "ERROR: argc = 1, need two argsm party ID {0,1} and port.");
    *party = atoi (arg[1]);
    *port = atoi (arg[2]);
}

#endif
