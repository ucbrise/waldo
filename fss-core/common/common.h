#pragma once
#include "defines.h"

namespace osuCrypto
{
    // Taken from https://github.com/mc2-project/delphi/blob/master/rust/protocols-sys/c++/src/lib/conv2d.h
    /* Helper function for performing modulo with possibly negative numbers */
    inline int128_t neg_mod(int128_t val, int128_t mod) {
        return ((val % mod) + mod) % mod;
    }

    inline int128_t get_signed(uint128_t val) {
        uint128_t mid_pt = ((uint128_t)(-1))/2 + 1;
        // cast from boost::uint128_t to boost::int128_t is not working
        // so implementing one here
        // reverse cast from signed to unsigned is working (skipping that)
        return (val >= mid_pt) ? ((int128_t)(val - mid_pt) - mid_pt) : val;
    }

    inline uint128_t neg_mod(uint128_t val, uint128_t mod) {
        int128_t val_s = get_signed(val);
        // get_signed not needed for mod since it is always +ve
        // Assumption: mod < mid_pt (see get_signed).
        int128_t mod_s = mod;
        return (uint128_t) (((val_s % mod_s) + mod_s) % mod_s);
    }

}
