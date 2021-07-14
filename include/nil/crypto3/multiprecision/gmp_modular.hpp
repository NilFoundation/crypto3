//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef _MULTIPRECISION_GMP_MODULAR_HPP
#define _MULTIPRECISION_GMP_MODULAR_HPP

#include <nil/crypto3/multiprecision/gmp.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params_gmp.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            typedef modular_params<gmp_int> mpz_int_mod_params;
            typedef number<modular_adaptor<gmp_int>> mpz_int_mod;
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil
#endif    //_MULTIPRECISION_GMP_MODULAR_HPP
