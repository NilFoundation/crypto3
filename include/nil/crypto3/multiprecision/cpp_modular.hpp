//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MP_CPP_MODULAR_HPP
#define CRYPTO3_MP_CPP_MODULAR_HPP

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

namespace boost {
    namespace multiprecision {
        namespace backends {

            // Fixed precision unsigned types:
            typedef modular_params<cpp_int_modular_backend<64>> umod_params_params64_t;
            typedef modular_params<cpp_int_modular_backend<128>> umod_params_params128_t;
            typedef modular_params<cpp_int_modular_backend<256>> umod_params256_t;
            typedef modular_params<cpp_int_modular_backend<512>> umod_params512_t;
            typedef modular_params<cpp_int_modular_backend<1024>> umod_params1024_t;
        }
    }   // namespace multiprecision
}   // namespace boost
                    
#endif
