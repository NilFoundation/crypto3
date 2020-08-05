//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN128_INIT_HPP
#define ALGEBRA_FF_BN128_INIT_HPP

#include <nil/algebra/pairing/include/bn.h>

#include <nil/algebra/curves/detail/bn128/bn128_g1.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_g2.hpp>
#include <nil/algebra/curves/detail/bn128/bn128_gt.hpp>

#include <nil/algebra/fields/fp.hpp>

#include <boost/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace algebra {

        const mp_size_t bn128_r_bitcount = 254;
        const mp_size_t bn128_q_bitcount = 254;

        NumberType bn128_modulus_r;
        NumberType bn128_modulus_q;

        class bn128_G1;
        class bn128_G2;
        class bn128_GT;
        typedef bn128_GT bn128_Fq12;

    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_FF_BN128_INIT_HPP
