//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BN128_POLICY_HPP
#define ALGEBRA_PAIRING_BN128_POLICY_HPP

#include <sstream>

#include <nil/algebra/pairing/ate.hpp>
#include <nil/algebra/pairing/detail/bn128/functions.hpp>

#include <nil/algebra/curves/bn128.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            struct pairing_policy <bn128<ModulusBits, GeneratorBits>>{

                using g1_precomp = detail::bn128_ate_g1_precomp<ModulusBits, GeneratorBits>;
                using g2_precomp = detail::bn128_ate_g2_precomp<ModulusBits, GeneratorBits>;

                using precompute_g1 = detail::bn128_ate_precompute_g1<ModulusBits, GeneratorBits>;
                using precompute_g2 = detail::bn128_ate_precompute_g2<ModulusBits, GeneratorBits>;

                using reduced_pairing = detail::reduced_pairing<ModulusBits, GeneratorBits>;
                using pairing = detail::pairing<ModulusBits, GeneratorBits>;

                using miller_loop = detail::bn128_ate_miller_loop<ModulusBits, GeneratorBits>;
                using double_miller_loop = detail::bn128_double_ate_miller_loop<ModulusBits, GeneratorBits>;
                using final_exponentiation = detail::bn128_final_exponentiation<ModulusBits, GeneratorBits>;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_BN128_POLICY_HPP