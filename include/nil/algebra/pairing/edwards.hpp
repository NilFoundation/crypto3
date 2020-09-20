//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_EDWARDS_POLICY_HPP
#define ALGEBRA_PAIRING_EDWARDS_POLICY_HPP

#include <nil/algebra/pairing/detail/edwards/functions.hpp>
#include <nil/algebra/pairing/policy.hpp>

#include <nil/algebra/curves/edwards.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            struct pairing_policy<edwards<ModulusBits, GeneratorBits>> {

                using g1_precomp = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::g1_precomp;
                using g2_precomp = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::g2_precomp;

                using precompute_g1 = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::precompute_g1;
                using precompute_g2 = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::precompute_g2;

                using g1_conic_coefficients = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::Fq_conic_coefficients;
                using g2_conic_coefficients = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::Fq3_conic_coefficients;

                using reduced_pairing = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::reduced_pairing;
                using pairing = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::pairing;

                using miller_loop = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::miller_loop;
                using double_miller_loop = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::double_miller_loop;
                using final_exponentiation = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>::final_exponentiation;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_POLICY_HPP