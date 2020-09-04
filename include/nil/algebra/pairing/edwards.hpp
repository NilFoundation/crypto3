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

#include <sstream>

#include <nil/algebra/pairing/detail/edwards/functions.hpp>

#include <nil/algebra/curves/edwards.hpp>

#include <nil/algebra/fields/detail/params/edwards/fq.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            struct pairing_policy <edwards<ModulusBits, GeneratorBits>>{

                using g1_precomp = detail::edwards_g1_precomp<ModulusBits, GeneratorBits>;
                using g2_precomp = detail::edwards_g2_precomp<ModulusBits, GeneratorBits>;

                using precompute_g1 = detail::edwards_precompute_g1<ModulusBits, GeneratorBits>;
                using precompute_g2 = detail::edwards_precompute_g2<ModulusBits, GeneratorBits>;

                using g1_conic_coefficients = detail::edwards_Fq_conic_coefficients<ModulusBits, GeneratorBits>;
                using g2_conic_coefficients = detail::edwards_Fq3_conic_coefficients<ModulusBits, GeneratorBits>;

                using reduced_pairing = detail::reduced_pairing<ModulusBits, GeneratorBits>;
                using pairing = detail::pairing<ModulusBits, GeneratorBits>;

                using miller_loop = detail::edwards_miller_loop<ModulusBits, GeneratorBits>;
                using double_miller_loop = detail::edwards_double_miller_loop<ModulusBits, GeneratorBits>;
                using final_exponentiation = detail::edwards_final_exponentiation<ModulusBits, GeneratorBits>;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_POLICY_HPP