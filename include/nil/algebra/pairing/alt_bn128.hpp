//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP
#define ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP

#include <nil/algebra/pairing/detail/alt_bn128/functions.hpp>
#include <nil/algebra/pairing/policy.hpp>

#include <nil/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            class pairing_policy<alt_bn128<ModulusBits, GeneratorBits>> {
                using policy_type = detail::alt_bn128_pairing_functions<ModulusBits, GeneratorBits>;
            public:

                using g1_precomp = policy_type::ate_g1_precomp;
                using g2_precomp = policy_type::ate_g2_precomp;

                using precompute_g1 = policy_type::ate_precompute_g1;
                using precompute_g2 = policy_type::ate_precompute_g2;

                using reduced_pairing = policy_type::reduced_pairing;
                using pairing = policy_type::pairing;

                using miller_loop = policy_type::ate_miller_loop;
                using double_miller_loop = policy_type::double_ate_miller_loop;
                using final_exponentiation = policy_type::final_exponentiation;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP