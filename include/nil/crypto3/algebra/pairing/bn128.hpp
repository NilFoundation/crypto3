//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_BN128_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BN128_POLICY_HPP

#include <nil/crypto3/algebra/pairing/detail/bn128/functions.hpp>
#include <nil/crypto3/algebra/pairing/policy.hpp>

#include <nil/crypto3/algebra/curves/bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct bn128;
            }    // namespace curves
            namespace pairing {

                using namespace nil::crypto3::algebra;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct pairing_policy<curves::bn128<ModulusBits, GeneratorBits>> {

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
    }            // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_PAIRING_BN128_POLICY_HPP