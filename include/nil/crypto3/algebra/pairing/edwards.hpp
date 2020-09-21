//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_POLICY_HPP

#include <nil/crypto3/algebra/pairing/detail/edwards/functions.hpp>
#include <nil/crypto3/algebra/pairing/policy.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct edwards;
            }    // namespace curves
            namespace pairing {

                using namespace nil::crypto3::algebra;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class pairing_policy<curves::edwards<ModulusBits, GeneratorBits>> {
                    using policy_type = detail::edwards_pairing_functions<ModulusBits, GeneratorBits>;
                    using basic_policy = detail::edwards_basic_policy<ModulusBits, GeneratorBits>;
                public:

                    using Fp_type = typename basic_policy::Fp_field;
                    using G1_type = typename basic_policy::g1;
                    using G2_type = typename basic_policy::g2;
                    using Fq_type = typename basic_policy::Fq_field;
                    using Fqe_type = typename basic_policy::Fqe_field;
                    using Fqk_type = typename basic_policy::gt_field;
                    using GT_type = typename basic_policy::gt;

                    using G1_precomp_type = typename policy_type::g1_precomp;
                    using G2_precomp_type = typename policy_type::g2_precomp;

                    using precompute_g1 = typename policy_type::precompute_g1;
                    using precompute_g2 = typename policy_type::precompute_g2;

                    using g1_conic_coefficients = typename policy_type::Fq_conic_coefficients;
                    using g2_conic_coefficients = typename policy_type::Fq3_conic_coefficients;

                    using reduced_pairing = typename policy_type::reduced_pairing;
                    using pairing = typename policy_type::pairing;

                    using miller_loop = typename policy_type::miller_loop;
                    using double_miller_loop = typename policy_type::double_miller_loop;
                    using final_exponentiation = typename policy_type::final_exponentiation;
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_POLICY_HPP