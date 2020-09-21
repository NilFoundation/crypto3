//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_POLICY_HPP

#include <nil/crypto3/algebra/pairing/detail/mnt4/functions.hpp>
#include <nil/crypto3/algebra/pairing/policy.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct mnt4;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct mnt6;
            }    // namespace curves
            namespace pairing {

                using namespace nil::crypto3::algebra;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class pairing_policy<curves::mnt4<ModulusBits, GeneratorBits>> {
                    using policy_type = detail::mnt4_pairing_functions<ModulusBits, GeneratorBits>;

                public:
                    using other_curve = curves::mnt6<ModulusBits, GeneratorBits>;

                    // typedef typename policy_type::scalar_field_type FieldType;
                    // typedef algebra::Fqe<algebra::curves::mnt6> fqe_type;
                    // typedef algebra::Fqk<algebra::curves::mnt6> fqk_type;

                    using g1_precomp = typename policy_type::g1_precomp;
                    using g2_precomp = typename policy_type::g2_precomp;

                    using precompute_g1 = typename policy_type::precompute_g1;
                    using precompute_g2 = typename policy_type::precompute_g2;

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
#endif    // ALGEBRA_PAIRING_MNT4_POLICY_HPP