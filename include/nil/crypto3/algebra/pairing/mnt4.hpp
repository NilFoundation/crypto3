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
                class pairing_policy<curves::mnt4<ModulusBits, GeneratorBits>> : public detail::mnt4_pairing_functions<ModulusBits, GeneratorBits> {
                    using policy_type = detail::mnt4_pairing_functions<ModulusBits, GeneratorBits>;
                    using basic_policy = detail::mnt4_basic_policy<ModulusBits, GeneratorBits>;
                public:
                    using other_curve = curves::mnt6<ModulusBits, GeneratorBits>;

                    using number_type = typename basic_policy::number_type;

                    constexpr static const typename basic_policy::number_type pairing_loop_count = basic_policy::ate_loop_count;

                    using Fp_type = typename basic_policy::Fp_field;
                    using G1_type = typename basic_policy::g1;
                    using G2_type = typename basic_policy::g2;
                    using Fq_type = typename basic_policy::Fq_field;
                    using Fqe_type = typename basic_policy::Fqe_field;
                    using Fqk_type = typename basic_policy::Fqk_field;
                    using GT_type = typename basic_policy::gt;

                    using G1_precomp = typename policy_type::g1_precomp;
                    using G2_precomp = typename policy_type::g2_precomp;

                    using policy_type::precompute_g1;
                    using policy_type::precompute_g2;

                    using policy_type::reduced_pairing;
                    using policy_type::pairing;

                    using policy_type::miller_loop;
                    using policy_type::double_miller_loop;
                    using policy_type::final_exponentiation;
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename pairing_policy<curves::mnt4<ModulusBits, GeneratorBits>>::number_type 
                    const pairing_policy<curves::mnt4<ModulusBits, GeneratorBits>>::pairing_loop_count;
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT4_POLICY_HPP