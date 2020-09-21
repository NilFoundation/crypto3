//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    struct edwards_basic_policy;

                    template<>
                    class edwards_basic_policy<183, CHAR_BIT> {
                        using policy_type = curves::detail::edwards_basic_policy<183, CHAR_BIT>;

                    public:
                        using number_type = typename policy_type::number_type;
                        using extended_number_type = typename policy_type::extended_number_type;

                        using Fp_field = typename policy_type::scalar_field_type;
                        using Fq_field = typename policy_type::g1_field_type;
                        using Fqe_field = typename policy_type::g2_field_type;
                        using Fqk_field = typename policy_type::gt_field_type;

                        using g1 = curves::detail::edwards_g1<183, CHAR_BIT>;
                        using g2 = curves::detail::edwards_g2<183, CHAR_BIT>;
                        using Fq = typename Fq_field::value_type;
                        using Fq3 = typename Fqe_field::value_type;
                        using gt = typename Fqk_field::value_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_modulus;

                        constexpr static const std::size_t number_type_max_bits = policy_type::base_field_bits;

                        constexpr static const number_type ate_loop_count =
                            number_type(0xE841DEEC0A9E39280000003_cppui92);

                        constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                            number_type(0x3A1077BB02A78E4A00000003_cppui94);
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;

                        constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x4);

                        constexpr static const extended_number_type final_exponent = extended_number_type(
                            0x11128FF78CE1BA3ED7BDC08DC0E8027077FC9348F971A3EF1053C9D33B1AA7CEBA86030D02292F9F5E784FDE9EE9D0176DBE7DA7ECBBCB64CDC0ACD4E64D7156C2F84EE1AAFA1098707148DB1E4797E330E5D507E78D8246A4843B4A174E7CD7CA937BDC5D67A6176F9A48984764500000000_cppui913);
                    };

                    constexpr typename edwards_basic_policy<183, CHAR_BIT>::number_type 
                        const edwards_basic_policy<183, CHAR_BIT>::ate_loop_count;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP