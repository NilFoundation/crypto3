//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/mnt4/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                    class mnt4_basic_policy;

                    template<>
                    class mnt4_basic_policy<298, CHAR_BIT> {
                        using policy_type = curves::detail::mnt4_basic_policy<298, CHAR_BIT>;

                    public:
                        using number_type = typename policy_type::number_type;
                        using extended_number_type = typename policy_type::extended_number_type;

                        using Fp_field = typename policy_type::scalar_field_type;
                        using Fq_field = typename policy_type::g1_field_type;
                        using Fqe_field = typename policy_type::g2_field_type;
                        using Fqk_field = typename policy_type::gt_field_type;

                        using g1 = curves::detail::mnt4_g1<298, CHAR_BIT>;
                        using g2 = curves::detail::mnt4_g2<298, CHAR_BIT>;
                        using Fq = typename Fq_field::value_type;
                        using Fq2 = typename Fqe_field::value_type;
                        using gt = typename Fqk_field::value_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_modulus;

                        constexpr static const std::size_t number_type_max_bits = policy_type::base_field_bits;

                        constexpr static const number_type ate_loop_count =
                            number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149);
                        constexpr static const bool ate_is_loop_count_neg = false;
                        constexpr static const extended_number_type final_exponent = extended_number_type(
                            0x343C7AC3174C87A1EFE216B37AFB6D3035ACCA5A07B2394F42E0029264C0324A95E87DCB6C97234CBA7385B8D20FEA4E85074066818687634E61F58B68EA590B11CEE431BE8348DEB351384D8485E987A57004BB9A1E7A6036C7A5801F55AC8E065E41B012422619E7E69541C5980000_cppui894);

                        constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                            number_type(0x1EEF5546609756BEC2A33F0DC9A1B671660001_cppui149);
                        constexpr static const number_type final_exponent_last_chunk_is_w0_neg = false;
                        constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x1);
                    };

                    constexpr typename mnt4_basic_policy<298, CHAR_BIT>::number_type 
                        const mnt4_basic_policy<298, CHAR_BIT>::ate_loop_count;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP
