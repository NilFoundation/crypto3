//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
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

                    template<std::size_t Version = 298>
                    class mnt4_basic_policy;

                    template<>
                    class mnt4_basic_policy<298> {
                        using policy_type = curves::detail::mnt4_basic_policy<298>;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::extended_number_type extended_number_type;

                        using fp_type = typename policy_type::scalar_field_type;
                        using fq_type = typename policy_type::g1_field_type;
                        using fqe_type = typename policy_type::g2_field_type;
                        using fqk_type = typename policy_type::gt_field_type;

                        using g1_type = curves::detail::mnt4_g1<298>;
                        using g2_type = curves::detail::mnt4_g2<298>;
                        using gt_type = typename policy_type::gt_field_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_type::modulus_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t number_type_max_bits = base_field_bits;

                        constexpr static const number_type ate_loop_count =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;
                        constexpr static const bool ate_is_loop_count_neg = false;
                        constexpr static const extended_number_type final_exponent = extended_number_type(
                            0x343C7AC3174C87A1EFE216B37AFB6D3035ACCA5A07B2394F42E0029264C0324A95E87DCB6C97234CBA7385B8D20FEA4E85074066818687634E61F58B68EA590B11CEE431BE8348DEB351384D8485E987A57004BB9A1E7A6036C7A5801F55AC8E065E41B012422619E7E69541C5980000_cppui894);

                        constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660001_cppui149;
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = false;
                        constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x1);
                    };

                    constexpr typename mnt4_basic_policy<298>::number_type const mnt4_basic_policy<298>::ate_loop_count;
                    constexpr typename mnt4_basic_policy<298>::number_type const
                        mnt4_basic_policy<298>::final_exponent_last_chunk_abs_of_w0;
                    constexpr typename mnt4_basic_policy<298>::number_type const
                        mnt4_basic_policy<298>::final_exponent_last_chunk_w1;
                    constexpr typename mnt4_basic_policy<298>::extended_number_type const
                        mnt4_basic_policy<298>::final_exponent;

                    constexpr bool const mnt4_basic_policy<298>::ate_is_loop_count_neg;
                    constexpr bool const mnt4_basic_policy<298>::final_exponent_last_chunk_is_w0_neg;
                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT4_BASIC_POLICY_HPP
