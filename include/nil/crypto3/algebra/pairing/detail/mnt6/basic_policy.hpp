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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/mnt6/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt6/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 298>
                    class mnt6_basic_policy;

                    template<>
                    class mnt6_basic_policy<298> {
                        using policy_type = curves::detail::mnt6_basic_policy<298>;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::extended_number_type extended_number_type;

                        using fp_type = typename policy_type::scalar_field_type;
                        using fq_type = typename policy_type::base_field_type;
                        using fqe_type = typename policy_type::g2_field_type;
                        using fqk_type = typename policy_type::gt_field_type;

                        using g1_type = curves::detail::mnt6_g1<298>;
                        using g2_type = curves::detail::mnt6_g2<298>;
                        using gt_type = typename policy_type::gt_field_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_type::modulus_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t number_type_max_bits = base_field_bits;

                        constexpr static const number_type ate_loop_count =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;
                        constexpr static const bool ate_is_loop_count_neg = true;
                        constexpr static const extended_number_type final_exponent = extended_number_type(
                            0x2D9F068E10293574745C62CB0EE7CF1D27F98BA7E8F16BB1CB498038B1B0B4D7EA28C42575093726D5E360818F2DD5B39038CFF6405359561DD2F2F0627F9264724E069A7198C17873F7F54D8C7CE3D5DAED1AC5E87C26C03B1F481813BB668B6FEDC7C2AAA83936D8BC842F74C66E7A13921F7D91474B3981D3A3B3B40537720C84FE27E3E90BB29DB12DFFE17A286C150EF5071B3087765F9454046ECBDD3B014FF91A1C18D55DB868E841DBF82BCCEFB4233833BD800000000_cppui1490);

                        constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;    // same as ate_loop_count?
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;
                        constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x1);
                    };

                    constexpr typename mnt6_basic_policy<298>::number_type const mnt6_basic_policy<298>::ate_loop_count;
                    constexpr typename mnt6_basic_policy<298>::number_type const
                        mnt6_basic_policy<298>::final_exponent_last_chunk_abs_of_w0;
                    constexpr typename mnt6_basic_policy<298>::number_type const
                        mnt6_basic_policy<298>::final_exponent_last_chunk_w1;
                    constexpr typename mnt6_basic_policy<298>::extended_number_type const
                        mnt6_basic_policy<298>::final_exponent;

                    constexpr bool const mnt6_basic_policy<298>::ate_is_loop_count_neg;
                    constexpr bool const mnt6_basic_policy<298>::final_exponent_last_chunk_is_w0_neg;
                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT6_BASIC_POLICY_HPP
