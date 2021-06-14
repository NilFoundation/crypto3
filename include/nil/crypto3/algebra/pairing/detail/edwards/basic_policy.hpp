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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 183>
                    struct edwards_basic_policy;

                    template<>
                    class edwards_basic_policy<183> {
                        using policy_type = curves::detail::edwards_basic_policy<183>;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::extended_number_type extended_number_type;

                        using fp_type = typename policy_type::scalar_field_type;
                        using fq_type = typename policy_type::g1_field_type;
                        using fqe_type = typename policy_type::g2_field_type;
                        using fqk_type = typename policy_type::gt_field_type;

                        using g1_type = curves::detail::edwards_g1<183>;
                        using g2_type = curves::detail::edwards_g2<183>;
                        using gt_type = typename policy_type::gt_field_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const number_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_type::modulus_bits;
                        constexpr static const number_type scalar_field_modulus = policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t number_type_max_bits = base_field_bits;

                        constexpr static const number_type ate_loop_count =
                            number_type(0xE841DEEC0A9E39280000003_cppui92);

                        constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                            number_type(0x3A1077BB02A78E4A00000003_cppui94);
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;

                        constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x4);

                        constexpr static const extended_number_type final_exponent = extended_number_type(
                            0x11128FF78CE1BA3ED7BDC08DC0E8027077FC9348F971A3EF1053C9D33B1AA7CEBA86030D02292F9F5E784FDE9EE9D0176DBE7DA7ECBBCB64CDC0ACD4E64D7156C2F84EE1AAFA1098707148DB1E4797E330E5D507E78D8246A4843B4A174E7CD7CA937BDC5D67A6176F9A48984764500000000_cppui913);
                    };

                    constexpr
                        typename edwards_basic_policy<183>::number_type const edwards_basic_policy<183>::ate_loop_count;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP
