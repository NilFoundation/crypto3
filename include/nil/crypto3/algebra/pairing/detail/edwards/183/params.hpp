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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIRING_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIRING_PARAMS_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::edwards<183>> {
                        using curve_type = curves::edwards<183>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const integral_type ate_loop_count =
                            integral_type(0xE841DEEC0A9E39280000003_cppui92);

                        constexpr static const integral_type final_exponent_last_chunk_abs_of_w0 =
                            integral_type(0x3A1077BB02A78E4A00000003_cppui94);
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;

                        constexpr static const integral_type final_exponent_last_chunk_w1 = integral_type(0x4);

                        constexpr static const extended_integral_type final_exponent = extended_integral_type(
                            0x11128FF78CE1BA3ED7BDC08DC0E8027077FC9348F971A3EF1053C9D33B1AA7CEBA86030D02292F9F5E784FDE9EE9D0176DBE7DA7ECBBCB64CDC0ACD4E64D7156C2F84EE1AAFA1098707148DB1E4797E330E5D507E78D8246A4843B4A174E7CD7CA937BDC5D67A6176F9A48984764500000000_cppui913);

                        using g2_field_type_value = typename curve_type::template g2_type<>::field_type::value_type;

                        constexpr static const g2_field_type_value twist =
                            curve_type::template g2_type<>::value_type::twist;
                    };

                    constexpr typename pairing_params<curves::edwards<183>>::integral_type const
                        pairing_params<curves::edwards<183>>::ate_loop_count;
                    constexpr typename pairing_params<curves::edwards<183>>::integral_type const
                        pairing_params<curves::edwards<183>>::final_exponent_last_chunk_abs_of_w0;

                    constexpr typename pairing_params<curves::edwards<183>>::integral_type const
                        pairing_params<curves::edwards<183>>::final_exponent_last_chunk_w1;

                    constexpr typename pairing_params<curves::edwards<183>>::extended_integral_type const
                        pairing_params<curves::edwards<183>>::final_exponent;

                    constexpr bool const pairing_params<curves::edwards<183>>::final_exponent_last_chunk_is_w0_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIRING_PARAMS_HPP
