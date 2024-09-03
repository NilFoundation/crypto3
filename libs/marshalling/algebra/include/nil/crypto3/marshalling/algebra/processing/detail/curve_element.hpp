//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_DETAIL_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_DETAIL_HPP

#include <type_traits>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>

#include <boost/outcome.hpp>

namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {
                namespace detail {
                    template<typename G1FieldType>
                    typename std::enable_if<algebra::is_field<G1FieldType>::value &&
                                                !(algebra::is_extended_field<G1FieldType>::value),
                                            bool>::type
                        sign_gf_p(const typename G1FieldType::value_type &v) {

                        if (v > G1FieldType::group_order_minus_one_half) {
                            return true;
                        }
                        return false;
                    }

                    template<typename G2FieldType>
                    typename std::enable_if<algebra::is_extended_field<G2FieldType>::value, bool>::type
                        sign_gf_p(const typename G2FieldType::value_type &v) {

                        if (v.data[1] == 0u) {
                            return sign_gf_p<typename G2FieldType::underlying_field_type>(v.data[0]);
                        }
                        return sign_gf_p<typename G2FieldType::underlying_field_type>(v.data[1]);
                    }

                    template<typename ChunkType, typename GroupValueType>
                    static inline ChunkType evaluate_m_unit(const GroupValueType &point, bool compression) {

                        constexpr static const ChunkType C_bit = 0x80;
                        constexpr static const ChunkType I_bit = 0x40;
                        constexpr static const ChunkType S_bit = 0x20;

                        ChunkType result = 0;
                        if (compression) {
                            result |= C_bit;
                        }
                        // TODO: check condition of infinite point
                        // TODO: did not work as affine point should be fixed for zero-point
                        if (point.is_zero()) {
                            result |= I_bit;
                        } else if (compression && sign_gf_p<typename GroupValueType::field_type>(point.to_affine().Y)) {
                            result |= S_bit;
                        }
                        return result;
                    }

                    /** @brief Recover X coordinate from Y coordinate and given sign
                     * This is specific to Ed25519 Twisted Edwards curve, but could be used for
                     * any other curve in twisted edwards form.
                     *
                     * The curve equation in twisted edwards form is A*x^2+y^2=1+D*x^2*y^2
                     * Given Y, we compute
                     * X^2 = ( 1 - Y^2 ) / ( A - D*Y^2 )
                     * If X^2 is not a square, then there is no such point and input should be rejected
                     * Otherwise X or -X are chosen by the sign parameter
                     */
                    template<typename GroupAffineElement>
                    static inline typename 
                    std::enable_if<
                        std::is_same<algebra::curves::coordinates::affine,
                        typename GroupAffineElement::coordinates>::value,
                        outcome::result<GroupAffineElement, nil::marshalling::status_type> >::type
                        recover_x(const typename GroupAffineElement::field_type::integral_type &y_int, bool sign) {
                        using base_field_type = typename GroupAffineElement::field_type;
                        using base_field_value_type = typename base_field_type::value_type;
                        using base_integral_type = typename base_field_type::integral_type;
                        using group_type = typename GroupAffineElement::group_type;
                        using group_affine_value_type = GroupAffineElement;

                        if (y_int >= base_field_type::modulus) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }
                        base_field_value_type y(y_int);
                        base_field_value_type y2 = y * y;
                        base_field_value_type y2dp1 = group_type::params_type::a - y2 * group_type::params_type::d;
                        if (y2dp1.is_zero()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }
                        base_field_value_type x2 =
                            (base_integral_type(1) - y2) * y2dp1.inversed();
                        if (x2.is_zero()) {
                            return group_affine_value_type(base_field_value_type::zero(), y);
                        }
                        if (!x2.is_square()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }
                        base_field_value_type x = x2.sqrt();
                        auto x_int = static_cast<base_integral_type>(x.data);
                        if (sign_gf_p<base_field_type>(x_int) != sign) {
                            x_int = base_field_type::modulus - x_int;
                        }
                        return group_affine_value_type(x_int, y);
                    }
                }    // namespace detail
            }        // namespace processing
        }            // namespace marshalling
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_DETAIL_HPP
