//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_SECP_R1_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_SECP_R1_CURVE_ELEMENT_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/curves/detail/secp_r1/types.hpp>
#include <nil/crypto3/algebra/curves/detail/secp_r1/g1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>

#include <nil/crypto3/marshalling/algebra/processing/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {

                template<std::size_t Version>
                struct curve_element_marshalling_params<
                    typename algebra::curves::detail::secp_r1_g1<
                        Version,
                        algebra::curves::forms::short_weierstrass,
                        algebra::curves::coordinates::projective>
                > {
                    using group_type = typename algebra::curves::secp_r1<Version>::template g1_type<>;

                    static constexpr std::size_t length() {
                        return 1 + bit_length() / 8 + ((bit_length() % 8) != 0);
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr std::size_t bit_length() {
                        return group_type::field_type::value_bits;
                    }

                    static constexpr std::size_t min_bit_length() {
                        return bit_length();
                    }

                    static constexpr std::size_t max_bit_length() {
                        return bit_length();
                    }
                };

                /*
                 * Encoding of elliptic curve point according to https://www.secg.org/sec1-v2.pdf
                 * Curve must be in short weierstrass form, Y^2 = X^3 + A*X + B
                 * Only X coordinate is encoded, prefixed with either 02 or 03 depending on whether Y is even or odd
                 * The encoding is big-endian
                 * Infinity is encoded as 00
                 * */
                template<std::size_t Version>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::detail::secp_r1_g1<
                        Version,
                        algebra::curves::forms::short_weierstrass,
                        algebra::curves::coordinates::projective> > {
                    using group_type = typename algebra::curves::secp_r1<Version>::template g1_type<>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static typename std::enable_if<
                        std::is_same<std::uint8_t, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                    process(const group_value_type &point, TIter &iter)
                    {
                        if (point.is_zero()) {
                            *iter++ = 0x00;
                            return nil::marshalling::status_type::success;
                        }
                        typename group_type::curve_type::template g1_type<typename algebra::curves::coordinates::affine, form>::value_type
                            point_affine = point.to_affine();

                        *iter++ = (point_affine.Y.data & 1) == 0u ? 0x02 : 0x03;
                        write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates, std::size_t Version>
                struct curve_element_reader<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::detail::secp_r1_g1<Version, algebra::curves::forms::short_weierstrass, Coordinates >> {

                    using group_type = typename algebra::curves::secp_r1<Version>::template g1_type<>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;
                    using curve_params = typename group_type::params_type;
                    using integral_type = typename group_value_type::field_type::integral_type;
                    using g1_field_type = typename group_value_type::field_type;
                    using g1_field_value_type = typename g1_field_type::value_type;

                    template<typename TIter>
                    static typename std::enable_if<
                        std::is_same<std::uint8_t, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                    process(group_value_type &point, TIter &iter)
                    {
                        using chunk_type = typename TIter::value_type;

                        const chunk_type prefix = *iter++;

                        if (0x00 == prefix) {
                            point = group_value_type::zero();
                            return nil::marshalling::status_type::success;
                        }

                        if (prefix != 0x02 && prefix != 0x03) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod * x_mod * x_mod + curve_params::a * x_mod + curve_params::b;
                        if (!y2_mod.is_square()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }

                        g1_field_value_type y_mod = y2_mod.sqrt();

                        const chunk_type expected_prefix = (y_mod.data & 1) == 0u ? 0x02 : 0x03;

                        if (expected_prefix == prefix) {
                            point = group_value_type(x_mod, y_mod);
                        } else {
                            point = group_value_type(x_mod, -y_mod);
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_SECP_R1_CURVE_ELEMENT_HPP
