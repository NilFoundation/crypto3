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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_ED25519_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_ED25519_CURVE_ELEMENT_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>

#include <nil/crypto3/marshalling/algebra/processing/detail/curve_element.hpp>
#include <nil/crypto3/marshalling/algebra/processing/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::little_endian,
                    typename algebra::curves::ed25519::template g1_type<Coordinates,
                                                                           algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::ed25519::template g1_type<Coordinates,
                                                                               algebra::curves::forms::twisted_edwards>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::little_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static typename std::enable_if<
                    std::is_same<std::uint8_t, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                        process(const group_value_type &point, TIter &iter) {
                        using base_field_type = typename group_type::field_type;
                        using base_integral_type = typename base_field_type::integral_type;

                        constexpr std::size_t encoded_size = 32;
                        using encoded_value_type = std::array<std::uint8_t, encoded_size>;
                        encoded_value_type encoded_value {0};

                        auto point_affine = point.to_affine();

                        /* Zero point is encoded as (0,1) */
                        if (point.is_zero()) {
                            point_affine.Y = 1u;
                            point_affine.X = 0u;
                        }

                        auto tmp_iter = std::begin(encoded_value);
                        write_data<encoded_size, endianness>(static_cast<base_integral_type>(point_affine.Y.data),
                                tmp_iter);
                        assert(!(encoded_value[encoded_size - 1] & 0x80));
                        bool sign = detail::sign_gf_p<base_field_type>(point_affine.X.data);
                        encoded_value[encoded_size - 1] |=
                            (static_cast<std::uint8_t>(sign ? 1 : 0) << 7);

                        std::copy(std::cbegin(encoded_value), std::cend(encoded_value), iter);

                        return nil::marshalling::status_type::success;
                    }
                };


                template<typename Coordinates>
                struct curve_element_reader<
                    nil::marshalling::endian::little_endian,
                    typename algebra::curves::ed25519::template g1_type<Coordinates,
                                                                           algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::ed25519::template g1_type<Coordinates,
                                                                               algebra::curves::forms::twisted_edwards>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::little_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    using group_affine_value_type =
                            typename algebra::curves::ed25519::g1_type<algebra::curves::coordinates::affine,
                                                                          form>::value_type;

                    template<typename TIter>
                    static typename std::enable_if<
                        std::is_same<std::uint8_t, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                        process(group_value_type &point, TIter &iter)
                    {

                        // somehow add size check of container pointed by iter
                        // assert(TSize == std::distance(first, last));
                        using base_field_type = typename group_type::field_type;
                        using base_integral_type = typename base_field_type::integral_type;
                        using group_affine_value_type =
                            typename algebra::curves::ed25519::g1_type<algebra::curves::coordinates::affine,
                                                                          form>::value_type;
                        constexpr std::size_t encoded_size = 32;
                        static_assert(encoded_size ==
                                          (params_type::bit_length() / 8 + (params_type::bit_length() % 8 ? 1 : 0)),
                                      "wrong size");

                        base_integral_type y =
                            read_data<params_type::bit_length(), base_integral_type, endianness>(iter);
                        bool sign = *(iter + encoded_size - 1) & (1 << 7);

                        auto decoded_point_affine =
                                detail::recover_x<group_affine_value_type>(y, sign);

                        if (!decoded_point_affine) {
                            return decoded_point_affine.error();
                        }

                        // TODO: remove hard-coded call for type conversion, implement type conversion between
                        // coordinates
                        //  through operator
                        point = decoded_point_affine.value().to_extended_with_a_minus_1();
                        return nil::marshalling::status_type::success;
                    }
                };

            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_ED25519_CURVE_ELEMENT_HPP
