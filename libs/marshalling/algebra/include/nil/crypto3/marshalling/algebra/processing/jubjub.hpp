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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_JUBJUB_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_JUBJUB_CURVE_ELEMENT_HPP

#include <cstdint>
#include <type_traits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/curves/jubjub.hpp>

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
                    typename algebra::curves::jubjub::template g1_type<Coordinates,
                                                                       algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::jubjub::template g1_type<Coordinates,
                                                                           algebra::curves::forms::twisted_edwards>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::little_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    /// https://zips.z.cash/protocol/protocol.pdf#concreteextractorjubjub
                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter)
                    {
                        write_data<params_type::bit_length(), endianness>(
                            static_cast<typename group_value_type::field_type::integral_type>(point.to_affine().X.data),
                            iter);
                        return nil::marshalling::status_type::success;
                    }
                };

                template<>
                struct curve_element_reader<
                    nil::marshalling::endian::little_endian,
                    typename algebra::curves::jubjub::template g1_type<algebra::curves::coordinates::affine,
                                                                       algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::jubjub::template g1_type<algebra::curves::coordinates::affine,
                                                                           algebra::curves::forms::twisted_edwards>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::little_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    /// abst_J(LEOS2BSP_{256}(iter))
                    /// See https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub
                    template<typename TIter>
                    static typename std::enable_if<
                        std::is_same<std::uint8_t, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                    process(group_value_type &point, TIter &iter)
                    {
                        using field_type = typename group_value_type::field_type;
                        using scalar_type = typename algebra::curves::jubjub::scalar_field_type;
                        using integral_type = typename field_type::integral_type;

                        integral_type int_u = read_data<params_type::bit_length(), integral_type, endianness>(iter);
                        if (int_u >= group_value_type::field_type::modulus) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }

                        if (int_u.is_zero()) {
                            point = group_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        field_type::value_type field_u(int_u);
                        field_type::value_type uu = field_u.squared();
                        field_type::value_type denominator =
                            (field_type::value_type::one() - field_type::value_type(group_type::params_type::d) * uu);
                        if (denominator.is_zero()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }

                        field_type::value_type fraction =
                            (field_type::value_type::one() - field_type::value_type(group_type::params_type::a) * uu)
                            * denominator.inversed();

                        if (!fraction.is_square()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }

                        field_type::value_type v = fraction.sqrt();

                        // ... at most one of (u, v) and (u, −v) is in J(𝑟)
                        point = group_value_type(field_u, v);
                        if ( (point * (scalar_type::modulus - 1) + point).is_zero() ) {
                            return nil::marshalling::status_type::success;
                        }

                        point = group_value_type(field_u, -v);
                        if ( (point * (scalar_type::modulus - 1) + point).is_zero() ) {
                            return nil::marshalling::status_type::success;
                        }

                        // If neither has order r, then point is of mixed order and should be rejected
                        point = group_value_type();
                        return nil::marshalling::status_type::invalid_msg_data;
                    }
                };
            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP
