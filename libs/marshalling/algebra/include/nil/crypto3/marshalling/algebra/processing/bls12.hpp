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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_BLS12_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_BLS12_CURVE_ELEMENT_HPP

#include <cstddef>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>

#include <nil/crypto3/marshalling/algebra/processing/detail/curve_element.hpp>
#include <nil/crypto3/marshalling/algebra/processing/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {


                /* Specialization for bls12_377::g2_type */
                template<typename Coordinates>
                struct curve_element_marshalling_params<algebra::curves::bls12_377::
                template g2_type<Coordinates, algebra::curves::forms::short_weierstrass> >
                {
                    using group_type = algebra::curves::bls12_381::template
                        g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;

                    static constexpr std::size_t length() {
                        return bit_length() / 8 + ((bit_length() % 8) != 0);
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr std::size_t bit_length() {
                        constexpr std::size_t modulus_bits_round_up = (group_type::field_type::modulus_bits + 7) & ~7;
                        return modulus_bits_round_up * group_type::field_type::arity;
                    }

                    static constexpr std::size_t min_bit_length() {
                        return bit_length();
                    }

                    static constexpr std::size_t max_bit_length() {
                        return bit_length();
                    }
                };

                /* Specialization for bls12_381::g2_type */
                template<typename Coordinates>
                struct curve_element_marshalling_params<algebra::curves::bls12_381::
                template g2_type<Coordinates, algebra::curves::forms::short_weierstrass> >
                {
                    using group_type = algebra::curves::bls12_381::template
                        g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;

                    static constexpr std::size_t length() {
                        return bit_length() / 8 + ((bit_length() % 8) != 0);
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr std::size_t bit_length() {
                        constexpr std::size_t modulus_bits_round_up = (group_type::field_type::modulus_bits + 7) & ~7;
                        return modulus_bits_round_up * group_type::field_type::arity;
                    }

                    static constexpr std::size_t min_bit_length() {
                        return bit_length();
                    }

                    static constexpr std::size_t max_bit_length() {
                        return bit_length();
                    }
                };

                template<typename Endianness, typename Coordinates>
                struct curve_element_writer<
                    Endianness,
                    typename algebra::curves::bls12_381::template g1_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_381::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = Endianness;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        typename group_type::curve_type::template g1_type<typename algebra::curves::coordinates::affine,
                                                                          form>::value_type point_affine =
                            point.to_affine();
                        chunk_type m_unit = detail::evaluate_m_unit<chunk_type>(point, true);
                        if (!(I_bit & m_unit)) {
                            // We assume here, that write_data doesn't change the iter
                            write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);
                        }
                        (*iter) |= m_unit;

                        return nil::marshalling::status_type::success;
                    }
                };


                template<typename Endianness, typename Coordinates>
                struct curve_element_writer<
                    Endianness,
                    typename algebra::curves::bls12_381::template g2_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_381::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = Endianness;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);

                        constexpr static const chunk_type I_bit = 0x40;
                        typename group_type::curve_type::template g2_type<typename algebra::curves::coordinates::affine,
                                                                          form>::value_type point_affine =
                            point.to_affine();
                        chunk_type m_unit = detail::evaluate_m_unit<chunk_type>(point, true);
                        if (!(I_bit & m_unit)) {
                            TIter write_iter = iter;
                            // We assume here, that write_data doesn't change the iter
                            write_data<sizeof_field_element, endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(
                                    point_affine.X.data[1].data),
                                write_iter);
                            write_iter += sizeof_field_element_chunks_count;
                            // We assume here, that write_data doesn't change the iter
                            write_data<sizeof_field_element, endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(
                                    point_affine.X.data[0].data),
                                write_iter);
                        }
                        (*iter) |= m_unit;

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Endianness, typename Coordinates>
                struct curve_element_writer<
                    Endianness,
                    typename algebra::curves::bls12_377::template g1_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_377::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = Endianness;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        typename group_type::curve_type::template g1_type<typename algebra::curves::coordinates::affine,
                                                                          form>::value_type point_affine =
                            point.to_affine();
                        chunk_type m_unit = detail::evaluate_m_unit<chunk_type>(point, true);
                        if (!(I_bit & m_unit)) {
                            // We assume here, that write_data doesn't change the iter
                            write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);
                        }
                        (*iter) |= m_unit;

                        return nil::marshalling::status_type::success;
                    }
                };


                template<typename Endianness, typename Coordinates>
                struct curve_element_writer<
                    Endianness,
                    typename algebra::curves::bls12_377::template g2_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_377::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = Endianness;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);

                        constexpr static const chunk_type I_bit = 0x40;
                        typename group_type::curve_type::template g2_type<typename algebra::curves::coordinates::affine,
                                                                          form>::value_type point_affine =
                            point.to_affine();
                        chunk_type m_unit = detail::evaluate_m_unit<chunk_type>(point, true);
                        if (!(I_bit & m_unit)) {
                            TIter write_iter = iter;
                            // We assume here, that write_data doesn't change the iter
                            write_data<sizeof_field_element, endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(
                                    point_affine.X.data[1].data),
                                write_iter);
                            write_iter += sizeof_field_element_chunks_count;
                            // We assume here, that write_data doesn't change the iter
                            write_data<sizeof_field_element, endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(
                                    point_affine.X.data[0].data),
                                write_iter);
                        }
                        (*iter) |= m_unit;

                        return nil::marshalling::status_type::success;
                    }
                };


                template<typename Coordinates>
                struct curve_element_reader<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::bls12_381::template g1_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_381::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        const chunk_type m_unit = *iter & 0xE0;
                        BOOST_ASSERT(m_unit != 0x20 && m_unit != 0x60 && m_unit != 0xE0);

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(chunk_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);
                        using g1_value_type = group_value_type;
                        using g1_field_type = typename group_value_type::field_type;
                        using g1_field_value_type = typename g1_field_type::value_type;
                        using integral_type = typename g1_value_type::field_type::integral_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        constexpr static const chunk_type S_bit = 0x20;

                        if (m_unit & I_bit) {
                            BOOST_VERIFY(iter + sizeof_field_element_chunks_count ==
                                         std::find(iter, iter + sizeof_field_element_chunks_count, true));
                            point = g1_value_type();    // point at infinity
                            return nil::marshalling::status_type::success;
                        }

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3u) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g1_field_type>(y_mod);
                        if (Y_bit == bool(m_unit & S_bit)) {
                            g1_value_type result(x_mod, y_mod, g1_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        } else {
                            g1_value_type result(x_mod, -y_mod, g1_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_reader<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::bls12_381::template g2_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_381::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        const chunk_type m_unit = *iter & 0xE0;
                        BOOST_ASSERT(m_unit != 0x20 && m_unit != 0x60 && m_unit != 0xE0);

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(chunk_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);
                        using g2_value_type = group_value_type;
                        using g2_field_type = typename g2_value_type::field_type;
                        using g2_field_value_type = typename g2_field_type::value_type;
                        using integral_type = typename g2_value_type::field_type::integral_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        constexpr static const chunk_type S_bit = 0x20;

                        if (m_unit & I_bit) {
                            BOOST_ASSERT(iter + 2 * sizeof_field_element_chunks_count ==
                                         std::find(iter, iter + 2 * sizeof_field_element_chunks_count, true));
                            point = g2_value_type();    // point at infinity
                            return nil::marshalling::status_type::success;
                        }

                        TIter read_iter = iter;

                        integral_type x_1 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;

                        integral_type x_0 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);

                        g2_field_value_type x_mod(x_0, x_1);
                        g2_field_value_type y2_mod = x_mod.pow(3u) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g2_field_type>(y_mod);
                        if (Y_bit == bool(m_unit & S_bit)) {
                            g2_value_type result(x_mod, y_mod, g2_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        } else {
                            g2_value_type result(x_mod, -y_mod, g2_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_reader<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::bls12_377::template g1_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_377::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        const chunk_type m_unit = *iter & 0xE0;
                        BOOST_ASSERT(m_unit != 0x20 && m_unit != 0x60 && m_unit != 0xE0);

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(chunk_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);
                        using g1_value_type = group_value_type;
                        using g1_field_type = typename group_value_type::field_type;
                        using g1_field_value_type = typename g1_field_type::value_type;
                        using integral_type = typename g1_value_type::field_type::integral_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        constexpr static const chunk_type S_bit = 0x20;

                        if (m_unit & I_bit) {
                            BOOST_VERIFY(iter + sizeof_field_element_chunks_count ==
                                         std::find(iter, iter + sizeof_field_element_chunks_count, true));
                            point = g1_value_type();    // point at infinity
                            return nil::marshalling::status_type::success;
                        }

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3u) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g1_field_type>(y_mod);
                        if (Y_bit == bool(m_unit & S_bit)) {
                            g1_value_type result(x_mod, y_mod, g1_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        } else {
                            g1_value_type result(x_mod, -y_mod, g1_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_reader<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::bls12_377::template g2_type<Coordinates,
                                                                          algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::bls12_377::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        const chunk_type m_unit = *iter & 0xE0;
                        BOOST_ASSERT(m_unit != 0x20 && m_unit != 0x60 && m_unit != 0xE0);

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(chunk_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);
                        using g2_value_type = group_value_type;
                        using g2_field_type = typename g2_value_type::field_type;
                        using g2_field_value_type = typename g2_field_type::value_type;
                        using integral_type = typename g2_value_type::field_type::integral_type;

                        constexpr static const chunk_type I_bit = 0x40;
                        constexpr static const chunk_type S_bit = 0x20;

                        if (m_unit & I_bit) {
                            BOOST_ASSERT(iter + 2 * sizeof_field_element_chunks_count ==
                                         std::find(iter, iter + 2 * sizeof_field_element_chunks_count, true));
                            point = g2_value_type();    // point at infinity
                            return nil::marshalling::status_type::success;
                        }

                        TIter read_iter = iter;

                        integral_type x_1 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;

                        integral_type x_0 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);

                        g2_field_value_type x_mod(x_0, x_1);
                        g2_field_value_type y2_mod = x_mod.pow(3u) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g2_field_type>(y_mod);
                        if (Y_bit == bool(m_unit & S_bit)) {
                            g2_value_type result(x_mod, y_mod, g2_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        } else {
                            g2_value_type result(x_mod, -y_mod, g2_field_value_type::one());
                            BOOST_ASSERT(result.is_well_formed());
                            point = result;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP
