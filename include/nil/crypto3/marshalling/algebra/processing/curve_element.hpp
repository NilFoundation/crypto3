//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <limits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>

#include <nil/crypto3/marshalling/algebra/processing/detail/curve_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {
                // TODO: add marshalling algorithm specification template parameter and specialize parameters depending
                //  on the algorithm and curve group if needed
                template<typename Group>
                struct curve_element_marshalling_params {
                    using group_type = Group;

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
                        return group_type::field_type::value_bits;
                    }

                    static constexpr std::size_t min_bit_length() {
                        return bit_length();
                    }

                    static constexpr std::size_t max_bit_length() {
                        return bit_length();
                    }
                };

                /* Specialization for mnt4_298::g2_type */
                template<typename Coordinates>
                struct curve_element_marshalling_params<algebra::curves::mnt4_298::
                template g2_type<Coordinates, algebra::curves::forms::short_weierstrass> >
                {
                    using group_type = algebra::curves::mnt4_298::template
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

                /* Specialization for mnt6_298::g2_type */
                template<typename Coordinates>
                struct curve_element_marshalling_params<algebra::curves::mnt6_298::
                template g2_type<Coordinates, algebra::curves::forms::short_weierstrass> >
                {
                    using group_type = algebra::curves::mnt6_298::template
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

                // TODO: do not specify marshalling algorithm by curve group, instead specify marshalling procedure only
                //  by form, coordinates and specification policy
                template<typename Endianness, typename Group>
                struct curve_element_writer;

                // TODO: do not specify marshalling algorithm by curve group, instead specify marshalling procedure only
                //  by form, coordinates and specification policy
                template<typename Endianness, typename Group>
                struct curve_element_reader;

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

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::alt_bn128_254::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::alt_bn128_254::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g1_value_type = group_value_type;
                    using g1_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is always encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;
                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;

                        auto point_affine = point.to_affine();

                        write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);

                        if (point_affine.is_zero()) {
                            *iter |= I_bit;
                        }

                        if (detail::sign_gf_p<g1_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::alt_bn128_254::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::alt_bn128_254::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g2_value_type = group_value_type;
                    using g2_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is always encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);

                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;
                        typename group_type::curve_type::template g2_type<
                            typename algebra::curves::coordinates::affine,
                            form>::value_type point_affine = point.to_affine();

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

                        if(point.is_zero()) {
                            *iter |= I_bit;
                        }

                        if (detail::sign_gf_p<g2_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::mnt4_298::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt4_298::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g1_value_type = group_value_type;
                    using g1_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;
                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;

                        auto point_affine = point.to_affine();

                        write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);

                        if (point_affine.is_zero()) {
                            *iter |= I_bit;
                        }

                        if (detail::sign_gf_p<g1_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::mnt4_298::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt4_298::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g2_value_type = group_value_type;
                    using g2_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is always encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);

                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;
                        auto point_affine = point.to_affine();

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
                        if(point.is_zero()) {
                            *iter |= I_bit;
                        }

                        if (detail::sign_gf_p<g2_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::mnt6_298::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt6_298::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g1_value_type = group_value_type;
                    using g1_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;
                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;

                        auto point_affine = point.to_affine();

                        write_data<params_type::bit_length(), endianness>(
                                static_cast<typename group_value_type::field_type::integral_type>(point_affine.X.data),
                                iter);

                        if (point_affine.is_zero()) {
                            *iter |= I_bit;
                        }

                        if (detail::sign_gf_p<g1_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::big_endian,
                    typename algebra::curves::mnt6_298::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt6_298::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using g2_value_type = group_value_type;
                    using g2_field_type = typename group_value_type::field_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(const group_value_type &point, TIter &iter) {

                        /* Point is always encoded in compressed form, only X coordinate.
                         * Highest bit is Infinity flag
                         * Second highest bit is sign of Y coordinate */

                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        constexpr static const std::size_t units_bits = 8;
                        constexpr static const std::size_t chunk_bits = sizeof(typename TIter::value_type) * units_bits;
                        constexpr static const std::size_t sizeof_field_element_chunks_count =
                            (sizeof_field_element / chunk_bits) + ((sizeof_field_element % chunk_bits) ? 1 : 0);

                        constexpr static const chunk_type I_bit = 0x80;
                        constexpr static const chunk_type S_bit = 0x40;
                        auto point_affine = point.to_affine();

                        TIter write_iter = iter;
                        write_data<sizeof_field_element, endianness>(
                            static_cast<typename group_value_type::field_type::integral_type>(
                                point_affine.X.data[2].data),
                            write_iter);
                        write_iter += sizeof_field_element_chunks_count;

                        write_data<sizeof_field_element, endianness>(
                            static_cast<typename group_value_type::field_type::integral_type>(
                                point_affine.X.data[1].data),
                            write_iter);
                        write_iter += sizeof_field_element_chunks_count;

                        write_data<sizeof_field_element, endianness>(
                            static_cast<typename group_value_type::field_type::integral_type>(
                                point_affine.X.data[0].data),
                            write_iter);

                        if(point.is_zero()) {
                            *iter |= I_bit;
                        }

                        auto y2_mod = point_affine.Y.squared();

                        if (detail::sign_gf_p<g2_field_type>(point_affine.Y)) {
                            *iter |= S_bit;
                        }

                        return nil::marshalling::status_type::success;
                    }
                };

                template<typename Coordinates>
                struct curve_element_writer<
                    nil::marshalling::endian::little_endian,
                    typename algebra::curves::curve25519::template g1_type<Coordinates,
                                                                           algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::curve25519::template g1_type<Coordinates,
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
                        using group_affine_value_type =
                            typename algebra::curves::curve25519::g1_type<algebra::curves::coordinates::affine,
                                                                          form>::value_type;
                        // TODO: somehow add size check of container pointed by iter
                        constexpr std::size_t encoded_size = 32;
                        static_assert(encoded_size ==
                                          (params_type::bit_length() / 8 + (params_type::bit_length() % 8 ? 1 : 0)),
                                      "wrong size");
                        using encoded_value_type = std::array<std::uint8_t, encoded_size>;

                        group_affine_value_type point_affine = point.to_affine();
                        // TODO: remove crating of temporary array encoded_value
                        encoded_value_type encoded_value {0};
                        // TODO: remove lvalue iterator
                        auto tmp_iter = std::begin(encoded_value);
                        write_data<encoded_size, endianness>(static_cast<base_integral_type>(point_affine.Y.data),
                                                             tmp_iter);
                        // TODO: throw catchable error, for example return status
                        assert(!(encoded_value[encoded_size - 1] & 0x80));
                        encoded_value[encoded_size - 1] |=
                            (static_cast<std::uint8_t>(static_cast<base_integral_type>(point_affine.X.data) & 1) << 7);

                        std::copy(std::cbegin(encoded_value), std::cend(encoded_value), iter);

                        return nil::marshalling::status_type::success;
                    }
                };

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
                    static typename std::enable_if<
                        !std::is_same<bool, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                        process(const group_value_type &point, TIter &iter) {
                        write_data<params_type::bit_length(), endianness>(
                            static_cast<typename group_value_type::field_type::integral_type>(point.to_affine().X.data),
                            iter);

                        return nil::marshalling::status_type::success;
                    }

                    // TODO: refactor
                    template<typename TIter>
                    static typename std::enable_if<
                        std::is_same<bool, typename std::iterator_traits<TIter>::value_type>::value,
                        nil::marshalling::status_type>::type
                        process(const group_value_type &point, TIter &iter) {
                        auto X_affine =
                            static_cast<typename group_value_type::field_type::integral_type>(point.to_affine().X.data);
                        for (std::size_t i = 0; i < params_type::bit_length(); ++i) {
                            *iter++ = bit_test(X_affine, 0);
                            X_affine >>= 1;
                        }

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
                            BOOST_ASSERT(iter + sizeof_field_element_chunks_count ==
                                         std::find(iter, iter + sizeof_field_element_chunks_count, true));
                            point = g1_value_type();    // point at infinity
                            return nil::marshalling::status_type::success;
                        }

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3) + g1_field_value_type(4);
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
                        g2_field_value_type y2_mod = x_mod.pow(3) + g2_field_value_type(4, 4);
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
                    typename algebra::curves::alt_bn128_254::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::alt_bn128_254::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        using g1_value_type = group_value_type;
                        using g1_field_type = typename group_value_type::field_type;
                        using g1_field_value_type = typename g1_field_type::value_type;
                        using integral_type = typename g1_value_type::field_type::integral_type;

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        if (I_bit) {
                            // point at infinity
                            point = g1_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g1_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    typename algebra::curves::alt_bn128_254::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::alt_bn128_254::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

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

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        TIter read_iter = iter;
                        integral_type x_1 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;
                        integral_type x_0 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);

                        if (I_bit) {
                            // point at infinity
                            point = group_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g2_field_value_type x_mod(x_0, x_1);
                        g2_field_value_type y2_mod = x_mod.pow(3) + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g2_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    typename algebra::curves::mnt4_298::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt4_298::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        using g1_value_type = group_value_type;
                        using g1_field_type = typename group_value_type::field_type;
                        using g1_field_value_type = typename g1_field_type::value_type;
                        using integral_type = typename g1_value_type::field_type::integral_type;

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        if (I_bit) {
                            // point at infinity
                            point = g1_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3)
                            + group_type::params_type::a * x_mod
                            + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g1_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    typename algebra::curves::mnt4_298::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt4_298::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

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

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        TIter read_iter = iter;
                        integral_type x_1 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;
                        integral_type x_0 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);

                        if (I_bit) {
                            // point at infinity
                            point = group_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g2_field_value_type x_mod(x_0, x_1);
                        g2_field_value_type y2_mod = x_mod.pow(3)
                            + group_type::params_type::a * x_mod
                            + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g2_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    typename algebra::curves::mnt6_298::template g1_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt6_298::
                        template g1_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

                        constexpr static const std::size_t sizeof_field_element =
                            params_type::bit_length() / (group_value_type::field_type::arity);
                        using g1_value_type = group_value_type;
                        using g1_field_type = typename group_value_type::field_type;
                        using g1_field_value_type = typename g1_field_type::value_type;
                        using integral_type = typename g1_value_type::field_type::integral_type;

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        integral_type x = read_data<sizeof_field_element, integral_type, endianness>(iter);

                        if (I_bit) {
                            // point at infinity
                            point = g1_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g1_field_value_type x_mod(x);
                        g1_field_value_type y2_mod = x_mod.pow(3)
                            + group_type::params_type::a * x_mod
                            + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g1_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g1_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    typename algebra::curves::mnt6_298::template g2_type<
                        Coordinates,
                        algebra::curves::forms::short_weierstrass>> {
                    using group_type = typename algebra::curves::mnt6_298::
                        template g2_type<Coordinates, algebra::curves::forms::short_weierstrass>;
                    using group_value_type = typename group_type::value_type;
                    using coordinates = typename group_value_type::coordinates;
                    using form = typename group_value_type::form;
                    using endianness = nil::marshalling::endian::big_endian;
                    using params_type = curve_element_marshalling_params<group_type>;

                    template<typename TIter>
                    static nil::marshalling::status_type process(group_value_type &point, TIter &iter) {
                        using chunk_type = typename TIter::value_type;

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

                        chunk_type I_bit = *iter & 0x80;
                        chunk_type S_bit = *iter & 0x40;

                        TIter read_iter = iter;
                        integral_type x_2 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;
                        integral_type x_1 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);
                        read_iter += sizeof_field_element_chunks_count;
                        integral_type x_0 = read_data<sizeof_field_element, integral_type, endianness>(read_iter);

                        if (I_bit) {
                            // point at infinity
                            point = group_value_type();
                            return nil::marshalling::status_type::success;
                        }

                        g2_field_value_type x_mod(x_0, x_1, x_2);
                        g2_field_value_type y2_mod = x_mod.pow(3)
                            + group_type::params_type::a * x_mod
                            + group_type::params_type::b;
                        BOOST_ASSERT(y2_mod.is_square());
                        g2_field_value_type y_mod = y2_mod.sqrt();
                        bool Y_bit = detail::sign_gf_p<g2_field_type>(y_mod);
                        if (Y_bit == bool(S_bit)) {
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
                    nil::marshalling::endian::little_endian,
                    typename algebra::curves::curve25519::template g1_type<Coordinates,
                                                                           algebra::curves::forms::twisted_edwards>> {
                    using group_type =
                        typename algebra::curves::curve25519::template g1_type<Coordinates,
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
                        process(group_value_type &point, TIter &iter) {
                        // somehow add size check of container pointed by iter
                        // assert(TSize == std::distance(first, last));
                        using base_field_type = typename group_type::field_type;
                        using base_integral_type = typename base_field_type::integral_type;
                        using group_affine_value_type =
                            typename algebra::curves::curve25519::g1_type<algebra::curves::coordinates::affine,
                                                                          form>::value_type;
                        constexpr std::size_t encoded_size = 32;
                        static_assert(encoded_size ==
                                          (params_type::bit_length() / 8 + (params_type::bit_length() % 8 ? 1 : 0)),
                                      "wrong size");

                        base_integral_type y =
                            read_data<params_type::bit_length(), base_integral_type, endianness>(iter);
                        bool sign = *(iter + encoded_size - 1) & (1 << 7);
                        group_affine_value_type decoded_point_affine =
                            detail::recover_x<group_affine_value_type>(y, sign);

                        // TODO: remove hard-coded call for type conversion, implement type conversion between
                        // coordinates
                        //  through operator
                        point = decoded_point_affine.to_extended_with_a_minus_1();

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
                        process(group_value_type &point, TIter &iter) {
                        using field_type = typename group_value_type::field_type;
                        using integral_type = typename field_type::integral_type;

                        const std::size_t chunk_number =
                            params_type::bit_length() / 8 + (params_type::bit_length() % 8 != 0);
                        assert(chunk_number == 32);

                        integral_type int_v = read_data<params_type::bit_length(), integral_type, endianness>(iter);
                        if (int_v >= group_value_type::field_type::modulus) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }
                        field_type::value_type field_v(int_v);
                        field_type::value_type vv = field_v.squared();
                        field_type::value_type denominator = (field_type::value_type(group_type::params_type::a) -
                                                              field_type::value_type(group_type::params_type::d) * vv);
                        if (denominator.is_zero()) {
                            return nil::marshalling::status_type::invalid_msg_data;
                        }
                        field_type::value_type fraction = (field_type::value_type::one() - vv) / denominator;

                        // TODO: change logic of sqrt error handling
                        field_type::value_type u;
                        if (fraction.is_one()) {
                            u = field_type::modulus - 1;
                        } else if (fraction.is_zero()) {
                            u = field_type::value_type::zero();
                        } else {
                            u = fraction.sqrt();
                            if (u == field_type::value_type(field_type::modulus - 1)) {
                                return nil::marshalling::status_type::invalid_msg_data;
                            }
                        }
                        // TODO: above logic should be handled in sqrt

                        if ((*(iter + chunk_number - 1) >> 7) == (static_cast<integral_type>(u.data) & 1)) {
                            point = group_value_type(u, field_v);
                        } else {
                            point = group_value_type(-u, field_v);
                        }

                        return nil::marshalling::status_type::success;
                    }
                };
            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_CURVE_ELEMENT_HPP
