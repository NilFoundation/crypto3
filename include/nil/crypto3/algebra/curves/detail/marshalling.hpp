//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ALGEBRA_CURVES_HPP
#define CRYPTO3_MARSHALLING_ALGEBRA_CURVES_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <boost/concept/assert.hpp>

#include <iterator>

using namespace nil::crypto3;

namespace nil {
    namespace marshalling {
        template<typename CurveType>
        struct curve_element_serializer { };

        // ZCash serialization format for BLS12-381
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#appendix-C
        template<>
        struct curve_element_serializer<algebra::curves::bls12_381> {
            typedef algebra::curves::bls12_381 curve_type;

            typedef typename curve_type::g1_type::value_type g1_value_type;
            typedef typename curve_type::g2_type::value_type g2_value_type;

            typedef typename g1_value_type::underlying_field_value_type g1_field_value_type;
            typedef typename g2_value_type::underlying_field_value_type g2_field_value_type;

            typedef typename g1_field_value_type::modulus_type modulus_type;

            constexpr static const unsigned sizeof_field_element = 48;
            typedef std::array<std::uint8_t, sizeof_field_element> compressed_g1_octets;
            typedef std::array<std::uint8_t, 2 * sizeof_field_element> uncompressed_g1_octets;
            typedef std::array<std::uint8_t, 2 * sizeof_field_element> compressed_g2_octets;
            typedef std::array<std::uint8_t, 4 * sizeof_field_element> uncompressed_g2_octets;

            // Serialization procedure according to
            // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#appendix-C.1
            static inline compressed_g1_octets point_to_octets_compress(const g1_value_type &point) {
                compressed_g1_octets result = {0};
                g1_value_type point_affine = point.to_affine();
                auto m_byte = evaluate_m_byte(point_affine, true);
                // TODO: check possibilities for TA
                if (!(I_bit & m_byte)) {
                    multiprecision::export_bits(
                        point_affine.X.data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                }
                result[0] |= m_byte;
                return result;
            }

            static inline uncompressed_g1_octets point_to_octets(const g1_value_type &point) {
                uncompressed_g1_octets result = {0};
                g1_value_type point_affine = point.to_affine();
                auto m_byte = evaluate_m_byte(point_affine, false);
                // TODO: check possibilities for TA
                if (!(I_bit & m_byte)) {
                    multiprecision::export_bits(
                        point_affine.Y.data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                    multiprecision::export_bits(point_affine.X.data.template convert_to<modulus_type>(),
                                                result.rbegin() + sizeof_field_element,
                                                8,
                                                false);
                }
                result[0] |= m_byte;
                return result;
            }

            static inline compressed_g2_octets point_to_octets_compress(const g2_value_type &point) {
                compressed_g2_octets result = {0};
                g2_value_type point_affine = point.to_affine();
                auto m_byte = evaluate_m_byte(point_affine, true);
                // TODO: check possibilities for TA
                if (!(I_bit & m_byte)) {
                    multiprecision::export_bits(
                        point_affine.X.data[0].data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                    multiprecision::export_bits(point_affine.X.data[1].data.template convert_to<modulus_type>(),
                                                result.rbegin() + sizeof_field_element,
                                                8,
                                                false);
                }
                result[0] |= m_byte;
                return result;
            }

            static inline uncompressed_g2_octets point_to_octets(const g2_value_type &point) {
                uncompressed_g2_octets result = {0};
                g2_value_type point_affine = point.to_affine();
                auto m_byte = evaluate_m_byte(point_affine, false);
                // TODO: check possibilities for TA
                if (!(I_bit & m_byte)) {
                    multiprecision::export_bits(
                        point_affine.Y.data[0].data.template convert_to<modulus_type>(), result.rbegin(), 8, false);
                    multiprecision::export_bits(point_affine.Y.data[1].data.template convert_to<modulus_type>(),
                                                result.rbegin() + sizeof_field_element,
                                                8,
                                                false);
                    multiprecision::export_bits(point_affine.X.data[0].data.template convert_to<modulus_type>(),
                                                result.rbegin() + 2 * sizeof_field_element,
                                                8,
                                                false);
                    multiprecision::export_bits(point_affine.X.data[1].data.template convert_to<modulus_type>(),
                                                result.rbegin() + 3 * sizeof_field_element,
                                                8,
                                                false);
                }
                result[0] |= m_byte;
                return result;
            }

            // TODO: use iterators
            // Deserialization procedure according to
            // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-09#appendix-C.2
            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g1_value_type octets_to_g1_point(const PointOctetsRange &octets) {
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<PointOctetsRange>));

                const std::uint8_t m_byte = *octets.begin() & 0xE0;
                BOOST_ASSERT(m_byte != 0x20 && m_byte != 0x60 && m_byte != 0xE0);

                PointOctetsRange point_octets;
                std::copy(octets.begin(), octets.end(), point_octets.begin());
                *point_octets.begin() &= 0x1F;

                if (m_byte & C_bit) {
                    return compressed_to_g1_point(point_octets, m_byte);
                }
                return uncompressed_to_g1_point(point_octets, m_byte);
            }

            // TODO: use iterators
            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g2_value_type octets_to_g2_point(const PointOctetsRange &octets) {
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<PointOctetsRange>));

                const std::uint8_t m_byte = *octets.begin() & 0xE0;
                BOOST_ASSERT(m_byte != 0x20 && m_byte != 0x60 && m_byte != 0xE0);

                PointOctetsRange point_octets;
                std::copy(octets.begin(), octets.end(), point_octets.begin());
                *point_octets.begin() &= 0x1F;

                if (m_byte & C_bit) {
                    return compressed_to_g2_point(point_octets, m_byte);
                }
                return uncompressed_to_g2_point(point_octets, m_byte);
            }

        protected:
            constexpr static const std::uint8_t C_bit = 0x80;
            constexpr static const std::uint8_t I_bit = 0x40;
            constexpr static const std::uint8_t S_bit = 0x20;
            // constexpr static const typename g1_field_value_type::modulus_type half_p =
            //     (g1_field_value_type::modulus - modulus_type(1)) / modulus_type(2);

            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g1_value_type compressed_to_g1_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {
                BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == sizeof_field_element);

                if (m_byte & I_bit) {
                    BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                    return g1_value_type();    // point at infinity
                }

                modulus_type x;
                multiprecision::import_bits(x, point_octets.rbegin(), point_octets.rend(), 8, false);
                g1_field_value_type x_mod(x);
                g1_field_value_type y2_mod = x_mod.pow(3) + g1_field_value_type(4);
                BOOST_ASSERT(y2_mod.is_square());
                g1_field_value_type y_mod = y2_mod.sqrt();
                bool Y_bit = sign_gf_p(y_mod);
                if (Y_bit == bool(m_byte & S_bit)) {
                    g1_value_type result(x_mod, y_mod, g1_field_value_type::one());
                    BOOST_ASSERT(result.is_well_formed());
                    return result;
                }
                g1_value_type result(x_mod, -y_mod, g1_field_value_type::one());
                BOOST_ASSERT(result.is_well_formed());
                return result;
            }

            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g1_value_type uncompressed_to_g1_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {
                BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == 2 * sizeof_field_element);

                if (m_byte & I_bit) {
                    BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                    return g1_value_type();    // point at infinity
                }

                modulus_type x, y;
                multiprecision::import_bits(
                    y, point_octets.rbegin(), point_octets.rbegin() + sizeof_field_element, 8, false);
                multiprecision::import_bits(
                    x, point_octets.rbegin() + sizeof_field_element, point_octets.rend(), 8, false);
                g1_value_type result(g1_field_value_type(x), g1_field_value_type(y), g1_field_value_type::one());
                BOOST_ASSERT(result.is_well_formed());
                return result;
            }

            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g2_value_type compressed_to_g2_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {
                BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == 2 * sizeof_field_element);

                if (m_byte & I_bit) {
                    BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                    return g2_value_type();    // point at infinity
                }

                modulus_type x_0, x_1;
                multiprecision::import_bits(
                    x_0, point_octets.rbegin(), point_octets.rbegin() + sizeof_field_element, 8, false);
                multiprecision::import_bits(
                    x_1, point_octets.rbegin() + sizeof_field_element, point_octets.rend(), 8, false);
                g2_field_value_type x_mod(x_0, x_1);
                g2_field_value_type y2_mod = x_mod.pow(3) + g2_field_value_type(4, 4);
                BOOST_ASSERT(y2_mod.is_square());
                g2_field_value_type y_mod = y2_mod.sqrt();
                bool Y_bit = sign_gf_p(y_mod);
                if (Y_bit == bool(m_byte & S_bit)) {
                    g2_value_type result(x_mod, y_mod, g2_field_value_type::one());
                    BOOST_ASSERT(result.is_well_formed());
                    return result;
                }
                g2_value_type result(x_mod, -y_mod, g2_field_value_type::one());
                BOOST_ASSERT(result.is_well_formed());
                return result;
            }

            template<typename PointOctetsRange,
                     typename = typename std::enable_if<
                         std::is_same<std::uint8_t, typename PointOctetsRange::value_type>::value>::type>
            static inline g2_value_type uncompressed_to_g2_point(PointOctetsRange &point_octets, std::uint8_t m_byte) {
                BOOST_ASSERT(std::distance(point_octets.begin(), point_octets.end()) == 4 * sizeof_field_element);

                if (m_byte & I_bit) {
                    BOOST_ASSERT(point_octets.end() == std::find(point_octets.begin(), point_octets.end(), true));
                    return g2_value_type();    // point at infinity
                }

                modulus_type x_0, x_1, y_0, y_1;
                multiprecision::import_bits(
                    y_0, point_octets.rbegin(), point_octets.rbegin() + sizeof_field_element, 8, false);
                multiprecision::import_bits(y_1,
                                            point_octets.rbegin() + sizeof_field_element,
                                            point_octets.rbegin() + 2 * sizeof_field_element,
                                            8,
                                            false);
                multiprecision::import_bits(x_0,
                                            point_octets.rbegin() + 2 * sizeof_field_element,
                                            point_octets.rbegin() + 3 * sizeof_field_element,
                                            8,
                                            false);
                multiprecision::import_bits(
                    x_1, point_octets.rbegin() + 3 * sizeof_field_element, point_octets.rend(), 8, false);
                g2_value_type result(g2_field_value_type(g1_field_value_type(x_0), g1_field_value_type(x_1)),
                                     g2_field_value_type(g1_field_value_type(y_0), g1_field_value_type(y_1)),
                                     g2_field_value_type::one());
                BOOST_ASSERT(result.is_well_formed());
                return result;
            }

            static inline bool sign_gf_p(const g1_field_value_type &v) {
                static const typename g1_field_value_type::modulus_type half_p =
                    (g1_field_value_type::modulus - modulus_type(1)) / modulus_type(2);

                if (v > half_p) {
                    return true;
                }
                return false;
            }

            static inline bool sign_gf_p(const g2_field_value_type &v) {
                if (v.data[1] == 0) {
                    return sign_gf_p(v.data[0]);
                }
                return sign_gf_p(v.data[1]);
            }

            template<typename GroupValueType>
            static inline std::uint8_t evaluate_m_byte(const GroupValueType &point, bool compression) {
                std::uint8_t result = 0;
                if (compression) {
                    result |= C_bit;
                }
                // TODO: check condition of infinite point
                if (point.Z.is_zero()) {
                    result |= I_bit;
                } else if (compression && sign_gf_p(point.Y)) {
                    result |= S_bit;
                }
                return result;
            }
        };
    }    // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ALGEBRA_CURVES_HPP
