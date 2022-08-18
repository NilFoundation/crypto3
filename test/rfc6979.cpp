//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE rfc6979_engine_test

#include <string>
#include <tuple>
#include <unordered_map>
#include <sstream>
#include <cstdlib>
#include <ctime>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/random/rfc6979.hpp>

#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/algebra/fields/sect/sect_k1/scalar_field.hpp>

#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/mac/hmac.hpp>

using namespace nil::crypto3;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << std::hex << e.data;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << ", " << e.data[1].data << "]";
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )";
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")";
}

template<typename Fp3CurveGroupElement>
void print_fp3_curve_group_element(std::ostream &os, const Fp3CurveGroupElement &e) {
    os << "(" << e.X.data[0].data << " , " << e.X.data[1].data << " , " << e.X.data[2].data << ") : ("
       << e.Y.data[0].data << " , " << e.Y.data[1].data << " , " << e.Y.data[2].data << ") : (" << e.Z.data[0].data
       << " , " << e.Z.data[1].data << " , " << e.Z.data[2].data << ")";
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename algebra::fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename algebra::fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename algebra::fields::detail::element_fp6_3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename algebra::fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename algebra::fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename algebra::curves::secp256k1::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename algebra::curves::secp256k1::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_AUTO_TEST_SUITE(rfc6979_engine_tests)

// test data from https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.1.2
BOOST_AUTO_TEST_CASE(k_generation_ansix9t163k1) {
    using scalar_field_type = algebra::fields::sect_k1_scalar_field<163>;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using integral_type = typename scalar_field_type::integral_type;

    using hash_type = hashes::sha2<256>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;

    scalar_field_value_type x(integral_type("880910758388802926002809875406932607774501250863"));

    std::string m_str = "sample";
    std::vector<std::uint8_t> m(m_str.cbegin(), m_str.cend());
    typename hash_type::digest_type h1 = hash<hash_type>(m);
    typename hash_type::digest_type etalon_h1 = {{0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1,
                                                  0xD6, 0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9,
                                                  0x89, 0x15, 0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF}};
    BOOST_CHECK(etalon_h1 == h1);

    // int2octets
    std::vector<std::uint8_t> etalon_int2octets = {0x00, 0x9A, 0x4D, 0x67, 0x92, 0x29, 0x5A, 0x7F, 0x73, 0x0F, 0xC3,
                                                   0xF2, 0xB4, 0x9C, 0xBC, 0x0F, 0x62, 0xE8, 0x62, 0x27, 0x2F};
    
    nil::marshalling::status_type status;
    std::vector<std::uint8_t> int2octets_x =
        ::nil::marshalling::pack<::nil::marshalling::option::big_endian>(x, status);

    BOOST_CHECK(
        std::equal(etalon_int2octets.cbegin(), etalon_int2octets.cend(), int2octets_x.cbegin()));

    // bits2int
    std::vector<std::uint8_t> T1 = {0x93, 0x05, 0xA4, 0x6D, 0xE7, 0xFF, 0x8E, 0xB1, 0x07, 0x19, 0x4D,
                                    0xEB, 0xD3, 0xFD, 0x48, 0xAA, 0x20, 0xD5, 0xE7, 0x65, 0x6C, 0xBE,
                                    0x0E, 0xA6, 0x9D, 0x2A, 0x8D, 0x4E, 0x7C, 0x67, 0x31, 0x4A};
    std::vector<std::uint8_t> T2 = {0xC7, 0x0C, 0x78, 0x60, 0x8A, 0x3B, 0x5B, 0xE9, 0x28, 0x9B, 0xE9,
                                    0x0E, 0xF6, 0xE8, 0x1A, 0x9E, 0x2C, 0x15, 0x16, 0xD5, 0x75, 0x1D,
                                    0x2F, 0x75, 0xF5, 0x00, 0x33, 0xE4, 0x5F, 0x73, 0xBD, 0xEB};
    BOOST_CHECK(integral_type("6714779766809171704749678479118231475016740846379") == generator_type::bits2int(T1));
    BOOST_CHECK(integral_type("9090938069291897132358078204413687471124595127979") == generator_type::bits2int(T2));

    // bits2octets
    auto modulus_octets_container = generator_type::bits2octets(h1);
    BOOST_CHECK(std::equal(modulus_octets_container.cbegin(), modulus_octets_container.cend(),
                           std::vector<std::uint8_t> {0x01, 0x79, 0x5E, 0xDF, 0x0D, 0x54, 0xDB, 0x76, 0x0F, 0x15,
                           0x6D, 0x0D, 0xAC, 0x04, 0xC0, 0x32, 0x2B, 0x3A, 0x20, 0x42, 0x24}
                                                      .cbegin()));

    auto gen = generator_type(x, h1);
    auto k = gen();
    integral_type etalon_k("3259566757037731885269073930746036563011142801435");
    BOOST_CHECK(k == etalon_k);
}

BOOST_AUTO_TEST_SUITE_END()
