//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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
//
// Currently supported curves:
// MNT4<298>, MNT6<298>
// BLS12<381>, BLS12<377>
// alt_bn128<254>
// jubjub, babyjubjub
// pallas, vesta
// families of secp_k1, secp_r1
// ed25519, curve25519
//
//

#define BOOST_TEST_MODULE crypto3_marshalling_curve_element_test

#include <boost/test/unit_test.hpp>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <boost/multiprecision/number.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(*it);
    }
    std::cout << std::endl;
}

template<typename T>
void test_group_element_big_endian(T val) {
    using namespace nil::crypto3::marshalling;

    using Endianness = nil::marshalling::option::big_endian;

    using unit_type = unsigned char;

//    using curve_element_type = types::curve_element<nil::marshalling::field_type<Endianness>, typename T::group_type>;
//    static_assert(nil::marshalling::is_curve_element<curve_element_type>::value);

    // TODO: add incorrect blobs
    // TODO: add bits container checks
    //
    static_assert(nil::marshalling::is_compatible<T>::value);
    nil::marshalling::status_type status;

    std::vector<unit_type> cv = nil::marshalling::pack<Endianness>(val, status);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    T test_val = nil::marshalling::pack<Endianness>(cv, status);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    BOOST_CHECK(val == test_val);
}

template<typename group_type>
void test_group_element() {

    /* test default element - zero for GT and infinity for G1/G2 */
    typename group_type::value_type val = typename group_type::value_type();
    test_group_element_big_endian(val);

    /* test 128 random points */
    for (std::size_t i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        val = nil::crypto3::algebra::random_element<group_type>();
        test_group_element_big_endian(val);
    }
}

template<typename curve_type>
void test_curve(std::string curve_name)
{
    std::cout << "Testing curve: " << curve_name << std::endl;

    std::cout << "Marshaling of G1 group elements" << std::endl;
    test_group_element<typename curve_type::template g1_type<>>();

    std::cout << "Testing of " << curve_name << " finished" << std::endl;

}

template<typename curve_type>
void test_pairing_curve(std::string curve_name)
{
    std::cout << "Testing curve: " << curve_name << std::endl;

    std::cout << "Marshaling of G1 group elements" << std::endl;
    test_group_element<typename curve_type::template g1_type<>>();

    std::cout << "Marshaling of G2 group elements" << std::endl;
    test_group_element<typename curve_type::template g2_type<>>();

    /* TODO: do we really need to marshal GT elements? 
    std::cout << "Marshaling of GT group elements" << std::endl;
    test_group_element<typename curve_type::gt_type>();
    */

    std::cout << "Testing of " << curve_name << " finished" << std::endl;
}


BOOST_AUTO_TEST_SUITE(curve_element_test_suite)

BOOST_AUTO_TEST_CASE(curve_element_mnt4) {
    test_pairing_curve<nil::crypto3::algebra::curves::mnt4_298>("mnt4_298");
}

BOOST_AUTO_TEST_CASE(curve_element_mnt6) {
    test_pairing_curve<nil::crypto3::algebra::curves::mnt6_298>("mnt6_298");
}

BOOST_AUTO_TEST_CASE(curve_element_bls12_381) {
    test_pairing_curve<nil::crypto3::algebra::curves::bls12_381>("bls12_381");
}

// TODO: implement marshalling for bls12<377>
#if 0
BOOST_AUTO_TEST_CASE(curve_element_bls12_377) {
    test_curve<nil::crypto3::algebra::curves::bls12_377>("bls12_377");
}
#endif

BOOST_AUTO_TEST_CASE(curve_element_bn254) {
    test_pairing_curve<nil::crypto3::algebra::curves::alt_bn128_254>("alt_bn128_254");
}

// TODO: implement marshalling for pasta curves
#if 0
BOOST_AUTO_TEST_CASE(curve_element_pallas) {
    test_curve<nil::crypto3::algebra::curves::pallas>("pallas");
}

BOOST_AUTO_TEST_CASE(curve_element_vesta) {
    test_curve<nil::crypto3::algebra::curves::vesta>("vesta");
}
#endif

// TODO: implement marshalling for secp_k1/secp_r1 curves
#if 0
BOOST_AUTO_TEST_CASE(curve_element_secp_k1) {
    test_curve<nil::crypto3::algebra::curves::secp_k1<160>>("secp_k1<160>");
}

BOOST_AUTO_TEST_CASE(curve_element_secp_r1) {
    test_curve<nil::crypto3::algebra::curves::secp_r1<160>>("secp_r1<160>");
}
#endif

/* TODO: add marshalling for jubjub/babyjubjub/ed25519/curve25519, it is broken for now */
#if 0
BOOST_AUTO_TEST_CASE(curve_element_jubjub) {
    test_curve<nil::crypto3::algebra::curves::jubjub>("jubjub");
}

BOOST_AUTO_TEST_CASE(curve_element_babyjubjub) {
    test_curve<nil::crypto3::algebra::curves::jubjub>("babyjubjub");
}

BOOST_AUTO_TEST_CASE(curve_element_ed25519) {
    test_curve<nil::crypto3::algebra::curves::ed25519>("ed25519");
}

BOOST_AUTO_TEST_CASE(curve_element_curve25519) {
    test_curve<nil::crypto3::algebra::curves::curve25519>("curve25519");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
