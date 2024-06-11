//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_field_element_vector_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> e) {
    std::cout << std::hex << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> e) {
    std::cout << std::hex << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename T, typename Endianness>
void test_field_element_non_fixed_size_container(std::vector<T> val_container) {

    using namespace nil::crypto3::marshalling;

    std::size_t units_bits = 8;
    using unit_type = unsigned char;

    nil::marshalling::status_type status;
    std::vector<unit_type> cv =
        nil::marshalling::pack<Endianness>(val_container, status);

    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<T> test_val = nil::marshalling::pack<Endianness>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<typename FieldType, typename Endianness, std::size_t TSize>
void test_field_element_non_fixed_size_container() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        std::vector<typename FieldType::value_type> val_container;
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        for (std::size_t i = 0; i < TSize; i++) {
            val_container.push_back(nil::crypto3::algebra::random_element<FieldType>());
        }
        test_field_element_non_fixed_size_container<typename FieldType::value_type,
            Endianness>(val_container);
    }
}

BOOST_AUTO_TEST_SUITE(field_element_non_fixed_size_container_test_suite)

BOOST_AUTO_TEST_CASE(field_element_non_fixed_size_container_bls12_381_g1_field_be) {
    std::cout << "BLS12-381 g1 group field non fixed size container big-endian test started" << std::endl;
    test_field_element_non_fixed_size_container<nil::crypto3::algebra::curves::bls12<381>::g1_type<>::field_type,
                                                nil::marshalling::option::big_endian,
                                                5>();
    std::cout << "BLS12-381 g1 group field non fixed size container big-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_non_fixed_size_container_bls12_381_g1_field_le) {
    std::cout << "BLS12-381 g1 group field non fixed size container little-endian test started" << std::endl;
    test_field_element_non_fixed_size_container<nil::crypto3::algebra::curves::bls12<381>::g1_type<>::field_type,
                                                nil::marshalling::option::little_endian,
                                                5>();
    std::cout << "BLS12-381 g1 group field non fixed size container little-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_non_fixed_size_container_bls12_381_g2_field_be) {
    std::cout << "BLS12-381 g2 group field non fixed size container big-endian test started" << std::endl;
    test_field_element_non_fixed_size_container<nil::crypto3::algebra::curves::bls12<381>::g2_type<>::field_type,
                                                nil::marshalling::option::big_endian,
                                                7>();
    std::cout << "BLS12-381 g2 group field non fixed size container big-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(field_element_non_fixed_size_container_bls12_381_g2_field_le) {
    std::cout << "BLS12-381 g2 group field non fixed size container little-endian test started" << std::endl;
    test_field_element_non_fixed_size_container<nil::crypto3::algebra::curves::bls12<381>::g2_type<>::field_type,
                                                nil::marshalling::option::little_endian,
                                                7>();
    std::cout << "BLS12-381 g2 group field non fixed size container little-endian test finished" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
