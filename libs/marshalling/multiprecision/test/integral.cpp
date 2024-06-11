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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_test
// #define BOOST_TEST_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

template<class T>
T generate_random() {
    static const unsigned limbs = std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_bounded ?
                                      std::numeric_limits<T>::digits / std::numeric_limits<unsigned>::digits + 3 :
                                      20;

    static boost::random::uniform_int_distribution<unsigned> ui(0, limbs);
    static boost::random::mt19937 gen;
    T val = gen();
    unsigned lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        val *= (gen.max)();
        val += gen();
    }
    // If we overflow the number, like it was 23 bits, but we filled 1 limb of 64 bits,
    // or it was 254 bits but we filled the upper 2 bits, the number will not complain.
    // Nothing will be thrown, but errors will happen. The caller is responsible to not do so.
    val.backend().normalize();

    return val;
}

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<class T, typename OutputType>
void test_round_trip_fixed_precision_big_endian(T val) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : 8 * sizeof(OutputType);
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::big_endian>, T>;
    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);
    std::size_t begin_index = cv.size() - ((boost::multiprecision::msb(val) + 1) / units_bits +
                                           (((boost::multiprecision::msb(val) + 1) % units_bits) ? 1 : 0));

    export_bits(val, cv.begin() + begin_index, units_bits, true);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<nil::marshalling::option::big_endian>(cv, status);

    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<nil::marshalling::option::big_endian>(val, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_fixed_precision_little_endian(T val) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : 8 * sizeof(OutputType);
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::little_endian>, T>;
    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    std::vector<unit_type> cv;

    export_bits(val, std::back_inserter(cv), units_bits, false);
    cv.resize(unitblob_size, 0x00);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<nil::marshalling::option::little_endian>(cv, status);

    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<nil::marshalling::option::little_endian>(val, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_fixed_precision() {

    static_assert(nil::marshalling::is_compatible<T>::value);

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1; ++i) {
        T val = generate_random<T>();
        test_round_trip_fixed_precision_big_endian<T, OutputType>(val);
        test_round_trip_fixed_precision_little_endian<T, OutputType>(val);
    }
}

template<typename TEndianness, class T, typename OutputType>
void test_round_trip_non_fixed_precision(T val) {
    using namespace nil::crypto3::marshalling;

    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : CHAR_BIT * sizeof(OutputType);
    using unit_type = OutputType;

    std::vector<unit_type> cv;
    export_bits(val, std::back_inserter(cv), units_bits,
        std::is_same<TEndianness, nil::marshalling::option::big_endian>::value?true:false);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<TEndianness>(cv, status);

    // std::cout << std::hex << test_val << '\n' << val << '\n';

    // std::cout << "bits:\n";
    // for(auto a : cv){
    //     std::cout << a;
    // }
    // std::cout << '\n';

    // for(auto a : test_cv){
    //     std::cout << a;
    // }
    // std::cout << '\n';


    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<TEndianness>(val, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_non_fixed_precision() {

    static_assert(nil::marshalling::is_compatible<T>::value);

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        T val = generate_random<T>();
        test_round_trip_non_fixed_precision<nil::marshalling::option::big_endian, T, OutputType>(val);
        test_round_trip_non_fixed_precision<nil::marshalling::option::little_endian, T, OutputType>(val);
    }
}

BOOST_AUTO_TEST_SUITE(integral_test_suite)

BOOST_AUTO_TEST_CASE(integral_checked_int1024) {
    test_round_trip_fixed_precision<boost::multiprecision::uint1024_modular_t, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_uint512) {
    test_round_trip_fixed_precision<boost::multiprecision::uint512_modular_t, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_64) {
    test_round_trip_fixed_precision<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<64>>, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_23) {
    test_round_trip_fixed_precision<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<23>>, unsigned char>();
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(integral_test_suite_bits)

BOOST_AUTO_TEST_CASE(integral_checked_int1024_bits) {
    test_round_trip_fixed_precision<boost::multiprecision::uint1024_modular_t, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_uint512_bits) {
    test_round_trip_fixed_precision<boost::multiprecision::uint512_modular_t, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_64_bits) {
    test_round_trip_fixed_precision<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<64>>, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_23_bits) {
    test_round_trip_fixed_precision<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<23>>, bool>();
}

BOOST_AUTO_TEST_SUITE_END()
