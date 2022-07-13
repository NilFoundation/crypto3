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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_fixed_size_container_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <type_traits>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

template<class T>
struct unchecked_type {
    typedef T type;
};

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType,
         nil::crypto3::multiprecision::cpp_int_check_type Checked, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
struct unchecked_type<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, Checked, Allocator>,
    ExpressionTemplates>> {
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType,
                                                      nil::crypto3::multiprecision::unchecked, Allocator>,
        ExpressionTemplates>
        type;
};

template<class T>
T generate_random() {
    typedef typename unchecked_type<T>::type unchecked_T;

    static const unsigned limbs = std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_bounded ?
                                      std::numeric_limits<T>::digits / std::numeric_limits<unsigned>::digits + 3 :
                                      20;

    static boost::random::uniform_int_distribution<unsigned> ui(0, limbs);
    static boost::random::mt19937 gen;
    unchecked_T val = gen();
    unsigned lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        val *= (gen.max)();
        val += gen();
    }
    return val;
}

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision_big_endian(
    std::array<T, TSize> val_container) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : sizeof(OutputType) * 8;
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::big_endian>, T>;

    using container_type =
        nil::marshalling::types::array_list<nil::marshalling::field_type<nil::marshalling::option::little_endian>,
                                            integral_type, nil::marshalling::option::fixed_size_storage<TSize>>;

    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    container_type test_val_container;

    std::vector<unit_type> cv;
    cv.resize(unitblob_size * TSize, 0x00);

    for (std::size_t i = 0; i < TSize; i++) {
        std::size_t begin_index =
            unitblob_size - ((nil::crypto3::multiprecision::msb(val_container[i]) + 1) / units_bits +
                             (((nil::crypto3::multiprecision::msb(val_container[i]) + 1) % units_bits) ? 1 : 0));

        export_bits(val_container[i], cv.begin() + unitblob_size * i + begin_index, units_bits, true);
    }

    nil::marshalling::status_type status;
    std::array<T, TSize> test_val = 
        nil::marshalling::pack<nil::marshalling::option::big_endian>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = 
        nil::marshalling::pack<nil::marshalling::option::big_endian>(val_container, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision_little_endian(
    std::array<T, TSize> val_container) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : sizeof(OutputType) * 8;
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::little_endian>, T>;

    using container_type =
        nil::marshalling::types::array_list<nil::marshalling::field_type<nil::marshalling::option::little_endian>,
                                            integral_type, nil::marshalling::option::fixed_size_storage<TSize>>;

    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    container_type test_val_container;

    std::vector<unit_type> cv;
    cv.resize(unitblob_size * TSize, 0x00);

    for (std::size_t i = 0; i < TSize; i++) {
        export_bits(val_container[i], cv.begin() + unitblob_size * i, units_bits, false);
    }

    nil::marshalling::status_type status;
    std::array<T, TSize> test_val = 
        nil::marshalling::pack<nil::marshalling::option::little_endian>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = 
        nil::marshalling::pack<nil::marshalling::option::little_endian>(val_container, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, std::size_t TSize, typename OutputType>
void test_round_trip_fixed_size_container_fixed_precision() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        std::array<T, TSize> val_container;
        for (std::size_t i = 0; i < TSize; i++) {
            val_container[i] = generate_random<T>();
        }
        test_round_trip_fixed_size_container_fixed_precision_big_endian<T, TSize, OutputType>(val_container);
        test_round_trip_fixed_size_container_fixed_precision_little_endian<T, TSize, OutputType>(val_container);
    }
}


BOOST_AUTO_TEST_SUITE(integral_fixed_test_suite)

BOOST_AUTO_TEST_CASE(integral_fixed_checked_int1024) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::checked_int1024_t, 128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_uint512) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::checked_uint512_t, 128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_int_backend_64) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
            64, 64, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>,
        128, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_int_backend_23) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
            23, 23, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>,
        128, unsigned char>();
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(integral_fixed_test_suite_bits)

BOOST_AUTO_TEST_CASE(integral_fixed_checked_int1024_bits) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::checked_int1024_t, 128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_uint512_bits) {
    test_round_trip_fixed_size_container_fixed_precision<nil::crypto3::multiprecision::checked_uint512_t, 128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_int_backend_23_bits) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
            23, 23, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>,
        128, bool>();
}

BOOST_AUTO_TEST_CASE(integral_fixed_cpp_int_backend_64_bits) {
    test_round_trip_fixed_size_container_fixed_precision<
        nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
            64, 64, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>,
        128, bool>();
}

BOOST_AUTO_TEST_SUITE_END()
