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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_non_fixed_size_container_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <boost/container/vector.hpp>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <boost/multiprecision/number.hpp>

#include <boost/predef.h>

#include <iostream>
#include <iomanip>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

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
        val *= boost::random::mt19937::max();
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

template<typename Endianness, std::size_t TSize, typename OutputType, typename Container>
void test_round_trip_non_fixed_size_container_fixed_precision(const Container &val_container) {
    using namespace nil::crypto3::marshalling;
    using unit_type = OutputType;

    nil::marshalling::status_type status;

    std::vector<unit_type> cv =
            nil::marshalling::pack<Endianness>(val_container, status);

    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<typename Container::value_type> test_val = nil::marshalling::pack<Endianness>(cv, status);

    BOOST_CHECK(std::equal(val_container.begin(), val_container.end(), test_val.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);

}

template<typename Endianness, class T, std::size_t TSize, typename OutputType>
void test_round_trip_non_fixed_size_container_fixed_precision() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        if (!(i % 128) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }

        std::vector<T> val_container;

        for (std::size_t i = 0; i < TSize; i++) {
            val_container.push_back(generate_random<T>());
        }
        test_round_trip_non_fixed_size_container_fixed_precision<Endianness, TSize, OutputType>(val_container);
    }
}

BOOST_AUTO_TEST_SUITE(integral_non_fixed_test_suite)

    BOOST_AUTO_TEST_CASE(integral_non_fixed_checked_int1024_be) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::big_endian,
                boost::multiprecision::uint1024_modular_t,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_checked_int1024_le) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::little_endian,
                boost::multiprecision::uint1024_modular_t,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_uint512_be) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::big_endian,
                boost::multiprecision::uint512_modular_t,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_uint512_le) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::little_endian,
                boost::multiprecision::uint512_modular_t,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_64_be) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::big_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<64>>,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_64_le) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::little_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<64>>,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_23_be) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::big_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<23>>,
                128, unsigned char>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_23_le) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::little_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<23>>,
                128, unsigned char>();
    }

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(integral_non_fixed_test_suite_bits)

    BOOST_AUTO_TEST_CASE(integral_non_fixed_checked_int1024_be_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::big_endian,
                boost::multiprecision::uint1024_modular_t,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_checked_int1024_le_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::little_endian,
                boost::multiprecision::uint1024_modular_t,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_uint512_be_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::big_endian,
                boost::multiprecision::uint512_modular_t,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_uint512_le_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<nil::marshalling::option::little_endian,
                boost::multiprecision::uint512_modular_t,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_64_be_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::big_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<64>>,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_64_le_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::little_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<64>>,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_23_be_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::big_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<23>>,
                128, bool>();
    }

    BOOST_AUTO_TEST_CASE(integral_non_fixed_cpp_int_backend_23_le_bits) {
        test_round_trip_non_fixed_size_container_fixed_precision<
                nil::marshalling::option::little_endian,
                boost::multiprecision::number<
                        boost::multiprecision::cpp_int_modular_backend<23>>,
                128, bool>();
    }

BOOST_AUTO_TEST_SUITE_END()
