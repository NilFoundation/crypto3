//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE chacha_rng_test

#include <string>
#include <tuple>
#include <unordered_map>

#include <boost/test/unit_test.hpp>

#include <boost/random/random_device.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <nil/crypto3/random/chacha.hpp>

using namespace nil::crypto3;

template<typename StreamCipher = stream::chacha<64, 128, 20>,
         typename MessageAuthenticationCode = mac::hmac<hashes::sha2<256>>>
void test_uniform_random_bit_generator() {
    using generator_type = random::chacha<StreamCipher, MessageAuthenticationCode>;
    using printer_type = boost::test_tools::tt_detail::print_log_value<typename generator_type::result_type>;

    generator_type g;
    printer_type print;
    std::cout << "min = ";
    print(std::cout, generator_type::min());
    std::cout << std::endl;
    std::cout << "max = ";
    print(std::cout, generator_type::max());
    std::cout << std::endl;
    for (auto i = 0; i < 10; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }
}

// TODO: add custom Generator
template<typename StreamCipher = stream::chacha<64, 128, 20>,
         typename MessageAuthenticationCode = mac::hmac<hashes::sha2<256>>>
void test_random_number_engine() {
    std::srand(std::time(nullptr));
    constexpr std::size_t n = 5;
    using generator_type = random::chacha<StreamCipher, MessageAuthenticationCode>;
    using printer_type = boost::test_tools::tt_detail::print_log_value<typename generator_type::result_type>;

    generator_type g;
    printer_type print;
    boost::random::mt19937 seed_seq;

    std::cout << "min = ";
    print(std::cout, generator_type::min());
    std::cout << std::endl;

    std::cout << "max = ";
    print(std::cout, generator_type::max());
    std::cout << std::endl;

    std::cout << "operator():" << std::endl;
    for (auto i = 0; i < n; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }

    std::cout << "seed():" << std::endl;
    g.seed();
    for (auto i = 0; i < n; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }

    std::cout << "seed(value):" << std::endl;
    g.seed(0);
    for (auto i = 0; i < n; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }

    std::cout << "seed(Sseq):" << std::endl;
    g.seed(seed_seq);
    for (auto i = 0; i < n; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }

    std::cout << "operator== and operator!=:" << std::endl;
    generator_type g1;
    std::cout << (g == g1) << std::endl;
    std::cout << (g != g1) << std::endl;
    g.seed();
    std::cout << (g == g1) << std::endl;
    std::cout << (g != g1) << std::endl;

    std::cout << "operator<<:" << std::endl;
    std::cout << g << std::endl;

    std::cout << "operator>>:" << std::endl;
    std::stringstream test_stream;
    test_stream << std::rand();
    test_stream >> g;
    for (auto i = 0; i < n; i++) {
        print(std::cout, g());
        std::cout << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE(algebraic_random_device_interface_tests)

BOOST_AUTO_TEST_CASE(mnt4_test) {
    test_uniform_random_bit_generator<>();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(algebraic_engine_interface_tests)

BOOST_AUTO_TEST_CASE(mnt4_test) {
    test_random_number_engine<>();
}

BOOST_AUTO_TEST_SUITE_END()
