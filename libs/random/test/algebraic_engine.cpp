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

#define BOOST_TEST_MODULE algebraic_engine_test

#include <string>
#include <tuple>
#include <unordered_map>
#include <sstream>
#include <cstdlib>
#include <ctime>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>

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
                void operator()(std::ostream &os, typename algebra::fields::detail::element_fp6_3over2<FieldParams> const &e) {
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
            struct print_log_value<typename algebra::curves::mnt4<298>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename algebra::curves::mnt4<298>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename algebra::curves::mnt4<298>::g2_type<>::value_type> {
                void operator()(std::ostream &os, typename algebra::curves::mnt4<298>::g2_type<>::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename algebra::curves::bls12<381>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename algebra::curves::bls12<381>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename algebra::curves::bls12<381>::g2_type<>::value_type> {
                void operator()(std::ostream &os, typename algebra::curves::bls12<381>::g2_type<>::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
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

template<typename T>
void test_uniform_random_bit_generator() {
    using generator_type = random::algebraic_random_device<T>;
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
template<typename T>
void test_random_number_engine() {
    std::srand(std::time(nullptr));
    constexpr std::size_t n = 5;
    using generator_type = random::algebraic_engine<T>;
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

    std::cout << "discard(z):" << std::endl;
    g.discard(n);
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
    using curve_type = algebra::curves::mnt4<298>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    test_uniform_random_bit_generator<scalar_field_type>();
    test_uniform_random_bit_generator<typename curve_type::g1_type<>::field_type>();
    test_uniform_random_bit_generator<typename curve_type::g2_type<>::field_type>();
    test_uniform_random_bit_generator<typename curve_type::g1_type<>>();
    test_uniform_random_bit_generator<typename curve_type::g2_type<>>();
}

BOOST_AUTO_TEST_CASE(bls12_381_test) {
    using curve_type = algebra::curves::bls12<381>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    test_uniform_random_bit_generator<scalar_field_type>();
    test_uniform_random_bit_generator<typename curve_type::g1_type<>::field_type>();
    test_uniform_random_bit_generator<typename curve_type::g2_type<>::field_type>();
    test_uniform_random_bit_generator<typename curve_type::g1_type<>>();
    test_uniform_random_bit_generator<typename curve_type::g2_type<>>();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(algebraic_engine_interface_tests)

BOOST_AUTO_TEST_CASE(mnt4_test) {
    using curve_type = algebra::curves::mnt4<298>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    test_random_number_engine<scalar_field_type>();
    test_random_number_engine<typename curve_type::g1_type<>::field_type>();
    test_random_number_engine<typename curve_type::g2_type<>::field_type>();
    test_random_number_engine<typename curve_type::g1_type<>>();
    test_random_number_engine<typename curve_type::g2_type<>>();
}

BOOST_AUTO_TEST_CASE(bls12_381_test) {
    using curve_type = algebra::curves::bls12<381>;
    using scalar_field_type = typename curve_type::scalar_field_type;

    test_random_number_engine<scalar_field_type>();
    test_random_number_engine<typename curve_type::g1_type<>::field_type>();
    test_random_number_engine<typename curve_type::g2_type<>::field_type>();
    test_random_number_engine<typename curve_type::g1_type<>>();
    test_random_number_engine<typename curve_type::g2_type<>>();
}

BOOST_AUTO_TEST_SUITE_END()
