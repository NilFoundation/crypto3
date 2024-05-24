//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE hash_based_algebraic_test

#include <string>
#include <tuple>
#include <unordered_map>
#include <sstream>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/random/hash.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << std::hex << e.data << std::endl;
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

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_AUTO_TEST_SUITE(conformity_tests)

BOOST_AUTO_TEST_CASE(mnt4_special_seed_test) {
    using field_type = typename algebra::curves::mnt4<298>::scalar_field_type;
    using field_value_type = typename field_type::value_type;
    using hash_type = hashes::sha2<512>;
    using rng_engine = random::hash<hashes::sha2<512>, field_value_type>;

    rng_engine re(3);
    BOOST_CHECK_EQUAL(
        re(), field_value_type(0x393e87004ad130e3fa1c13c3c0391ed914f84af59c580994d7b4f2f58de985b82586a40bc64_cppui298));

    re.seed(14);
    BOOST_CHECK_EQUAL(
        re(), field_value_type(0x366deb8c8eb00255ee349e493688dc65614403e41845b60968fe4705cf35881800f3404dc49_cppui298));
    std::cout << re << std::endl;

    std::stringstream test_stream;
    test_stream << 1440;
    test_stream >> re;
    BOOST_CHECK_EQUAL(
        re(), field_value_type(0x2ae56dde0c14786b087b3908a09e63b4077007b771cce4f9d3d82cc9d1bc01a8aab2eb15e26_cppui298));

    BOOST_CHECK_EQUAL(
        rng_engine(157968)(),
        field_value_type(0x11e63ba9c5eefde9663db16d8338eb019b1deb6eefd8db63851e6210d3ca136e45a1afb82a0_cppui298));
    BOOST_CHECK_EQUAL(
        rng_engine(148847)(),
        field_value_type(0x299dd09eafb03aba12a3dbead40384f4d7d39e79174e1a8a905e99f815bdc710cca857ead32_cppui298));
}

BOOST_AUTO_TEST_SUITE_END()
