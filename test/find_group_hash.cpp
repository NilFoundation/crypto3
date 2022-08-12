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

#define BOOST_TEST_MODULE hash_find_group_hash_test

#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <type_traits>
#include <tuple>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/find_group_hash.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename CurveParams, typename Form>
void print_curve_point(std::ostream &os,
                       const curves::detail::curve_element<CurveParams, Form, curves::coordinates::affine> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "] )" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename CurveParams, typename Form, typename Coordinates>
            struct print_log_value<curves::detail::curve_element<CurveParams, Form, Coordinates>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams, Form, Coordinates> const &p) {
                    print_curve_point(os, p);
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

// template<typename Group>
// void check_hash_to_curve(const std::string &msg_str, const typename Group::value_type &expected) {
//     using hash_type = hashes::h2c<Group>;
//     std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
//     typename Group::value_type result = to_curve<hash_type>(msg);
//     BOOST_CHECK_EQUAL(result, expected);
// }

BOOST_AUTO_TEST_SUITE(hash_find_group_hash_manual_test_suite)

BOOST_AUTO_TEST_CASE(jubjub_sha256_default_params_manual_test) {
    using hash_type = hashes::find_group_hash<>;

    std::vector<std::uint8_t> input = {0, 0, 0, 0};
    std::cout << "HERE" << std::endl;
    typename hash_type::group_value_type expected = typename hash_type::group_value_type(
        typename hash_type::group_value_type::field_type::integral_type(
            "14821992026951101352906249207585330645531160601076441869339940926000353872705"),
        typename hash_type::group_value_type::field_type::integral_type(
            "52287259411977570791304693313354699485314647509298698724706688571292689216990"));
    auto point = hash<hash_type>(input);
    BOOST_CHECK(expected == point);

    input = {1, 0, 0, 0};
    expected = typename hash_type::group_value_type(
        typename hash_type::group_value_type::field_type::integral_type(
            "1463691854240270278606818648002136194121833583821877204193209581327298182344"),
        typename hash_type::group_value_type::field_type::integral_type(
            "29819841443135548958808950484163239058878703816702478211299889017771131589670"));
    point = hash<hash_type>(input);
    BOOST_CHECK(expected == point);

    input = {2, 0, 0, 0};
    expected = typename hash_type::group_value_type(
        typename hash_type::group_value_type::field_type::integral_type(
            "40291265060939609650944463710328312785099355084223308258183327547022417006973"),
        typename hash_type::group_value_type::field_type::integral_type(
            "52192102488968215278324791125420866252464543397675384723668566547038588479994"));
    point = hash<hash_type>(input);
    BOOST_CHECK(expected == point);

    input = {3, 0, 0, 0};
    expected = typename hash_type::group_value_type(
        typename hash_type::group_value_type::field_type::integral_type(
            "9727827140824687394408632390964265750934762150332666686367551954377952599690"),
        typename hash_type::group_value_type::field_type::integral_type(
            "19724757542882122580209648860907766139392382704367414563715710526666657068129"));
    point = hash<hash_type>(input);
    BOOST_CHECK(expected == point);

    std::uint32_t input_uint32 = 3;
    point = hash<hash_type>({input_uint32,});
    BOOST_CHECK(expected == point);
}

BOOST_AUTO_TEST_SUITE_END()
