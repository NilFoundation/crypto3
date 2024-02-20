//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_short_weierstrass_coordinates_test

#include <iostream>
#include <type_traits>

#include <boost/test/included/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/secp_r1.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

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

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::jacobian_with_a4_minus_3>::value||
                        std::is_same<Coordinates, curves::coordinates::jacobian>::value||
                        std::is_same<Coordinates, curves::coordinates::projective_with_a4_minus_3>::value>::type
    print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "], Z:[";
    print_field_element(os, p.Z);
    os << "] )" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
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

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

std::string test_data = std::string(TEST_DATA_DIR) + R"(coordinates.json)";

boost::property_tree::ptree string_data(std::string test_name) {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

enum curve_operation_test_constants : std::size_t { C1, C2 };

enum curve_operation_test_points : std::size_t {
    p1,
    p2,
    p1_plus_p2,
    p1_minus_p2,
    p1_mul_C1,
    p2_mul_C1_plus_p2_mul_C2,
    p1_dbl
};

template<typename CurveGroup>
void check_curve_operations(const std::vector<typename CurveGroup::value_type> &points,
                            const std::vector<std::size_t> &constants) {
    using nil::crypto3::multiprecision::cpp_int;

    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
    BOOST_CHECK_EQUAL(points[p1].doubled(), points[p1_dbl]);
    BOOST_CHECK_EQUAL(points[p1] * static_cast<cpp_int>(constants[C1]), points[p1_mul_C1]);
    BOOST_CHECK_EQUAL((points[p2] * static_cast<cpp_int>(constants[C1])) +
                          (points[p2] * static_cast<cpp_int>(constants[C2])),
                      points[p2_mul_C1_plus_p2_mul_C2]);
    BOOST_CHECK_EQUAL((points[p2] * static_cast<cpp_int>(constants[C1])) +
                          (points[p2] * static_cast<cpp_int>(constants[C2])),
                      points[p2] * static_cast<cpp_int>(constants[C1] + constants[C2]));
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_test_init(std::vector<typename FpCurveGroup::value_type> &points,
                        std::vector<std::size_t> &constants,
                        const TestSet &test_set) {
    typedef typename FpCurveGroup::field_type::value_type field_value_type;
    std::array<field_value_type, 3> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::integral_type(coordinate.second.data()));
        }
        points.emplace_back(typename FpCurveGroup::value_type(coordinates[0], coordinates[1], coordinates[2]));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename CurveGroup, typename TestSet>
void curve_operation_test(const TestSet &test_set,
                          void (&test_init)(std::vector<typename CurveGroup::value_type> &,
                                            std::vector<std::size_t> &,
                                            const TestSet &)) {

    std::vector<typename CurveGroup::value_type> points;
    std::vector<std::size_t> constants;

    test_init(points, constants, test_set);

    check_curve_operations<CurveGroup>(points, constants);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_DATA_TEST_CASE(curve_operation_test_jacobian_minus_3, string_data("curve_operation_test_jacobian_minus_3"), data_set) {
    using policy_type = curves::secp_r1<256>::g1_type< curves::coordinates::jacobian_with_a4_minus_3,  curves::forms::short_weierstrass>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_jacobian, string_data("curve_operation_test_jacobian"), data_set) {
    using policy_type = curves::secp_r1<256>::g1_type< curves::coordinates::jacobian,  curves::forms::short_weierstrass>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_projective_with_a4_minus_3, string_data("curve_operation_test_projective_with_a4_minus_3"), data_set) {
    using policy_type = curves::secp_r1<256>::g1_type< curves::coordinates::projective_with_a4_minus_3,  curves::forms::short_weierstrass>;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}
BOOST_AUTO_TEST_SUITE_END()
