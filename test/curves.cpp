//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE curves_algebra_test

#include <iostream>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

// #include <nil/algebra/curves/alt_bn128.hpp>
// #include <nil/algebra/curves/bls12.hpp>
#include <nil/algebra/curves/bn128.hpp>
// #include <nil/algebra/curves/brainpool_r1.hpp>
#include <nil/algebra/curves/edwards.hpp>
// #include <nil/algebra/curves/frp_v1.hpp>
// #include <nil/algebra/curves/gost_A.hpp>
#include <nil/algebra/curves/mnt4.hpp>
#include <nil/algebra/curves/mnt6.hpp>
// #include <nil/algebra/curves/p192.hpp>
// #include <nil/algebra/curves/p224.hpp>
// #include <nil/algebra/curves/p256.hpp>
// #include <nil/algebra/curves/p384.hpp>
// #include <nil/algebra/curves/p521.hpp>
// #include <nil/algebra/curves/secp.hpp>
// #include <nil/algebra/curves/sm2p_v1.hpp>
// #include <nil/algebra/curves/x962_p.hpp>

using namespace nil::algebra;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FpCurveGroup>
            void print_fp_curve_group_element(std::ostream &os, FpCurveGroup e) {
                os << "( " << e.p[0].data << " : " << e.p[1].data << " : " << e.p[2].data << " )";
            }

            template<>
            struct print_log_value<typename curves::bn128<254>::g1_type> {
                void operator()(std::ostream &os, typename curves::bn128<254>::g1_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::edwards<183>::g1_type> {
                void operator()(std::ostream &os, typename curves::edwards<183>::g1_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt4<298>::g1_type> {
                void operator()(std::ostream &os, typename curves::mnt4<298>::g1_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt6<298>::g1_type> {
                void operator()(std::ostream &os, typename curves::mnt6<298>::g1_type const &e) {
                    print_fp_curve_group_element(os, e);
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

// if target == check-algebra just data/curves.json
const char *test_data = "libs/algebra/test/data/curves.json";

boost::property_tree::ptree string_data(std::string test_name) {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

enum binary_operators_tests_members : std::size_t {
    p1,
    p2,
    p1_plus_p2,
    p1_minus_p2,
};

template<typename FpCurveGroup, typename PointsSetType>
void binary_operators_test_fp_init(const PointsSetType &points_set) {
    using field_value_type = typename FpCurveGroup::underlying_field_type_value;
    std::array<field_value_type, 3> coordinates;
    std::vector<FpCurveGroup> points;

    for (auto &point : points_set.second) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::modulus_type(coordinate.second.data()));
        }
        points.emplace_back(FpCurveGroup(coordinates[0], coordinates[1], coordinates[2]));
    }

    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_DATA_TEST_CASE(binary_operators_test_bn128_g1, string_data("binary_operators_test_bn128_g1"), points_set) {
    using policy_type = curves::bn128<254>::g1_type;

    binary_operators_test_fp_init<policy_type>(points_set);
}

BOOST_DATA_TEST_CASE(binary_operators_test_edwards_g1, string_data("binary_operators_test_edwards_g1"), points_set) {
    using policy_type = curves::edwards<183>::g1_type;

    binary_operators_test_fp_init<policy_type>(points_set);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt4_g1, string_data("binary_operators_test_mnt4_g1"), points_set) {
    using policy_type = curves::mnt4<298>::g1_type;

    binary_operators_test_fp_init<policy_type>(points_set);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt6_g1, string_data("binary_operators_test_mnt6_g1"), points_set) {
    using policy_type = curves::mnt6<298>::g1_type;

    binary_operators_test_fp_init<policy_type>(points_set);
}

BOOST_AUTO_TEST_SUITE_END()
