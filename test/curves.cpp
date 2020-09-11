//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

            template<typename Fp2CurveGroup>
            void print_fp2_curve_group_element(std::ostream &os, Fp2CurveGroup e) {
                os << "(" << e.p[0].data[0].data << " , " << e.p[0].data[1].data << ") : ("
                   << e.p[1].data[0].data << " , " << e.p[1].data[1].data << ") : ("
                   << e.p[2].data[0].data << " , " << e.p[2].data[1].data << ")" << std::endl;
            }

            template<typename Fp3CurveGroup>
            void print_fp3_curve_group_element(std::ostream &os, Fp3CurveGroup e) {
                std::cout << "(" << e.p[0].data[0].data << " , " << e.p[0].data[1].data << " , " << e.p[0].data[2].data << ") : ("
                          << e.p[1].data[0].data << " , " << e.p[1].data[1].data << " , " << e.p[1].data[2].data << ") : ("
                          << e.p[2].data[0].data << " , " << e.p[2].data[1].data << " , " << e.p[2].data[2].data << ")" << std::endl;
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

            template<>
            struct print_log_value<typename curves::mnt4<298>::g2_type> {
                void operator()(std::ostream &os, typename curves::mnt4<298>::g2_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bn128<254>::g2_type> {
                void operator()(std::ostream &os, typename curves::bn128<254>::g2_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::edwards<183>::g2_type> {
                void operator()(std::ostream &os, typename curves::edwards<183>::g2_type const &e) {
                    print_fp3_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt6<298>::g2_type> {
                void operator()(std::ostream &os, typename curves::mnt6<298>::g2_type const &e) {
                    print_fp3_curve_group_element(os, e);
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

enum binary_operator_test_constants : std::size_t {
    C1,
    C2
};

enum binary_operator_test_points : std::size_t {
    p1,
    p2,
    p1_plus_p2,
    p1_minus_p2,
    p1_mul_C1,
    p2_mul_C1_plus_p2_mul_C2,
    p1_dbl
};

template<typename CurveGroup>
void check_curve_operations(const std::vector<CurveGroup> &points, const std::vector<std::size_t> &constants) {
    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
    BOOST_CHECK_EQUAL(points[p1].doubled(), points[p1_dbl]);
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_test_init(std::vector<FpCurveGroup> &points,
                   std::vector<std::size_t> &constants,
                   const TestSet &test_set) {
    using field_value_type = typename FpCurveGroup::underlying_field_type_value;
    std::array<field_value_type, 3> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::modulus_type(coordinate.second.data()));
        }
        points.emplace_back(FpCurveGroup(coordinates[0], coordinates[1], coordinates[2]));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename Fp2CurveGroup, typename TestSet>
void fp2_curve_test_init(std::vector<Fp2CurveGroup> &points,
                    std::vector<std::size_t> &constants,
                    const TestSet &test_set) {
    using fp2_value_type = typename Fp2CurveGroup::underlying_field_type_value;
    using modulus_type = typename fp2_value_type::underlying_type::modulus_type;
    std::array<modulus_type, 6> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = modulus_type(
                    coordinate.second.data());
            }
        }
        points.emplace_back(Fp2CurveGroup(fp2_value_type(coordinates[0], coordinates[1]),
                                          fp2_value_type(coordinates[2], coordinates[3]),
                                          fp2_value_type(coordinates[4], coordinates[5])));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename Fp3CurveGroup, typename TestSet>
void fp3_curve_test_init(std::vector<Fp3CurveGroup> &points,
                    std::vector<std::size_t> &constants,
                    const TestSet &test_set) {
    using fp3_value_type = typename Fp3CurveGroup::underlying_field_type_value;
    using modulus_type = typename fp3_value_type::underlying_type::modulus_type;

    std::array<modulus_type, 9> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = modulus_type(
                    coordinate.second.data());
            }
        }
        points.emplace_back(Fp3CurveGroup(fp3_value_type(coordinates[0], coordinates[1], coordinates[2]),
                                          fp3_value_type(coordinates[3], coordinates[4], coordinates[5]),
                                          fp3_value_type(coordinates[6], coordinates[7], coordinates[8])));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename CurveGroup, typename TestSet>
void curve_operation_test(const TestSet &test_set,
                          void (&test_init)(std::vector<CurveGroup> &,
                                            std::vector<std::size_t> &,
                                            const TestSet &)) {
    std::vector<CurveGroup> points;
    std::vector<std::size_t> constants;

    test_init(points, constants, test_set);

    check_curve_operations(points, constants);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_DATA_TEST_CASE(binary_operators_test_bn128_g1, string_data("binary_operators_test_bn128_g1"), data_set) {
    using policy_type = curves::bn128<254>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_edwards_g1, string_data("binary_operators_test_edwards_g1"), data_set) {
    using policy_type = curves::edwards<183>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt4_g1, string_data("binary_operators_test_mnt4_g1"), data_set) {
    using policy_type = curves::mnt4<298>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt6_g1, string_data("binary_operators_test_mnt6_g1"), data_set) {
    using policy_type = curves::mnt6<298>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt4_g2, string_data("binary_operators_test_mnt4_g2"), data_set) {
    using policy_type = curves::mnt4<298>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_bn128_g2, string_data("binary_operators_test_bn128_g2"), data_set) {
    using policy_type = curves::bn128<254>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_edwards_g2, string_data("binary_operators_test_edwards_g2"), data_set) {
    using policy_type = curves::edwards<183>::g2_type;

    curve_operation_test<policy_type>(data_set, fp3_curve_test_init);
}

BOOST_DATA_TEST_CASE(binary_operators_test_mnt6_g2, string_data("binary_operators_test_mnt6_g2"), data_set) {
    using policy_type = curves::mnt6<298>::g2_type;

    curve_operation_test<policy_type>(data_set, fp3_curve_test_init);
}

BOOST_AUTO_TEST_SUITE_END()
