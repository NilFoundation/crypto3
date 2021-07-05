//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_curves_test

#include <iostream>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
// #include <nil/crypto3/algebra/curves/brainpool_r1.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
// #include <nil/crypto3/algebra/curves/frp_v1.hpp>
// #include <nil/crypto3/algebra/curves/gost_A.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
// #include <nil/crypto3/algebra/curves/p192.hpp>
// #include <nil/crypto3/algebra/curves/p224.hpp>
// #include <nil/crypto3/algebra/curves/p256.hpp>
// #include <nil/crypto3/algebra/curves/p384.hpp>
// #include <nil/crypto3/algebra/curves/p521.hpp>
// #include <nil/crypto3/algebra/curves/secp.hpp>
// #include <nil/crypto3/algebra/curves/sm2p_v1.hpp>
// #include <nil/crypto3/algebra/curves/x962_p.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp<FieldParams> e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp2<FieldParams> e) {
    std::cout << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp3<FieldParams> e) {
    std::cout << e.data[0].data << " " << e.data[1].data << " " << e.data[2].data << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )";
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroupElement>
void print_fp3_curve_group_element(std::ostream &os, const Fp3CurveGroupElement &e) {
    os << "(" << e.X.data[0].data << " , " << e.X.data[1].data << " , " << e.X.data[2].data << ") : ("
       << e.Y.data[0].data << " , " << e.Y.data[1].data << " , " << e.Y.data[2].data << ") : (" << e.Z.data[0].data
       << " , " << e.Z.data[1].data << " , " << e.Z.data[2].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {

            template<>
            struct print_log_value<typename curves::jubjub::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::jubjub::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::edwards<183>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::edwards<183>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt4<298>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::mnt4<298>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt6<298>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::mnt6<298>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::alt_bn128<254>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::alt_bn128<254>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<377>::g1_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<377>::g1_type::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt4<298>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::mnt4<298>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<381>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<381>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::bls12<377>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::bls12<377>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::alt_bn128<254>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::alt_bn128<254>::g2_type::value_type const &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::edwards<183>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::edwards<183>::g2_type::value_type const &e) {
                    print_fp3_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::mnt6<298>::g2_type::value_type> {
                void operator()(std::ostream &os, typename curves::mnt6<298>::g2_type::value_type const &e) {
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
const char *test_data = "../../../../libs/algebra/test/data/curves.json";

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
    p1_dbl,
    p1_mixed_add_p2,
    p1_to_affine,
    p2_to_special
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
    BOOST_CHECK_EQUAL(points[p1].mixed_add(points[p2]), points[p1_mixed_add_p2]);
    typename CurveGroup::value_type p1_copy = typename CurveGroup::value_type(points[p1]).to_affine();
    BOOST_CHECK_EQUAL(p1_copy, points[p1_to_affine]);
    typename CurveGroup::value_type p2_copy = typename CurveGroup::value_type(points[p2]).to_projective();
    BOOST_CHECK_EQUAL(p2_copy, points[p2_to_special]);
}

// temporary separated test for JubJub and BabyJubJub
template<typename CurveGroup>
void check_curve_operations_twisted_edwards(const std::vector<typename CurveGroup::value_type> &points,
                            const std::vector<typename CurveGroup::curve_type::number_type> &constants) {
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
    // BOOST_CHECK_EQUAL(points[p1].mixed_add(points[p2]), points[p1_mixed_add_p2]);
    // typename CurveGroup::value_type p1_copy = typename CurveGroup::value_type(points[p1]).to_affine();
    // BOOST_CHECK_EQUAL(p1_copy, points[p1_to_affine]);
    // typename CurveGroup::value_type p2_copy = typename CurveGroup::value_type(points[p2]).to_projective();
    // BOOST_CHECK_EQUAL(p2_copy, points[p2_to_special]);
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_test_init(std::vector<typename FpCurveGroup::value_type> &points,
                        std::vector<std::size_t> &constants,
                        const TestSet &test_set) {
    typedef typename FpCurveGroup::underlying_field_type::value_type field_value_type;
    std::array<field_value_type, 3> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::modulus_type(coordinate.second.data()));
        }
        points.emplace_back(typename FpCurveGroup::value_type(coordinates[0], coordinates[1], coordinates[2]));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename FpCurveGroup, typename TestSet>
void fp_curve_twisted_edwards_test_init(std::vector<typename FpCurveGroup::value_type> &points,
                        std::vector<typename FpCurveGroup::curve_type::number_type> &constants,
                        const TestSet &test_set) {
    typedef typename FpCurveGroup::underlying_field_type::value_type field_value_type;
    std::array<field_value_type, 3> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate : point.second) {
            coordinates[i++] = field_value_type(typename field_value_type::modulus_type(coordinate.second.data()));
        }
        points.emplace_back(typename FpCurveGroup::value_type(coordinates[0], coordinates[1]));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(typename FpCurveGroup::curve_type::number_type(constant.second.data()));
    }
}

template<typename Fp2CurveGroup, typename TestSet>
void fp2_curve_test_init(std::vector<typename Fp2CurveGroup::value_type> &points,
                         std::vector<std::size_t> &constants,
                         const TestSet &test_set) {
    using fp2_value_type = typename Fp2CurveGroup::underlying_field_type::value_type;
    using modulus_type = typename fp2_value_type::underlying_type::modulus_type;
    std::array<modulus_type, 6> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = modulus_type(coordinate.second.data());
            }
        }
        points.emplace_back(typename Fp2CurveGroup::value_type(fp2_value_type(coordinates[0], coordinates[1]),
                                                               fp2_value_type(coordinates[2], coordinates[3]),
                                                               fp2_value_type(coordinates[4], coordinates[5])));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoul(constant.second.data()));
    }
}

template<typename Fp3CurveGroup, typename TestSet>
void fp3_curve_test_init(std::vector<typename Fp3CurveGroup::value_type> &points,
                         std::vector<std::size_t> &constants,
                         const TestSet &test_set) {
    using fp3_value_type = typename Fp3CurveGroup::underlying_field_type::value_type;
    using modulus_type = typename fp3_value_type::underlying_type::modulus_type;

    std::array<modulus_type, 9> coordinates;

    for (auto &point : test_set.second.get_child("point_coordinates")) {
        auto i = 0;
        for (auto &coordinate_pairs : point.second) {
            for (auto &coordinate : coordinate_pairs.second) {
                coordinates[i++] = modulus_type(coordinate.second.data());
            }
        }
        points.emplace_back(
            typename Fp3CurveGroup::value_type(fp3_value_type(coordinates[0], coordinates[1], coordinates[2]),
                                               fp3_value_type(coordinates[3], coordinates[4], coordinates[5]),
                                               fp3_value_type(coordinates[6], coordinates[7], coordinates[8])));
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

template<typename CurveGroup, typename TestSet>
void curve_operation_test_twisted_edwards(const TestSet &test_set,
                          void (&test_init)(std::vector<typename CurveGroup::value_type> &,
                                            std::vector<typename CurveGroup::curve_type::number_type> &,
                                            const TestSet &)) {

    std::vector<typename CurveGroup::value_type> points;
    std::vector<typename CurveGroup::curve_type::number_type> constants;

    test_init(points, constants, test_set);

    check_curve_operations_twisted_edwards<CurveGroup>(points, constants);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_DATA_TEST_CASE(curve_operation_test_jubjub_g1, string_data("curve_operation_test_jubjub_g1"), data_set) {
    using policy_type = curves::jubjub::g1_type;

    curve_operation_test_twisted_edwards<policy_type>(data_set, fp_curve_twisted_edwards_test_init<policy_type>);
}

BOOST_AUTO_TEST_CASE(curve_operation_test_babyjubjub_g1) {
    using policy_type = curves::babyjubjub::g1_type;

    typename policy_type::value_type P1(typename policy_type::underlying_field_type::value_type(0x274DBCE8D15179969BC0D49FA725BDDF9DE555E0BA6A693C6ADB52FC9EE7A82C_cppui254),
                          typename policy_type::underlying_field_type::value_type(0x5CE98C61B05F47FE2EAE9A542BD99F6B2E78246231640B54595FEBFD51EB853_cppui251)), 
                       P2(typename policy_type::underlying_field_type::value_type(0x2491ABA8D3A191A76E35BC47BD9AFE6CC88FEE14D607CBE779F2349047D5C157_cppui254),
                          typename policy_type::underlying_field_type::value_type(0x2E07297F8D3C3D7818DBDDFD24C35583F9A9D4ED0CB0C1D1348DD8F7F99152D7_cppui254)),
                       P3(typename policy_type::underlying_field_type::value_type(0x11805510440A3488B3B811EAACD0EC7C72DDED51978190E19067A2AFAEBAF361_cppui253),
                          typename policy_type::underlying_field_type::value_type(0x1F07AA1B3C598E2FF9FF77744A39298A0A89A9027777AF9FA100DD448E072C13_cppui253));

    typename policy_type::value_type P1pP2 = P1 + P2;

    BOOST_CHECK(P1 + P2 == P3);

    typename policy_type::value_type 
                       P4(typename policy_type::underlying_field_type::value_type(0xF3C160E26FC96C347DD9E705EB5A3E8D661502728609FF95B3B889296901AB5_cppui252),
                          typename policy_type::underlying_field_type::value_type(0x9979273078B5C735585107619130E62E315C5CAFE683A064F79DFED17EB14E1_cppui252));

    BOOST_CHECK(P1.doubled() == P4);

    typename policy_type::value_type
        P5(typename policy_type::underlying_field_type::value_type(0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c_cppui252),
           typename policy_type::underlying_field_type::value_type(0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853_cppui252)),
        et_s1P5(typename policy_type::underlying_field_type::value_type(0x2ad46cbfb78773b6254adc1d80c6efa02f3bf948c37e5a2222136421d7bec942_cppui252),
           typename policy_type::underlying_field_type::value_type(0x14e9693f16d75f7065ce51e1f46ae6c60841ca1e0cf264eda26398e36ca2ed69_cppui252)),
        et_s2P5(typename policy_type::underlying_field_type::value_type(0x25bd7aefee96617d4f715ecf8e50ef9fa102eeb452642c6322d38aa9b32c2ca5_cppui252),
               typename policy_type::underlying_field_type::value_type(0x8e043ec729eedea414b63de474c8f0930ea966733ae283e01f348ca3c35e3ab_cppui252)),
        P6(typename policy_type::underlying_field_type::value_type(0xf3c160e26fc96c347dd9e705eb5a3e8d661502728609ff95b3b889296901ab5_cppui252),
           typename policy_type::underlying_field_type::value_type(0x9979273078b5c735585107619130e62e315c5cafe683a064f79dfed17eb14e1_cppui252)),
        et_s1P6(typename policy_type::underlying_field_type::value_type(0x1dfce39036af5e722b6c8a3214b93b93b2eac662ec2cf67195ef3994b944fb0f_cppui252),
                typename policy_type::underlying_field_type::value_type(0x12aa55c3cc7ff986c520ddcae3927877e682f01bed87628f643f34905692880e_cppui252))
        ;

    BOOST_CHECK(et_s1P5 == static_cast<nil::crypto3::multiprecision::cpp_int>(3) * P5);
    BOOST_CHECK(et_s2P5 == nil::crypto3::multiprecision::cpp_int("14035240266687799601661095864649209771790948434046947201833777492504781204499") * P5);
    BOOST_CHECK(et_s1P6 == nil::crypto3::multiprecision::cpp_int("20819045374670962167435360035096875258406992893633759881276124905556507972311") * P6);
    BOOST_CHECK(P5.is_well_formed());
    BOOST_CHECK(P6.is_well_formed());

    // curve_operation_test_twisted_edwards<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_edwards_g1, string_data("curve_operation_test_edwards_g1"), data_set) {
    using policy_type = curves::edwards<183>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt4_g1, string_data("curve_operation_test_mnt4_g1"), data_set) {
    using policy_type = curves::mnt4<298>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt6_g1, string_data("curve_operation_test_mnt6_g1"), data_set) {
    using policy_type = curves::mnt6<298>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt4_g2, string_data("curve_operation_test_mnt4_g2"), data_set) {
    using policy_type = curves::mnt4<298>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_edwards_g2, string_data("curve_operation_test_edwards_g2"), data_set) {
    using policy_type = curves::edwards<183>::g2_type;

    curve_operation_test<policy_type>(data_set, fp3_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_mnt6_g2, string_data("curve_operation_test_mnt6_g2"), data_set) {
    using policy_type = curves::mnt6<298>::g2_type;

    curve_operation_test<policy_type>(data_set, fp3_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_381_g1, string_data("curve_operation_test_bls12_381_g1"), data_set) {
    using policy_type = curves::bls12<381>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_377_g1, string_data("curve_operation_test_bls12_377_g1"), data_set) {
    using policy_type = curves::bls12<377>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_381_g2, string_data("curve_operation_test_bls12_381_g2"), data_set) {
    using policy_type = curves::bls12<381>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_bls12_377_g2, string_data("curve_operation_test_bls12_377_g2"), data_set) {
    using policy_type = curves::bls12<377>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_alt_bn128_g1, string_data("curve_operation_test_alt_bn128_g1"), data_set) {
    using policy_type = curves::alt_bn128<254>::g1_type;

    curve_operation_test<policy_type>(data_set, fp_curve_test_init<policy_type>);
}

BOOST_DATA_TEST_CASE(curve_operation_test_alt_bn128_g2, string_data("curve_operation_test_alt_bn128_g2"), data_set) {
    using policy_type = curves::alt_bn128<254>::g2_type;

    curve_operation_test<policy_type>(data_set, fp2_curve_test_init<policy_type>);
}

BOOST_AUTO_TEST_SUITE_END()
