//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE curves_algebra_test

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

#include <boost/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::algebra;

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
    p1_to_affine_coordinates,
    p2_to_special
};

template<typename CurveGroup>
void check_curve_operations(const std::vector<typename CurveGroup::value_type> &points,
                            const std::vector<std::size_t> &constants) {
    using boost::multiprecision::cpp_int;

    BOOST_CHECK_EQUAL(points[p1] + points[p2], points[p1_plus_p2]);
    BOOST_CHECK_EQUAL(points[p1] - points[p2], points[p1_minus_p2]);
    BOOST_CHECK_EQUAL(points[p1].doubled(), points[p1_dbl]);
    BOOST_CHECK_EQUAL(points[p1].mixed_add(points[p2]), points[p1_mixed_add_p2]);
    typename CurveGroup::value_type p1_copy = typename CurveGroup::value_type(points[p1]).to_affine_coordinates();
    BOOST_CHECK_EQUAL(p1_copy, points[p1_to_affine_coordinates]);
    typename CurveGroup::value_type p2_copy = typename CurveGroup::value_type(points[p2]).to_special();
    BOOST_CHECK_EQUAL(p2_copy, points[p2_to_special]);
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

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

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


BOOST_AUTO_TEST_SUITE(curves_manual_static_tests)

BOOST_AUTO_TEST_CASE(curve_operation_test_bls12_381_g1) {
    using curve_type = typename curves::bls12<381>::g1_type;
    using curve_value_type = typename curve_type::value_type;
    using field_type = typename curve_type::underlying_field_type;
    using field_value_type = typename field_type::value_type;

    constexpr field_value_type x1 = 0x19a8ce51e3507d9ed66343fc7abda65f24a02a5054c262ba82dd067f91de595469ba0029571b22007d3712a51a14b66b_cppui381;
    constexpr field_value_type y1 = 0x151c956a92fe067a60533e2f9f4d90c75a460f9ca0a6d3beb2b0388fe2be7f1f21de58af7fd2c85ef13326856408a3a4_cppui381;
    constexpr field_value_type z1 = 0x814f8119ab9939282414f63efe8421ea0893343f697dba821cc21abb4c0c72573c542becd25d84d3f97d76951cb44bd_cppui381;
    constexpr curve_value_type p1(x1, y1, z1);

    constexpr field_value_type x2 = 0xe5944419aae6b311708fdee3e7a3169ef47f7a509ec5e6781a918eb42294a0c3a3916df0f5c3bf75b1553ee7c66198a_cppui381;
    constexpr field_value_type y2 = 0x80f8b87d65fa717f44c74f944e6f8b9c5493a87bfa0b48395c6326ad2c83e848280a7b7a81cfc3e44be18c2b721cf31_cppui381;
    constexpr field_value_type z2 = 0x12dde0758a406a2d79166ade03f68799b359910c31d65ccb63090720eb6191393661cf26c3e83c922a804305027c2803_cppui381;
    constexpr curve_value_type p2(x2, y2, z2);

    constexpr field_value_type x3 = 0x13034f3fbe9a557cc7daf9aaffbc1a4b3d1a4c88c11ba5fd4502aed63ed08f3f52e1bce1ba9a5ea70d862436cd8c0a53_cppui381;
    constexpr field_value_type y3 = 0x2c731465ff3bd544bd350c9b6bb5fafca2cbfe31c0a3221566d1fc5547d463914b64e26b4107a78c0179a004c7642af_cppui381;
    constexpr field_value_type z3 = 0x214b8ebcf8c5293040a2c85d41d27593829f116fb11224cb6b530a288bc66e3d4007d5087f71aa1c209f9d98b87111f_cppui381;
    constexpr curve_value_type p_add(x3, y3, z3);

    constexpr field_value_type x4 = 0x8d3551b80950015b4dbaac4c60e7c48f1470c13ca93b203f1e3d38e874a4c19356b237b823ee551865afa5f7eefd487_cppui381;
    constexpr field_value_type y4 = 0xfa74f3643c4fef7f88fb5d844652185d8343f5c2f2a4394c626d8f3c773bd9d60158f30158f1feefa7b6c12e07cf0ef_cppui381;
    constexpr field_value_type z4 = 0x214b8ebcf8c5293040a2c85d41d27593829f116fb11224cb6b530a288bc66e3d4007d5087f71aa1c209f9d98b87111f_cppui381;
    constexpr curve_value_type p_sub(x4, y4, z4);

    constexpr field_value_type x5 = 0x111152cbd1f7ff876f9f13ceacf6a535831ff5fbf59fe5f54ce37efef87b70ba89bc47d8d63c85565e29c4e1310cc8e9_cppui381;
    constexpr field_value_type y5 = 0x16e86e2375254ce972334364277bc8ada71598631902013b23356752e653f6b51eeebf72cb72b446e8f32208ef27c58_cppui381;
    constexpr field_value_type z5 = 0xe2b294ae8d8181dc4fd9c6edfe3d79215232abbacd879e339e9fb7ffc7d8158f292c1c408731d227507181e16708cbc_cppui381;
    constexpr curve_value_type p_mul_C(x5, y5, z5);
    constexpr auto C1 = 0x2b4bd538_cppui381;

    constexpr field_value_type x6 = 0x163c6586913d88ba0ca1f082e90f5dc6b97c9b8fc28e9f9f6140c357a8b97c20088da93e51089a3d870c9ac4cd7419ec_cppui381;
    constexpr field_value_type y6 = 0x1987e74481a1bfa0ba3f38753c44af0cf77d64753812a22ed2c83f64990a5735ccb24aebc72b8ab559cab1a76e1fd20b_cppui381;
    constexpr field_value_type z6 = 0xe65506b39c7874b40449480e82a0f94e09702038694504b36b90750c36b606c8691311677d524faa9d6d37ccd401880_cppui381;
    constexpr curve_value_type p_mul_C1_plus_p_mul_C2(x6, y6, z6);
    constexpr auto C2 = 0x33345b17_cppui381;

    constexpr field_value_type x7 = 0x10d19f9eee3414eadafe29124a9fef7375febc627b1441803e4dad963d09933da41008344e943c78ffde3559f2178355_cppui381;
    constexpr field_value_type y7 = 0xdb1e67d87a21b1fdbbd3c144e316b160cc9b2c54d89899d6f653b67e55380f58998d689fa67365a0db92feb2c05cc2d_cppui381;
    constexpr field_value_type z7 = 0x148e0002306d83c5334f9224aa8ef6392241ccf700b85ace54543c16bb8cab1850ba1c98cd1b57e02e033ad0556fa2d9_cppui381;
    constexpr curve_value_type p_dbl(x7, y7, z7);

    constexpr field_value_type x8 = 0x10b20f5e7f5b503c38c4b78ae6d9cbd6abd5290b6be91dcf7d68c7fa75b3f1c034625651fff0bd1d8f0fb860a2df3989_cppui381;
    constexpr field_value_type y8 = 0xbc3f46e7c56be14cb259b918e1c36ac8eabe791a408bd53bb14fb3c1211bfd7e445f7890fe369446943fb8de6cbe7_cppui381;
    constexpr field_value_type z8 = 0x7d39ff04059ee3118e7b1e694e5e5e0b4f8982bffddb4ae5cc35a00546819ea2a5c92c5e9fbf3078bc102d1dc8d1162_cppui381;
    constexpr curve_value_type p_mixed_add(x8, y8, z8);

    constexpr field_value_type x9 = 0x97c062b9a9bee0bc02f762c7b7057a0cfa52f336f9bce0b130aaa2402bc7c820cc4f30f29ed69d87342c3137659af29_cppui381;
    constexpr field_value_type y9 = 0x10eabcbf296774122daf3b60e289f0885485b66c4111d1a229bea7566aea5c9f87d1cbc8ae752e13288ec885d3f97eb6_cppui381;
    constexpr field_value_type z9 = 0x1_cppui381;
    constexpr curve_value_type p_to_affine(x9, y9, z9);

    constexpr field_value_type x10 = 0xf2d335bf6370059219a693b1b50dfe9f966c371f052b36f70e426bf84750dcd4bb3da3beeef4e013c4532f4f78e06c1_cppui381;
    constexpr field_value_type y10 = 0x54deeaa0db80987f8d81cfb4c716ae590c3b7641656f3fef45859a6446144c6eb191bbeb88929cbd90b2b9995574c90_cppui381;
    constexpr field_value_type z10 = 0x1_cppui381;
    constexpr curve_value_type p_to_special(x10, y10, z10);

    static_assert(p1 + p2 == p_add, "add error");
    static_assert(p1 - p2 == p_sub, "sub error");
    static_assert(p1 * C1 == p_mul_C, "mul error");
    static_assert(p2 * C1 + p2 * C2 == p_mul_C1_plus_p_mul_C2, "mul add mul error");
    static_assert(p1.doubled() == p_dbl, "double error");
    static_assert(p1.mixed_add(p2) == p_mixed_add, "mixed add error");
    static_assert(p1.to_affine_coordinates() == p_to_affine, "to affine error");
    static_assert(p2.to_special() == p_to_special, "to special error");
}

BOOST_AUTO_TEST_SUITE_END()
