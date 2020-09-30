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
#include <vector>
#include <array>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3::algebra::pairing;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FpCurveGroup>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroup &e) {
    os << "(" << e.X.data << "," << e.Y.data << "," << e.Z.data << ")" << std::endl;
}

template<typename Fp2CurveGroup>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroup &e) {
    os << "(" << e.X.data[0].data << "," << e.X.data[1].data << "),(" << e.Y.data[0].data << ","
       << e.Y.data[1].data << "),(" << e.Z.data[0].data << "," << e.Z.data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroup>
void print_fp3_curve_group_element(std::ostream &os, const Fp3CurveGroup &e) {
    os << "(" << e.X.data[0].data << "," << e.X.data[1].data << e.X.data[2].data << "),("
       << e.Y.data[0].data << "," << e.Y.data[1].data << e.Y.data[2].data << "),("
       << e.Z.data[0].data << "," << e.Z.data[1].data << e.Z.data[2].data << ")" << std::endl;
}

template<typename Fp12_2_3_2CurveGroup>
void print_fp12_2_3_2_curve_group_element(std::ostream &os, const Fp12_2_3_2CurveGroup &e) {
    os << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
                << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
                << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
               << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
               << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]" << std::endl;
}

void print_fpt_curve_group_element(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::GT_type &e){
    print_fp12_2_3_2_curve_group_element(os, e);
}

void print_ate_g1_precomp_element(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_precomp &e) {
    os << "(" << e.PX.data << "," << e.PY.data << ")" << std::endl;
}

void print_ate_g2_precomp_element(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_precomp &e){
    os << "\"coordinates\": [[" << e.QX.data[0].data << " , " << e.QX.data[1].data << "] , ["
       << e.QY.data[0].data << " , " << e.QY.data[1].data << "]]" << std::endl;
    auto print_coeff = [&os](const auto &c){
        os << "\"ell_0\": [" << c.ell_0.data[0].data << "," << c.ell_0.data[1].data << "],"
           << "\"ell_VW\": [" << c.ell_VW.data[0].data << "," << c.ell_VW.data[1].data << "],"
           << "\"ell_VV\": [" << c.ell_VV.data[0].data << "," << c.ell_VV.data[1].data << "]";
    };
    os << "coefficients: [";
    for (auto &c : e.coeffs) {
        os << "{";
        print_coeff(c);
        os << "},";
    }
    os << "]" << std::endl;
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

            template<>
            struct print_log_value<curves::bls12<381, CHAR_BIT>::pairing_policy::G1_type> {
                void operator()(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_type &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381, CHAR_BIT>::pairing_policy::G2_type> {
                void operator()(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_type &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381, CHAR_BIT>::pairing_policy::G1_precomp> {
                void operator()(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_precomp &e) {
                    print_ate_g1_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381, CHAR_BIT>::pairing_policy::G2_precomp> {
                void operator()(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_precomp &e) {
                    print_ate_g2_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381, CHAR_BIT>::pairing_policy::GT_type> {
                void operator()(std::ostream &os, const typename curves::bls12<381, CHAR_BIT>::pairing_policy::GT_type &e) {
                    print_fpt_curve_group_element(os, e);
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

const char *test_data = "../../../../libs/algebra/test/data/pairing.json";

boost::property_tree::ptree string_data(const std::string &test_name) {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

enum Fr_enum : std::size_t {
    VKx_poly, VKy_poly, VKz_poly,
    A1_poly, B1_poly, C1_poly,
    A2_poly, B2_poly, C2_poly
};
enum G1_enum : std::size_t {
    A1, C1, A2, C2, VKx
};
enum G2_enum : std::size_t {
    B1, B2, VKy, VKz
};
enum GT_enum : std::size_t {
    pairing_A1_B1, pairing_A2_B2,
    reduced_pairing_A1_B1, reduced_pairing_A2_B2,
    reduced_pairing_A1_B1_mul_reduced_pairing_A2_B2,
    reduced_pairing_VKx_poly_A1_B1,
    miller_loop_prec_A1_prec_B1, miller_loop_prec_A2_prec_B2,
    double_miller_loop_prec_A1_prec_B1_prec_A2_prec_B2
};
enum G1_precomp_enum : std::size_t {
    prec_A1, prec_A2
};
enum G2_precomp_enum : std::size_t {
    prec_B1, prec_B2
};

template<typename PairingT, typename Fr_value_type, typename G1_value_type, typename G2_value_type,
    typename GT_value_type, typename G1_precomp_value_type, typename G2_precomp_value_type>
void check_pairing_operations(std::vector<Fr_value_type> &Fr_elements,
                              std::vector<G1_value_type> &G1_elements,
                              std::vector<G2_value_type> &G2_elements,
                              std::vector<GT_value_type> &GT_elements,
                              std::vector<G1_precomp_value_type> &G1_prec_elements,
                              std::vector<G2_precomp_value_type> &G2_prec_elements) {
    BOOST_CHECK_EQUAL((Fr_elements[A1_poly] * Fr_elements[B1_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C1_poly]);
    BOOST_CHECK_EQUAL((Fr_elements[A2_poly] * Fr_elements[B2_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C2_poly]);
    // TODO: activate when scalar multiplication done
    // BOOST_CHECK_EQUAL(Fr_elements[VKx_poly] * G1_value_type::one(),
    //                   G1_elements[VKx]);
    // BOOST_CHECK_EQUAL(Fr_elements[VKy_poly] * G2_value_type::one(),
    //                   G1_elements[VKy]);
    // BOOST_CHECK_EQUAL(Fr_elements[VKz_poly] * G2_value_type::one(),
    //                   G1_elements[VKz]);
    // BOOST_CHECK_EQUAL(Fr_elements[A1_poly] * G1_value_type::one(),
    //                   G1_elements[A1]);
    // BOOST_CHECK_EQUAL(Fr_elements[C1_poly] * G1_value_type::one(),
    //                   G1_elements[C1]);
    // BOOST_CHECK_EQUAL(Fr_elements[A2_poly] * G1_value_type::one(),
    //                   G1_elements[A2]);
    // BOOST_CHECK_EQUAL(Fr_elements[C2_poly] * G1_value_type::one(),
    //                   G1_elements[C2]);
    // BOOST_CHECK_EQUAL(Fr_elements[B1_poly] * G2_value_type::one(),
    //                   G2_elements[B1]);
    // BOOST_CHECK_EQUAL(Fr_elements[B2_poly] * G2_value_type::one(),
    //                   G2_elements[B2]);
    //
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A1]), G1_prec_elements[prec_A1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A2]), G1_prec_elements[prec_A2]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B1]), G2_prec_elements[prec_B1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B2]), G2_prec_elements[prec_B2]);
    BOOST_CHECK_EQUAL(PairingT::pairing(G1_elements[A1], G2_elements[B1]), GT_elements[pairing_A1_B1]);
    BOOST_CHECK_EQUAL(PairingT::pairing(G1_elements[A2], G2_elements[B2]), GT_elements[pairing_A2_B2]);
    // TODO: activate after reduced_pairing->cyclotomic_exp fixed. Bugs in final_exponentiation_last_chunk
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]), GT_elements[reduced_pairing_A1_B1]);
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]),
    //                   PairingT::reduced_pairing(G1_elements[VKx], G2_elements[VKy]) *
    //                       PairingT::reduced_pairing(G1_elements[C1], G2_elements[VKz]));
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   GT_elements[reduced_pairing_A2_B2]);
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   PairingT::reduced_pairing(G1_elements[VKx], G2_elements[VKy]) *
    //                       PairingT::reduced_pairing(G1_elements[C2], G2_elements[VKz]));
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]) * PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   GT_elements[reduced_pairing_A1_B1_mul_reduced_pairing_A2_B2]);
    // // TODO: activate when scalar multiplication done
    // // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]) * PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    // //                   PairingT::reduced_pairing(Fr_value_type(2) * G1_elements[VKx], G2_elements[VKy]) *
    // //                       PairingT::reduced_pairing(G1_elements[C1] + G1_elements[C2], G2_elements[VKz]));
    // // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
    // //                   GT_elements[reduced_pairing_VKx_poly_A1_B1]);
    // // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
    // //                   PairingT::reduced_pairing(G1_elements[A1], Fr_elements[VKx_poly] * G2_elements[B1]));
    // // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
    // //                   PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]).pow(VKx_poly));
    // //
    BOOST_CHECK_EQUAL(PairingT::miller_loop(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1]),
                      GT_elements[miller_loop_prec_A1_prec_B1]);
    BOOST_CHECK_EQUAL(PairingT::miller_loop(G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      GT_elements[miller_loop_prec_A2_prec_B2]);
    BOOST_CHECK_EQUAL(PairingT::double_miller_loop(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1],
                                                      G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      GT_elements[double_miller_loop_prec_A1_prec_B1_prec_A2_prec_B2]);
    BOOST_CHECK_EQUAL(PairingT::miller_loop(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1]) *
                          PairingT::miller_loop(G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      PairingT::double_miller_loop(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1],
                                                   G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]));
}

template<typename TestSet>
void pairing_test_Fr_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::Fp_type::value_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::Fp_type::value_type;
    using modulus_type = typename value_type::modulus_type;

    for (auto &fr_elem : test_set.second.get_child("Fr")) {
        elements.emplace_back(value_type(modulus_type(fr_elem.second.data())));
        // print_field_element(std::cout, elements.back());
    }
}

template<typename TestSet>
void pairing_test_G1_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::G1_type;
    using modulus_type = typename value_type::underlying_field_type_value::modulus_type;

    std::array<modulus_type, 3> coordinates;

    for (auto &elem_coords : test_set.second.get_child("G1")) {
        std::size_t i = 0;
        for (auto &elem_coord : elem_coords.second) {
            coordinates[i++] = modulus_type(elem_coord.second.data());
        }
        elements.emplace_back(value_type(coordinates[0], coordinates[1], coordinates[2]));
        // print_fp_curve_group_element(std::cout, elements.back());
    }
}

template<typename TestSet>
void pairing_test_G2_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::G2_type;
    using underlying_type = typename value_type::underlying_field_type_value;
    using modulus_type = typename underlying_type::underlying_type::modulus_type;

    std::array<modulus_type, 6> coordinates;

    for (auto &elem_coords_coords : test_set.second.get_child("G2")) {
        std::size_t i = 0;
        for (auto &elem_coords_coord : elem_coords_coords.second) {
            for (auto &elem_coord_coord : elem_coords_coord.second) {
                coordinates[i++] = modulus_type(elem_coord_coord.second.data());
            }
        }
        elements.emplace_back(value_type(underlying_type(coordinates[0], coordinates[1]),
                                         underlying_type(coordinates[2], coordinates[3]),
                                         underlying_type(coordinates[4], coordinates[5])));
        // print_fp2_curve_group_element(std::cout, elements.back());
    }
}

template<typename TestSet>
void pairing_test_GT_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::GT_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::GT_type;
    using underlying_type = typename value_type::underlying_type;
    using under_underlying_type = typename underlying_type::underlying_type;
    using modulus_type = typename under_underlying_type::underlying_type::modulus_type;

    std::array<modulus_type, 12> coordinates;

    for (auto &elem_coords_coords_coords : test_set.second.get_child("GT")) {
        std::size_t i = 0;
        for (auto &elem_coords_coords_coord : elem_coords_coords_coords.second) {
            for (auto &elem_coords_coord_coord : elem_coords_coords_coord.second) {
                for (auto &elem_coord_coord_coord : elem_coords_coord_coord.second) {
                    coordinates[i++] = modulus_type(elem_coord_coord_coord.second.data());
                }
            }
        }
        elements.emplace_back(value_type(underlying_type(under_underlying_type(coordinates[0], coordinates[1]),
                                                         under_underlying_type(coordinates[2], coordinates[3]),
                                                         under_underlying_type(coordinates[4], coordinates[5])),
                                         underlying_type(under_underlying_type(coordinates[6], coordinates[7]),
                                                         under_underlying_type(coordinates[8], coordinates[9]),
                                                         under_underlying_type(coordinates[10], coordinates[11]))));
        // print_fp12_2_3_2_curve_group_element(std::cout, elements.back());
    }
}

template<typename TestSet>
void pairing_test_G1_precomp_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::G1_precomp;
    using element_value_type = value_type::value_type;
    using modulus_type = typename element_value_type::modulus_type;

    for (auto &elem : test_set.second.get_child("G1_precomp")) {
        elements.emplace_back(value_type{element_value_type(modulus_type(elem.second.get_child("PX").data())),
                                         element_value_type(modulus_type(elem.second.get_child("PY").data()))});
        // print_ate_g1_precomp_element(std::cout, elements.back());
    }
}

template<typename TestSet>
void pairing_test_G2_precomp_init(std::vector<typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    using value_type = typename pairing_policy::G2_precomp;
    using element_value_type = value_type::value_type;
    using coeffs_type = value_type::coeffs_type::value_type;
    using coeffs_value_type = coeffs_type::value_type;
    using element_modulus_type = typename element_value_type::underlying_type::modulus_type;
    using coeffs_modulus_type = typename coeffs_value_type::underlying_type::modulus_type;

    std::array<element_modulus_type, 2> element_coordinates;
    std::array<coeffs_modulus_type, 2> coeffs_coordinates;

    for (auto &elem : test_set.second.get_child("G2_precomp")) {
        elements.emplace_back(value_type());

        std::size_t i = 0;
        for (auto &elem_QX_coord : elem.second.get_child("QX")) {
            element_coordinates[i++] = element_modulus_type(elem_QX_coord.second.data());
        }
        elements.back().QX = element_value_type(element_coordinates[0], element_coordinates[1]);

        i = 0;
        for (auto &elem_QY_coord : elem.second.get_child("QY")) {
            element_coordinates[i++] = element_modulus_type(elem_QY_coord.second.data());
        }
        elements.back().QY = element_value_type(element_coordinates[0], element_coordinates[1]);

        for (auto &elem_coeffs : elem.second.get_child("coeffs")) {
            elements.back().coeffs.emplace_back(coeffs_type());

            i = 0;
            for (auto &ell_0_coord : elem_coeffs.second.get_child("ell_0")) {
                coeffs_coordinates[i++] = coeffs_modulus_type(ell_0_coord.second.data());
            }
            elements.back().coeffs.back().ell_0 = coeffs_value_type(coeffs_coordinates[0],
                                                                    coeffs_coordinates[1]);

            i = 0;
            for (auto &ell_VW_coord : elem_coeffs.second.get_child("ell_VW")) {
                coeffs_coordinates[i++] = coeffs_modulus_type(ell_VW_coord.second.data());
            }
            elements.back().coeffs.back().ell_VW = coeffs_value_type(coeffs_coordinates[0],
                                                                     coeffs_coordinates[1]);

            i = 0;
            for (auto &ell_VV_coord : elem_coeffs.second.get_child("ell_VV")) {
                coeffs_coordinates[i++] = coeffs_modulus_type(ell_VV_coord.second.data());
            }
            elements.back().coeffs.back().ell_VV = coeffs_value_type(coeffs_coordinates[0],
                                                                     coeffs_coordinates[1]);
        }
        // print_ate_g2_precomp_element(std::cout, elements.back());
    }
}

template<typename Fr_value_type, typename G1_value_type, typename G2_value_type, typename GT_value_type,
    typename G1_precomp_value_type, typename G2_precomp_value_type, typename TestSet>
void pairing_test_init(std::vector<Fr_value_type> &Fr_elements,
                       std::vector<G1_value_type> &G1_elements,
                       std::vector<G2_value_type> &G2_elements,
                       std::vector<GT_value_type> &GT_elements,
                       std::vector<G1_precomp_value_type> &G1_prec_elements,
                       std::vector<G2_precomp_value_type> &G2_prec_elements,
                       const TestSet &test_set) {
    pairing_test_Fr_init(Fr_elements, test_set);
    pairing_test_G1_init(G1_elements, test_set);
    pairing_test_G2_init(G2_elements, test_set);
    pairing_test_GT_init(GT_elements, test_set);
    pairing_test_G1_precomp_init(G1_prec_elements, test_set);
    pairing_test_G2_precomp_init(G2_prec_elements, test_set);
}

template<typename PairingT, typename TestSet>
void pairing_operation_test(const TestSet &test_set) {
    std::vector<typename PairingT::Fp_type::value_type> Fr_elements;
    std::vector<typename PairingT::G1_type> G1_elements;
    std::vector<typename PairingT::G2_type> G2_elements;
    std::vector<typename PairingT::GT_type> GT_elements;
    std::vector<typename PairingT::G1_precomp> G1_prec_elements;
    std::vector<typename PairingT::G2_precomp> G2_prec_elements;

    pairing_test_init(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements, G2_prec_elements, test_set);
    check_pairing_operations<PairingT>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements, G2_prec_elements);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

    BOOST_DATA_TEST_CASE(pairing_operation_test_bls12_381, string_data("pairing_operation_test_bls12_381"), data_set) {
        using pairing_policy = typename curves::bls12<381, CHAR_BIT>::pairing_policy;

        pairing_operation_test<pairing_policy>(data_set);
    }

    // BOOST_AUTO_TEST_CASE(curves_manual_test1) {
    //     using PairingT = typename curves::bls12<381, CHAR_BIT>::pairing_policy;
    //     using g1_value_type = typename PairingT::G1_type::underlying_field_type_value;
    //     using g2_value_type = typename PairingT::G2_type::underlying_field_type_value;
    //     using modulus_type_g1 = typename g1_value_type::modulus_type;
    //     using modulus_type_g2 = typename g2_value_type::underlying_type::modulus_type;
    //
    //     g1_value_type A1_0(modulus_type_g1("2244088338878515068076034612456282033420001690023847623067411812553166833938927361152918087997340403447124889369809")),
    //         A1_1(modulus_type_g1("196554475430287644779948037329204074070644001213668031277007180253142440060513973955866033252824585754533710057861")),
    //         A1_2(modulus_type_g1("3198405624169629554226082162590269563517244624190831852799275194047813770544455224440477803282296551826167425525681")),
    //         C1_0(modulus_type_g1("1471895319918289971254337138964546401220112747954020508480155412870941997836481242777328044284390379955881423657874")),
    //         C1_1(modulus_type_g1("2618604062792141454078932281453725010784076878043065087206897422592110257207033190723558669281362547394160036132934")),
    //         C1_2(modulus_type_g1("3346995343222580987332684176539676068387282031514003708649444718724701957389494563087158275970629970676094344013716")),
    //         A2_0(modulus_type_g1("2682249689520653567439648689330426342692194809082003481546430009093851689167073683596090652757892426575278004015494")),
    //         A2_1(modulus_type_g1("2628994491005091070772644616155366903116347684115229884523119855557130215849874209571213504230673898212114696842906")),
    //         A2_2(modulus_type_g1("990031967156779680479158878658096770751682392790700376117398337504602519305614581667679742414685742826330366544007")),
    //         C2_0(modulus_type_g1("926087019097931748358038872074795078668470001418463937870916782910937029074077606674282732186233584482364885121915")),
    //         C2_1(modulus_type_g1("706783273826355790527215974164813571543002470821870676624040636854657378567584986120219589290194541275397462495843")),
    //         C2_2(modulus_type_g1("2660354959187513575805636966459453423037613073836654906177183849869104805673167376720409013777929692014159886825095")),
    //         VKx_0(modulus_type_g1("834946260353562728671474806796982283757426166377644633837889112998808435981910129014575188011152065892115125718906")),
    //         VKx_1(modulus_type_g1("3967489100780754588433666671337162437996660214844031967764161018203813359293552438462106740767038901514326103172391")),
    //         VKx_2(modulus_type_g1("3681536275912437150471312293359456304560969829433125410038907757394388073963314949960747154221947493701835699651918"));
    //     typename PairingT::G1_type A1(A1_0, A1_1, A1_2),
    //         C1(C1_0, C1_1, C1_2),
    //         A2(A2_0, A2_1, A2_2),
    //         C2(C2_0, C2_1, C2_0),
    //         VKx(VKx_0, VKx_1, VKx_2);
    //     g2_value_type B1_0(modulus_type_g2("14475269082931950307770582105299646555664714294518657312104513709608629674021538616619827399553062457321149410436"),
    //                        modulus_type_g2("3306316611826963303603178407033839564556280493536653138109029267606300925416762655052439328558493044405545974080618")),
    //         B1_1(modulus_type_g2("3417039541855019527149261752143556964694798976953800573792682044770922088570815330396866165435561177837622652711501"),
    //              modulus_type_g2("3116681340961638916827099897143450964566623086308256263235819172215795272656651444314519727757311250462709842226807")),
    //         B1_2(modulus_type_g2("819002616090911538956215027775694565827318529518101972322890937361314397746477933724925821512874989419622299879786"),
    //              modulus_type_g2("2698454278925126642390612414282053282609869206826499574237392619753460280306151167829906769371560475652661508760542")),
    //         B2_0(modulus_type_g2("954871950632861228861626790859028993559019479905651434033894237773196995908198753462215651224849086275815499977584"),
    //              modulus_type_g2("224557252924510985819264786488868532333906099651246153548388261756454798637280956395662285702554789984626177992114")),
    //         B2_1(modulus_type_g2("1162130201198147610643266122811228275498486973982789887313247676582480770639105996140647018081832391666510546217440"),
    //              modulus_type_g2("2678643760099406123530390826515016021196110189903328373281039053909413044618946298805179983082243172155318349166693")),
    //         B2_2(modulus_type_g2("2701543554678261336944870032245480070240520118713097488337891564344751598251505728771031801668532643002566856655585"),
    //              modulus_type_g2("2643636584007815899332574827150381812052714655589887885139617737156594920976975003603793376755975180312154205229788")),
    //         VKy_0(modulus_type_g2("3005482287548021625292019079537506745463317909552731664427293371763598338872770034439796611020834486577882127807089"),
    //              modulus_type_g2("1320061601507396534410684443815478159413531325333771069230596444536551181850973298366993636267285633165570780895770")),
    //         VKy_1(modulus_type_g2("3138676019805081207549801370240340972606056294623671254994115228127258456564048094207014961929330315905145373377760"),
    //              modulus_type_g2("1116025990409568523618033720248856254503176729411706173311608923263029364033099154767258621229988817847929344207559")),
    //         VKy_2(modulus_type_g2("1214709919203374785838295846700246658862888634658550865704373956400149533950916599617153109361810965734928174404665"),
    //              modulus_type_g2("534094893882288898775718833321488880658258618535311001525144502355817934147218316518821953721124079797136890480468")),
    //         VKz_0(modulus_type_g2("2761785722516608794832891110723308806096178023759736184844692241159337344624724070863704054655803695202697879786237"),
    //               modulus_type_g2("2031520148780009860888929519200337883783969227820766168078513715009205584635844980278378987353993358368322391347510")),
    //         VKz_1(modulus_type_g2("362898654090295917075272425837920809380156902549910956692233062417396109229376815440210067308202576805613886477127"),
    //               modulus_type_g2("2772668732934018150857459271555770758037185987210653550038496923162227777754026152909585727706978303258399840314364")),
    //         VKz_2(modulus_type_g2("1655424192950924845327353814264530159481188297621649842616825942762963996599767999845445354318057957011450509847237"),
    //               modulus_type_g2("1587079656861128476897944618540424550870467554873815651595522957552964588833982435172407598044597026969767257717273"));
    //     typename PairingT::G2_type B1(B1_0, B1_1, B1_2),
    //         B2(B2_0, B2_1, B2_2),
    //         VKy(VKy_0, VKy_1, VKy_2),
    //         VKz(VKz_0, VKz_1, VKz_2);
    //     typename PairingT::G1_precomp prec_A1 = PairingT::precompute_g1(A1);
    //     // std::cout << "A1:" << std::endl;
    //     // print_fp_curve_group_element(std::cout, A1);
    //     // std::cout << "prec_A1:" << std::endl;
    //     // print_ate_g1_precomp_element(std::cout, prec_A1);
    //     typename PairingT::G1_precomp prec_A2 = PairingT::precompute_g1(A2);
    //     // std::cout << "A2:" << std::endl;
    //     // print_fp_curve_group_element(std::cout, A2);
    //     // std::cout << "prec_A2:" << std::endl;
    //     // print_ate_g1_precomp_element(std::cout, prec_A2);
    //     typename PairingT::G2_precomp prec_B1 = PairingT::precompute_g2(B1);
    //     // std::cout << "B1:" << std::endl;
    //     // print_fp2_curve_group_element(std::cout, B1);
    //     // std::cout << "prec_B1:" << std::endl;
    //     // print_ate_g2_precomp_element(std::cout, prec_B1);
    //     typename PairingT::G2_precomp prec_B2 = PairingT::precompute_g2(B2);
    //     // std::cout << "B2:" << std::endl;
    //     // print_fp2_curve_group_element(std::cout, B2);
    //     // std::cout << "prec_B2:" << std::endl;
    //     // print_ate_g2_precomp_element(std::cout, prec_B2);
    //     // TODO: fix reduced_pairing when cyclotomic_exp will be done. Bugs in final_exponentiation_last_chunk
    //     // typename PairingT::GT_type A1_B1 = PairingT::reduced_pairing(A1, B1);
    //     // std::cout << "B1:" << std::endl;
    //     // print_fp2_curve_group_element(std::cout, B1);
    //     // std::cout << "A1_B1:" << std::endl;
    //     // print_fpt_curve_group_element(std::cout, A1_B1);
    //     typename PairingT::GT_type ml_prec_A1_prec_B1 = PairingT::miller_loop(prec_A1, prec_B1);
    //     // std::cout << "ml_prec_A1_prec_B1:" << std::endl;
    //     // print_fp12_2_3_2_curve_group_element(std::cout, ml_prec_A1_prec_B1);
    //     typename PairingT::GT_type ml_prec_A2_prec_B2 = PairingT::miller_loop(prec_A2, prec_B2);
    //     // std::cout << "ml_prec_A2_prec_B2:" << std::endl;
    //     // print_fp12_2_3_2_curve_group_element(std::cout, ml_prec_A2_prec_B2);
    //     typename PairingT::GT_type dbml = PairingT::double_miller_loop(prec_A1, prec_B1, prec_A2, prec_B2);
    //     // std::cout << "dbml:" << std::endl;
    //     // print_fp12_2_3_2_curve_group_element(std::cout, dbml);
    //     typename PairingT::GT_type dbml_mul = ml_prec_A1_prec_B1 * ml_prec_A2_prec_B2;
    //     // std::cout << "dbml_mul:" << std::endl;
    //     // print_fp12_2_3_2_curve_group_element(std::cout, dbml_mul);
    //     BOOST_CHECK_EQUAL(dbml, dbml_mul);
    // }

BOOST_AUTO_TEST_SUITE_END()
