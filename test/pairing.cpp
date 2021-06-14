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
#include <vector>
#include <array>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp4<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_2over3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]";
}

template<typename CurveGroupValue>
void print_curve_group_element(std::ostream &os, const CurveGroupValue &e) {
    os << "(";
    print_field_element(os, e.X);
    os << ",";
    print_field_element(os, e.Y);
    os << ",";
    print_field_element(os, e.Z);
    os << ")" << std::endl;
}

void print_g1_precomp_element(std::ostream &os, const typename curves::bls12<381>::pairing::g1_precomp &e) {
    os << "{\"PX\": ";
    print_field_element(os, e.PX);
    os << ", \"PY\": ";
    print_field_element(os, e.PY);
    os << "}" << std::endl;
}

void print_g1_precomp_element(std::ostream &os, const typename curves::mnt4<298>::pairing::g1_precomp &e) {
    os << "{\"PX\": ";
    print_field_element(os, e.PX);
    os << ", \"PY\": ";
    print_field_element(os, e.PY);
    os << ", \"PX_twist\": ";
    print_field_element(os, e.PX_twist);
    os << ", \"PY_twist\": ";
    print_field_element(os, e.PY_twist);
    os << "}" << std::endl;
}

void print_g1_precomp_element(std::ostream &os, const typename curves::mnt6<298>::pairing::g1_precomp &e) {
    os << "{\"PX\": ";
    print_field_element(os, e.PX);
    os << ", \"PY\": ";
    print_field_element(os, e.PY);
    os << ", \"PX_twist\": ";
    print_field_element(os, e.PX_twist);
    os << ", \"PY_twist\": ";
    print_field_element(os, e.PY_twist);
    os << "}" << std::endl;
}

void print_g2_precomp_element(std::ostream &os, const typename curves::bls12<381>::pairing::g2_precomp &e) {
    os << "\"coordinates\": [[" << e.QX.data[0].data << " , " << e.QX.data[1].data << "] , [" << e.QY.data[0].data
       << " , " << e.QY.data[1].data << "]]" << std::endl;
    auto print_coeff = [&os](const auto &c) {
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

void print_g2_precomp_element(std::ostream &os, const typename curves::mnt4<298>::pairing::g2_precomp &e) {
    os << "\"coordinates\": {\"QX\": ";
    print_field_element(os, e.QX);
    os << ", \"QY\": ";
    print_field_element(os, e.QY);
    os << ", \"QY2\": ";
    print_field_element(os, e.QY2);
    os << ", \"QX_over_twist\": ";
    print_field_element(os, e.QX_over_twist);
    os << ", \"QY_over_twist\": ";
    print_field_element(os, e.QY_over_twist);
    os << "}" << std::endl;

    auto print_dbl_coeff = [&os](const auto &c) {
        os << "{\"c_H\": ";
        print_field_element(os, c.c_H);
        os << ", \"c_4C\": ";
        print_field_element(os, c.c_4C);
        os << ", \"c_J\": ";
        print_field_element(os, c.c_J);
        os << ", \"c_L\": ";
        print_field_element(os, c.c_L);
        os << "}" << std::endl;
    };
    auto print_add_coeff = [&os](const auto &c) {
        os << "{\"c_L1\": ";
        print_field_element(os, c.c_L1);
        os << ", \"c_RZ\": ";
        print_field_element(os, c.c_RZ);
        os << "}" << std::endl;
    };

    os << "dbl_coeffs: ";
    for (auto &c : e.dbl_coeffs) {
        print_dbl_coeff(c);
    }
    std::cout << std::endl;

    os << "add_coeffs: ";
    for (auto &c : e.add_coeffs) {
        print_add_coeff(c);
    }
    std::cout << std::endl;
}

void print_g2_precomp_element(std::ostream &os, const typename curves::mnt6<298>::pairing::g2_precomp &e) {
    os << "\"coordinates\": {\"QX\": ";
    print_field_element(os, e.QX);
    os << ", \"QY\": ";
    print_field_element(os, e.QY);
    os << ", \"QY2\": ";
    print_field_element(os, e.QY2);
    os << ", \"QX_over_twist\": ";
    print_field_element(os, e.QX_over_twist);
    os << ", \"QY_over_twist\": ";
    print_field_element(os, e.QY_over_twist);
    os << "}" << std::endl;

    auto print_dbl_coeff = [&os](const auto &c) {
        os << "{\"c_H\": ";
        print_field_element(os, c.c_H);
        os << ", \"c_4C\": ";
        print_field_element(os, c.c_4C);
        os << ", \"c_J\": ";
        print_field_element(os, c.c_J);
        os << ", \"c_L\": ";
        print_field_element(os, c.c_L);
        os << "}" << std::endl;
    };
    auto print_add_coeff = [&os](const auto &c) {
        os << "{\"c_L1\": ";
        print_field_element(os, c.c_L1);
        os << ", \"c_RZ\": ";
        print_field_element(os, c.c_RZ);
        os << "}" << std::endl;
    };

    os << "dbl_coeffs: ";
    for (auto &c : e.dbl_coeffs) {
        print_dbl_coeff(c);
    }
    std::cout << std::endl;

    os << "add_coeffs: ";
    for (auto &c : e.add_coeffs) {
        print_add_coeff(c);
    }
    std::cout << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing::g1_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing::g1_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing::g2_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing::g2_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing::g1_precomp> {
                void operator()(std::ostream &os, const typename curves::bls12<381>::pairing::g1_precomp &e) {
                    print_g1_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing::g2_precomp> {
                void operator()(std::ostream &os, const typename curves::bls12<381>::pairing::g2_precomp &e) {
                    print_g2_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing::gt_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing::gt_type::value_type &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<>
            struct print_log_value<curves::mnt4<298>::pairing::g1_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt4<298>::pairing::g1_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt4<298>::pairing::g2_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt4<298>::pairing::g2_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt4<298>::pairing::g1_precomp> {
                void operator()(std::ostream &os, const typename curves::mnt4<298>::pairing::g1_precomp &e) {
                    print_g1_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt4<298>::pairing::g2_precomp> {
                void operator()(std::ostream &os, const typename curves::mnt4<298>::pairing::g2_precomp &e) {
                    print_g2_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt4<298>::pairing::gt_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt4<298>::pairing::gt_type::value_type &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<>
            struct print_log_value<curves::mnt6<298>::pairing::g1_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt6<298>::pairing::g1_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt6<298>::pairing::g2_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt6<298>::pairing::g2_type::value_type &e) {
                    print_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt6<298>::pairing::g1_precomp> {
                void operator()(std::ostream &os, const typename curves::mnt6<298>::pairing::g1_precomp &e) {
                    print_g1_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt6<298>::pairing::g2_precomp> {
                void operator()(std::ostream &os, const typename curves::mnt6<298>::pairing::g2_precomp &e) {
                    print_g2_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::mnt6<298>::pairing::gt_type::value_type> {
                void operator()(std::ostream &os,
                                const typename curves::mnt6<298>::pairing::gt_type::value_type &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
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

enum Fr_enum : std::size_t { VKx_poly, VKy_poly, VKz_poly, A1_poly, B1_poly, C1_poly, A2_poly, B2_poly, C2_poly };
enum G1_enum : std::size_t { A1, C1, A2, C2, VKx };
enum G2_enum : std::size_t { B1, B2, VKy, VKz };
enum GT_enum : std::size_t {
    pairing_A1_B1,
    pairing_A2_B2,
    pair_reduceding_A1_B1,
    pair_reduceding_A2_B2,
    pair_reduceding_A1_B1_mul_pair_reduceding_A2_B2,
    pair_reduceding_VKx_poly_A1_B1,
    miller_loop_prec_A1_prec_B1,
    miller_loop_prec_A2_prec_B2,
    double_miller_loop_prec_A1_prec_B1_prec_A2_prec_B2
};
enum g1_precomp_enum : std::size_t { prec_A1, prec_A2 };
enum g2_precomp_enum : std::size_t { prec_B1, prec_B2 };

// TODO: add affine_pair_reduceding test
template<typename PairingT, typename Fr_value_type, typename G1_value_type, typename G2_value_type,
         typename GT_value_type, typename g1_precomp_value_type, typename g2_precomp_value_type>
void check_pairing_operations(std::vector<Fr_value_type> &Fr_elements,
                              std::vector<G1_value_type> &G1_elements,
                              std::vector<G2_value_type> &G2_elements,
                              std::vector<GT_value_type> &GT_elements,
                              std::vector<g1_precomp_value_type> &G1_prec_elements,
                              std::vector<g2_precomp_value_type> &G2_prec_elements) {
    std::cout << " * Basic fields and groups tests started..." << std::endl;
    BOOST_CHECK_EQUAL((Fr_elements[A1_poly] * Fr_elements[B1_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C1_poly]);
    BOOST_CHECK_EQUAL((Fr_elements[A2_poly] * Fr_elements[B2_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C2_poly]);
    BOOST_CHECK_EQUAL(Fr_elements[VKx_poly] * G1_value_type::one(), G1_elements[VKx]);
    BOOST_CHECK_EQUAL(Fr_elements[VKy_poly] * G2_value_type::one(), G2_elements[VKy]);
    BOOST_CHECK_EQUAL(Fr_elements[VKz_poly] * G2_value_type::one(), G2_elements[VKz]);
    BOOST_CHECK_EQUAL(Fr_elements[A1_poly] * G1_value_type::one(), G1_elements[A1]);
    BOOST_CHECK_EQUAL(Fr_elements[C1_poly] * G1_value_type::one(), G1_elements[C1]);
    BOOST_CHECK_EQUAL(Fr_elements[A2_poly] * G1_value_type::one(), G1_elements[A2]);
    BOOST_CHECK_EQUAL(Fr_elements[C2_poly] * G1_value_type::one(), G1_elements[C2]);
    BOOST_CHECK_EQUAL(Fr_elements[B1_poly] * G2_value_type::one(), G2_elements[B1]);
    BOOST_CHECK_EQUAL(Fr_elements[B2_poly] * G2_value_type::one(), G2_elements[B2]);
    std::cout << " * Basic fields and groups tests finished." << std::endl << std::endl;

    std::cout << " * Precomputing and pairing tests started..." << std::endl;
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A1]), G1_prec_elements[prec_A1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A2]), G1_prec_elements[prec_A2]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B1]), G2_prec_elements[prec_B1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B2]), G2_prec_elements[prec_B2]);
    BOOST_CHECK_EQUAL(PairingT::pair(G1_elements[A1], G2_elements[B1]), GT_elements[pairing_A1_B1]);
    BOOST_CHECK_EQUAL(PairingT::pair(G1_elements[A2], G2_elements[B2]), GT_elements[pairing_A2_B2]);
    std::cout << " * Precomputing and pairing tests finished." << std::endl << std::endl;

    // TODO: activate after pair_reduceding->cyclotomic_exp fixed. Bugs in final_exponentiation_last_chunk
    std::cout << " * Reduced pairing tests started..." << std::endl;
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A1], G2_elements[B1]), GT_elements[pair_reduceding_A1_B1]);
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A1], G2_elements[B1]),
                      PairingT::pair_reduced(G1_elements[VKx], G2_elements[VKy]) *
                          PairingT::pair_reduced(G1_elements[C1], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A2], G2_elements[B2]), GT_elements[pair_reduceding_A2_B2]);
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A2], G2_elements[B2]),
                      PairingT::pair_reduced(G1_elements[VKx], G2_elements[VKy]) *
                          PairingT::pair_reduced(G1_elements[C2], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A1], G2_elements[B1]) *
                          PairingT::pair_reduced(G1_elements[A2], G2_elements[B2]),
                      GT_elements[pair_reduceding_A1_B1_mul_pair_reduceding_A2_B2]);
    std::cout << " * Reduced pairing tests finished." << std::endl << std::endl;

    // TODO: activate when scalar multiplication done
    std::cout << " * Reduced pairing tests with scalar multiplication started..." << std::endl;
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(G1_elements[A1], G2_elements[B1]) *
                          PairingT::pair_reduced(G1_elements[A2], G2_elements[B2]),
                      PairingT::pair_reduced(Fr_value_type(2) * G1_elements[VKx], G2_elements[VKy]) *
                          PairingT::pair_reduced(G1_elements[C1] + G1_elements[C2], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
                      GT_elements[pair_reduceding_VKx_poly_A1_B1]);
    BOOST_CHECK_EQUAL(PairingT::pair_reduced(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
                      PairingT::pair_reduced(G1_elements[A1], Fr_elements[VKx_poly] * G2_elements[B1]));
    std::cout << " * Reduced pairing tests with scalar multiplication finished." << std::endl << std::endl;

    // TODO: activate when pow will be override with field element
    std::cout << " * Reduced pairing tests with pow started..." << std::endl;
    BOOST_CHECK_EQUAL(
        PairingT::pair_reduced(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
        // TODO: fix pow to accept field element as exponent
        PairingT::pair_reduced(G1_elements[A1], G2_elements[B1]).pow(cpp_int(Fr_elements[VKx_poly].data)));
    std::cout << " * Reduced pairing tests with pow finished." << std::endl << std::endl;

    std::cout << " * Miller loop tests started..." << std::endl;
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
    std::cout << " * Miller loop tests finished." << std::endl << std::endl;
}

template<typename ElementType>
struct field_element_init;

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp<FieldParams>> {
    using element_type = fields::detail::element_fp<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        return element_type(typename element_type::modulus_type(element_data.second.data()));
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp2<FieldParams>> {
    using element_type = fields::detail::element_fp2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp3<FieldParams>> {
    using element_type = fields::detail::element_fp3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 3> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1], element_values[2]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp4<FieldParams>> {
    using element_type = fields::detail::element_fp4<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp2 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp6_2over3<FieldParams>> {
    using element_type = fields::detail::element_fp6_2over3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp12_2over3over2<FieldParams>> {
    using element_type = fields::detail::element_fp12_2over3over2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp2 over element_fp
        using underlying_type_3over2 = typename element_type::underlying_type;
        // element_fp2 over element_fp
        using underlying_type = typename underlying_type_3over2::underlying_type;

        std::array<underlying_type_3over2, 2> element_values;
        std::array<underlying_type, 3> underlying_element_values;
        auto i = 0;
        for (auto &elem_3over2 : element_data.second) {
            auto j = 0;
            for (auto &elem_fp2 : elem_3over2.second) {
                underlying_element_values[j++] = field_element_init<underlying_type>::process(elem_fp2);
            }
            element_values[i++] = underlying_type_3over2(underlying_element_values[0], underlying_element_values[1],
                                                         underlying_element_values[2]);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename CurveGroupValue, typename PointData>
CurveGroupValue curve_point_init(const PointData &point_data) {
    using group_value_type = CurveGroupValue;
    using field_value_type = typename group_value_type::underlying_field_value_type;

    std::array<field_value_type, 3> coordinates;
    auto i = 0;
    for (auto &coordinate : point_data.second) {
        coordinates[i++] = field_element_init<field_value_type>::process(coordinate);
    }
    return group_value_type(coordinates[0], coordinates[1], coordinates[2]);
}

template<typename FieldParams, typename TestSet>
void pairing_test_Fr_init(std::vector<typename fields::detail::element_fp<FieldParams>> &elements,
                          const TestSet &test_set) {
    using value_type = typename fields::detail::element_fp<FieldParams>;

    for (auto &elem : test_set.second.get_child("Fr")) {
        elements.emplace_back(field_element_init<value_type>::process(elem));
    }
}

template<typename PairingT, typename TestSet>
void pairing_test_G1_init(std::vector<typename PairingT::g1_type::value_type> &elements, const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::g1_type::value_type;

    for (auto &elem_coords : test_set.second.get_child("G1")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename PairingT, typename TestSet>
void pairing_test_G2_init(std::vector<typename PairingT::g2_type::value_type> &elements, const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::g2_type::value_type;

    for (auto &elem_coords : test_set.second.get_child("G2")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename PairingT, typename TestSet>
void pairing_test_GT_init(std::vector<typename PairingT::gt_type::value_type> &elements, const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::gt_type::value_type;

    for (auto &elem_GT : test_set.second.get_child("GT")) {
        elements.emplace_back(field_element_init<value_type>::process(elem_GT));
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename curves::bls12<381>::pairing::g1_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381>::pairing;
    using value_type = typename pairing_policy::g1_precomp;
    using element_type = value_type::value_type;

    for (auto &elem : test_set.second.get_child("g1_precomp")) {
        elements.emplace_back(
            value_type {field_element_init<element_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<element_type>::process(elem.second.get_child("PY").front())});
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename curves::mnt4<298>::pairing::g1_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::mnt4<298>::pairing;
    using value_type = typename pairing_policy::g1_precomp;
    using element_type = value_type::value_type;
    using twist_element_type = value_type::twist_value_type;

    for (auto &elem : test_set.second.get_child("g1_precomp")) {
        elements.emplace_back(
            value_type {field_element_init<element_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<element_type>::process(elem.second.get_child("PY").front()),
                        field_element_init<twist_element_type>::process(elem.second.get_child("PX_twist").front()),
                        field_element_init<twist_element_type>::process(elem.second.get_child("PY_twist").front())});
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename curves::mnt6<298>::pairing::g1_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::mnt6<298>::pairing;
    using value_type = typename pairing_policy::g1_precomp;
    using element_type = value_type::value_type;
    using twist_element_type = value_type::twist_value_type;

    for (auto &elem : test_set.second.get_child("g1_precomp")) {
        elements.emplace_back(
            value_type {field_element_init<element_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<element_type>::process(elem.second.get_child("PY").front()),
                        field_element_init<twist_element_type>::process(elem.second.get_child("PX_twist").front()),
                        field_element_init<twist_element_type>::process(elem.second.get_child("PY_twist").front())});
    }
}

template<typename TestSet>
void pairing_test_g2_precomp_init(std::vector<typename curves::bls12<381>::pairing::g2_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381>::pairing;
    using value_type = typename pairing_policy::g2_precomp;
    using element_type = value_type::value_type;
    using coeffs_type = value_type::coeffs_type;
    using coeffs_value_type = coeffs_type::value_type;

    for (auto &elem : test_set.second.get_child("g2_precomp")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<element_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<element_type>::process(elem.second.get_child("QY").front());

        for (auto &elem_coeffs : elem.second.get_child("coeffs")) {
            elements.back().coeffs.emplace_back(coeffs_type());

            elements.back().coeffs.back().ell_0 =
                field_element_init<coeffs_value_type>::process(elem_coeffs.second.get_child("ell_0").front());
            elements.back().coeffs.back().ell_VW =
                field_element_init<coeffs_value_type>::process(elem_coeffs.second.get_child("ell_VW").front());
            elements.back().coeffs.back().ell_VV =
                field_element_init<coeffs_value_type>::process(elem_coeffs.second.get_child("ell_VV").front());
        }
    }
}

template<typename TestSet>
void pairing_test_g2_precomp_init(std::vector<typename curves::mnt4<298>::pairing::g2_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::mnt4<298>::pairing;
    using value_type = typename pairing_policy::g2_precomp;
    using element_type = typename value_type::value_type;
    using dbl_coeffs_type = typename value_type::dbl_coeffs_type;
    using add_coeffs_type = typename value_type::add_coeffs_type;
    using dbl_coeffs_value_type = typename dbl_coeffs_type::value_type;
    using add_coeffs_value_type = typename add_coeffs_type::value_type;

    for (auto &elem : test_set.second.get_child("g2_precomp")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<element_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<element_type>::process(elem.second.get_child("QY").front());
        elements.back().QY2 = field_element_init<element_type>::process(elem.second.get_child("QY2").front());
        elements.back().QX_over_twist =
            field_element_init<element_type>::process(elem.second.get_child("QX_over_twist").front());
        elements.back().QY_over_twist =
            field_element_init<element_type>::process(elem.second.get_child("QY_over_twist").front());

        for (auto &elem_coeffs : elem.second.get_child("dbl_coeffs")) {
            elements.back().dbl_coeffs.emplace_back(dbl_coeffs_type());

            elements.back().dbl_coeffs.back().c_H =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_H").front());
            elements.back().dbl_coeffs.back().c_4C =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_4C").front());
            elements.back().dbl_coeffs.back().c_J =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_J").front());
            elements.back().dbl_coeffs.back().c_L =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_L").front());
        }

        for (auto &elem_coeffs : elem.second.get_child("add_coeffs")) {
            elements.back().add_coeffs.emplace_back(add_coeffs_type());

            elements.back().add_coeffs.back().c_L1 =
                field_element_init<add_coeffs_value_type>::process(elem_coeffs.second.get_child("c_L1").front());
            elements.back().add_coeffs.back().c_RZ =
                field_element_init<add_coeffs_value_type>::process(elem_coeffs.second.get_child("c_RZ").front());
        }
    }
}

template<typename TestSet>
void pairing_test_g2_precomp_init(std::vector<typename curves::mnt6<298>::pairing::g2_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::mnt6<298>::pairing;
    using value_type = typename pairing_policy::g2_precomp;
    using element_type = typename value_type::value_type;
    using dbl_coeffs_type = typename value_type::dbl_coeffs_type;
    using add_coeffs_type = typename value_type::add_coeffs_type;
    using dbl_coeffs_value_type = typename dbl_coeffs_type::value_type;
    using add_coeffs_value_type = typename add_coeffs_type::value_type;

    for (auto &elem : test_set.second.get_child("g2_precomp")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<element_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<element_type>::process(elem.second.get_child("QY").front());
        elements.back().QY2 = field_element_init<element_type>::process(elem.second.get_child("QY2").front());
        elements.back().QX_over_twist =
            field_element_init<element_type>::process(elem.second.get_child("QX_over_twist").front());
        elements.back().QY_over_twist =
            field_element_init<element_type>::process(elem.second.get_child("QY_over_twist").front());

        for (auto &elem_coeffs : elem.second.get_child("dbl_coeffs")) {
            elements.back().dbl_coeffs.emplace_back(dbl_coeffs_type());

            elements.back().dbl_coeffs.back().c_H =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_H").front());
            elements.back().dbl_coeffs.back().c_4C =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_4C").front());
            elements.back().dbl_coeffs.back().c_J =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_J").front());
            elements.back().dbl_coeffs.back().c_L =
                field_element_init<dbl_coeffs_value_type>::process(elem_coeffs.second.get_child("c_L").front());
        }

        for (auto &elem_coeffs : elem.second.get_child("add_coeffs")) {
            elements.back().add_coeffs.emplace_back(add_coeffs_type());

            elements.back().add_coeffs.back().c_L1 =
                field_element_init<add_coeffs_value_type>::process(elem_coeffs.second.get_child("c_L1").front());
            elements.back().add_coeffs.back().c_RZ =
                field_element_init<add_coeffs_value_type>::process(elem_coeffs.second.get_child("c_RZ").front());
        }
    }
}

template<typename PairingT, typename Fr_value_type, typename G1_value_type, typename G2_value_type,
         typename GT_value_type, typename g1_precomp_value_type, typename g2_precomp_value_type, typename TestSet>
void pairing_test_init(std::vector<Fr_value_type> &Fr_elements,
                       std::vector<G1_value_type> &G1_elements,
                       std::vector<G2_value_type> &G2_elements,
                       std::vector<GT_value_type> &GT_elements,
                       std::vector<g1_precomp_value_type> &G1_prec_elements,
                       std::vector<g2_precomp_value_type> &G2_prec_elements,
                       const TestSet &test_set) {
    pairing_test_Fr_init(Fr_elements, test_set);
    pairing_test_G1_init<PairingT>(G1_elements, test_set);
    pairing_test_G2_init<PairingT>(G2_elements, test_set);
    pairing_test_GT_init<PairingT>(GT_elements, test_set);
    pairing_test_g1_precomp_init(G1_prec_elements, test_set);
    pairing_test_g2_precomp_init(G2_prec_elements, test_set);
}

template<typename PairingT, typename TestSet>
void pairing_operation_test(const TestSet &test_set) {
    std::vector<typename PairingT::fp_type::value_type> Fr_elements;
    std::vector<typename PairingT::g1_type::value_type> G1_elements;
    std::vector<typename PairingT::g2_type::value_type> G2_elements;
    std::vector<typename PairingT::gt_type::value_type> GT_elements;
    std::vector<typename PairingT::g1_precomp> G1_prec_elements;
    std::vector<typename PairingT::g2_precomp> G2_prec_elements;

    pairing_test_init<PairingT>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements, G2_prec_elements,
                                test_set);
    check_pairing_operations<PairingT>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements,
                                       G2_prec_elements);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

// TODO: fix pair_reduceding
BOOST_DATA_TEST_CASE(pairing_operation_test_bls12_381, string_data("pairing_operation_test_bls12_381"), data_set) {
    using pairing_policy = typename curves::bls12<381>::pairing;

    pairing_operation_test<pairing_policy>(data_set);
}

BOOST_DATA_TEST_CASE(pairing_operation_test_mnt4_298, string_data("pairing_operation_test_mnt4_298"), data_set) {
    using pairing_policy = typename curves::mnt4<298>::pairing;

    pairing_operation_test<pairing_policy>(data_set);
}

BOOST_DATA_TEST_CASE(pairing_operation_test_mnt6_298, string_data("pairing_operation_test_mnt6_298"), data_set) {
    using pairing_policy = typename curves::mnt6<298>::pairing;

    pairing_operation_test<pairing_policy>(data_set);
}

BOOST_AUTO_TEST_SUITE_END()
