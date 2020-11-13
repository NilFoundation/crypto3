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
#include <vector>
#include <array>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra;

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
    os << "(" << e.X.data[0].data << "," << e.X.data[1].data << "),(" << e.Y.data[0].data << "," << e.Y.data[1].data
       << "),(" << e.Z.data[0].data << "," << e.Z.data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroup>
void print_fp3_curve_group_element(std::ostream &os, const Fp3CurveGroup &e) {
    os << "(" << e.X.data[0].data << "," << e.X.data[1].data << e.X.data[2].data << "),(" << e.Y.data[0].data << ","
       << e.Y.data[1].data << e.Y.data[2].data << "),(" << e.Z.data[0].data << "," << e.Z.data[1].data
       << e.Z.data[2].data << ")" << std::endl;
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

void print_fpt_curve_group_element(std::ostream &os,
                                   const typename curves::bls12<381>::pairing_policy::GT_type &e) {
    print_fp12_2_3_2_curve_group_element(os, e);
}

void print_g1_precomp_element(std::ostream &os,
                                  const typename curves::bls12<381>::pairing_policy::G1_precomp &e) {
    os << "(" << e.PX.data << "," << e.PY.data << ")" << std::endl;
}

void print_g2_precomp_element(std::ostream &os,
                                  const typename curves::bls12<381>::pairing_policy::G2_precomp &e) {
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
            struct print_log_value<curves::bls12<381>::pairing_policy::G1_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing_policy::G1_type &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing_policy::G2_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing_policy::G2_type &e) {
                    print_fp2_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing_policy::G1_precomp> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing_policy::G1_precomp &e) {
                    print_g1_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing_policy::G2_precomp> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing_policy::G2_precomp &e) {
                    print_g2_precomp_element(os, e);
                }
            };

            template<>
            struct print_log_value<curves::bls12<381>::pairing_policy::GT_type> {
                void operator()(std::ostream &os,
                                const typename curves::bls12<381>::pairing_policy::GT_type &e) {
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

enum Fr_enum : std::size_t { VKx_poly, VKy_poly, VKz_poly, A1_poly, B1_poly, C1_poly, A2_poly, B2_poly, C2_poly };
enum G1_enum : std::size_t { A1, C1, A2, C2, VKx };
enum G2_enum : std::size_t { B1, B2, VKy, VKz };
enum GT_enum : std::size_t {
    pairing_A1_B1,
    pairing_A2_B2,
    reduced_pairing_A1_B1,
    reduced_pairing_A2_B2,
    reduced_pairing_A1_B1_mul_reduced_pairing_A2_B2,
    reduced_pairing_VKx_poly_A1_B1,
    miller_loop_prec_A1_prec_B1,
    miller_loop_prec_A2_prec_B2,
    double_miller_loop_prec_A1_prec_B1_prec_A2_prec_B2
};
enum G1_precomp_enum : std::size_t { prec_A1, prec_A2 };
enum G2_precomp_enum : std::size_t { prec_B1, prec_B2 };

// TODO: add affine_reduced_pairing test
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
     BOOST_CHECK_EQUAL(Fr_elements[VKx_poly] * G1_value_type::one(),
                       G1_elements[VKx]);
     BOOST_CHECK_EQUAL(Fr_elements[VKy_poly] * G2_value_type::one(),
                       G2_elements[VKy]);
     BOOST_CHECK_EQUAL(Fr_elements[VKz_poly] * G2_value_type::one(),
                       G2_elements[VKz]);
     BOOST_CHECK_EQUAL(Fr_elements[A1_poly] * G1_value_type::one(),
                       G1_elements[A1]);
     BOOST_CHECK_EQUAL(Fr_elements[C1_poly] * G1_value_type::one(),
                       G1_elements[C1]);
     BOOST_CHECK_EQUAL(Fr_elements[A2_poly] * G1_value_type::one(),
                       G1_elements[A2]);
     BOOST_CHECK_EQUAL(Fr_elements[C2_poly] * G1_value_type::one(),
                       G1_elements[C2]);
     BOOST_CHECK_EQUAL(Fr_elements[B1_poly] * G2_value_type::one(),
                       G2_elements[B1]);
     BOOST_CHECK_EQUAL(Fr_elements[B2_poly] * G2_value_type::one(),
                       G2_elements[B2]);
    
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A1]), G1_prec_elements[prec_A1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g1(G1_elements[A2]), G1_prec_elements[prec_A2]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B1]), G2_prec_elements[prec_B1]);
    BOOST_CHECK_EQUAL(PairingT::precompute_g2(G2_elements[B2]), G2_prec_elements[prec_B2]);
    BOOST_CHECK_EQUAL(PairingT::pairing(G1_elements[A1], G2_elements[B1]), GT_elements[pairing_A1_B1]);
    BOOST_CHECK_EQUAL(PairingT::pairing(G1_elements[A2], G2_elements[B2]), GT_elements[pairing_A2_B2]);
    // TODO: activate after reduced_pairing->cyclotomic_exp fixed. Bugs in final_exponentiation_last_chunk
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]),
    // GT_elements[reduced_pairing_A1_B1]); BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1],
    // G2_elements[B1]),
    //                   PairingT::reduced_pairing(G1_elements[VKx], G2_elements[VKy]) *
    //                       PairingT::reduced_pairing(G1_elements[C1], G2_elements[VKz]));
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   GT_elements[reduced_pairing_A2_B2]);
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   PairingT::reduced_pairing(G1_elements[VKx], G2_elements[VKy]) *
    //                       PairingT::reduced_pairing(G1_elements[C2], G2_elements[VKz]));
    // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]) *
    // PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
    //                   GT_elements[reduced_pairing_A1_B1_mul_reduced_pairing_A2_B2]);
    // // TODO: activate when scalar multiplication done
    // // BOOST_CHECK_EQUAL(PairingT::reduced_pairing(G1_elements[A1], G2_elements[B1]) *
    // PairingT::reduced_pairing(G1_elements[A2], G2_elements[B2]),
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

// template<typename FpValueType>
// FpValueType fp_element_init(const std::string &element_data) {
//     return element_type(typename element_type::modulus_type(element_data.second.data()));;
// }

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
            element_values[i++] = underlying_type_3over2(underlying_element_values[0],
                                                         underlying_element_values[1],
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
void pairing_test_G1_init(std::vector<typename PairingT::G1_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::G1_type;

    for (auto &elem_coords : test_set.second.get_child("G1")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename PairingT, typename TestSet>
void pairing_test_G2_init(std::vector<typename PairingT::G2_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::G2_type;

    for (auto &elem_coords : test_set.second.get_child("G2")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename PairingT, typename TestSet>
void pairing_test_GT_init(std::vector<typename PairingT::GT_type> &elements,
                          const TestSet &test_set) {
    using pairing_policy = PairingT;
    using value_type = typename pairing_policy::GT_type;

    for (auto &elem_GT : test_set.second.get_child("GT")) {
        elements.emplace_back(field_element_init<value_type>::process(elem_GT));
    }
}

template<typename TestSet>
void pairing_test_G1_precomp_init(std::vector<typename curves::bls12<381>::pairing_policy::G1_precomp> &elements,
                                  const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381>::pairing_policy;
    using value_type = typename pairing_policy::G1_precomp;
    using element_value_type = value_type::value_type;

    for (auto &elem : test_set.second.get_child("G1_precomp")) {
        elements.emplace_back(value_type {field_element_init<element_value_type>::process(
                                              elem.second.get_child("PX").front()),
                                          field_element_init<element_value_type>::process(
                                              elem.second.get_child("PY").front())});
    }
}

template<typename TestSet>
void pairing_test_G2_precomp_init(
    std::vector<typename curves::bls12<381>::pairing_policy::G2_precomp> &elements,
    const TestSet &test_set) {
    using pairing_policy = typename curves::bls12<381>::pairing_policy;
    using value_type = typename pairing_policy::G2_precomp;
    using element_value_type = value_type::value_type;
    using coeffs_type = value_type::coeffs_type::value_type;
    using coeffs_value_type = coeffs_type::value_type;

    for (auto &elem : test_set.second.get_child("G2_precomp")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<element_value_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<element_value_type>::process(elem.second.get_child("QY").front());

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

template<typename PairingT, typename Fr_value_type, typename G1_value_type, typename G2_value_type,
         typename GT_value_type, typename G1_precomp_value_type, typename G2_precomp_value_type, typename TestSet>
void pairing_test_init(std::vector<Fr_value_type> &Fr_elements,
                       std::vector<G1_value_type> &G1_elements,
                       std::vector<G2_value_type> &G2_elements,
                       std::vector<GT_value_type> &GT_elements,
                       std::vector<G1_precomp_value_type> &G1_prec_elements,
                       std::vector<G2_precomp_value_type> &G2_prec_elements,
                       const TestSet &test_set) {
    pairing_test_Fr_init(Fr_elements, test_set);
    pairing_test_G1_init<PairingT>(G1_elements, test_set);
    pairing_test_G2_init<PairingT>(G2_elements, test_set);
    pairing_test_GT_init<PairingT>(GT_elements, test_set);
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

    pairing_test_init<PairingT>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements, G2_prec_elements,
                                test_set);
    check_pairing_operations<PairingT>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements,
                                       G2_prec_elements);
}

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_DATA_TEST_CASE(pairing_operation_test_bls12_381, string_data("pairing_operation_test_bls12_381"), data_set) {
    using pairing_policy = typename curves::bls12<381>::pairing_policy;

    pairing_operation_test<pairing_policy>(data_set);
}

// BOOST_DATA_TEST_CASE(pairing_operation_test_mnt4_298, string_data("pairing_operation_test_mnt4_298"), data_set) {
//     using pairing_policy = typename curves::mnt4<298>::pairing_policy;
//
//     pairing_operation_test<pairing_policy>(data_set);
// }

BOOST_AUTO_TEST_SUITE_END()
