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

#include "nil/crypto3/algebra/curves/alt_bn128.hpp"
#define BOOST_TEST_MODULE algebra_curves_test

#include <iostream>
#include <vector>
#include <array>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/alt_bn128.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra;
using namespace boost::multiprecision;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

boost::property_tree::ptree string_data(const std::string &test_name) {
    static std::string test_data = std::string(TEST_DATA_DIR) + R"(pairing.json)";
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
template<typename CurveType, typename Fr_value_type, typename G1_value_type, typename G2_value_type,
         typename GT_value_type, typename g1_precomp_value_type, typename g2_precomp_value_type>
void check_pairing_operations(std::vector<Fr_value_type> const& Fr_elements,
                              std::vector<G1_value_type> const& G1_elements,
                              std::vector<G2_value_type> const& G2_elements,
                              std::vector<GT_value_type> const& GT_elements,
                              std::vector<g1_precomp_value_type> const& G1_prec_elements,
                              std::vector<g2_precomp_value_type> const& G2_prec_elements) {
    std::cout << " * Basic fields and groups tests started..." << std::endl;
    BOOST_CHECK_EQUAL((Fr_elements[A1_poly] * Fr_elements[B1_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C1_poly]);
    BOOST_CHECK_EQUAL((Fr_elements[A2_poly] * Fr_elements[B2_poly] - Fr_elements[VKx_poly] * Fr_elements[VKy_poly]) *
                          Fr_elements[VKz_poly].inversed(),
                      Fr_elements[C2_poly]);

    BOOST_CHECK_EQUAL(Fr_elements[A1_poly] * G1_value_type::zero(), G1_value_type::zero());
    BOOST_CHECK_EQUAL(Fr_elements[B1_poly] * G2_value_type::zero(), G2_value_type::zero());

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

    std::cout << " * Pairing with infinity tests started..." << std::endl;
    BOOST_CHECK_EQUAL(final_exponentiation<CurveType>(pair<CurveType>(G1_value_type::zero(), G2_elements[B1])), GT_value_type::one());
    std::cout << " * Pairing with infinity tests finished." << std::endl << std::endl;

    std::cout << " * Reduced pairing with infinity tests started..." << std::endl;
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_value_type::zero(), G2_elements[B1]), GT_value_type::one());
    std::cout << " * Reduced pairing with infinity tests finished." << std::endl << std::endl;


    std::cout << " * Precomputing and pairing tests started..." << std::endl;
    BOOST_CHECK_EQUAL(precompute_g1<CurveType>(G1_elements[A1]), G1_prec_elements[prec_A1]);
    BOOST_CHECK_EQUAL(precompute_g1<CurveType>(G1_elements[A2]), G1_prec_elements[prec_A2]);
    BOOST_CHECK_EQUAL(precompute_g2<CurveType>(G2_elements[B1]), G2_prec_elements[prec_B1]);
    BOOST_CHECK_EQUAL(precompute_g2<CurveType>(G2_elements[B2]), G2_prec_elements[prec_B2]);
    BOOST_CHECK_EQUAL(pair<CurveType>(G1_elements[A1], G2_elements[B1]), GT_elements[pairing_A1_B1]);
    BOOST_CHECK_EQUAL(pair<CurveType>(G1_elements[A2], G2_elements[B2]), GT_elements[pairing_A2_B2]);
    std::cout << " * Precomputing and pairing tests finished." << std::endl << std::endl;

    // TODO: activate after pair_reduceding->cyclotomic_exp fixed. Bugs in final_exponentiation_last_chunk
    std::cout << " * Reduced pairing tests started..." << std::endl;
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A1], G2_elements[B1]), GT_elements[pair_reduceding_A1_B1]);
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A1], G2_elements[B1]),
                      pair_reduced<CurveType>(G1_elements[VKx], G2_elements[VKy]) *
                          pair_reduced<CurveType>(G1_elements[C1], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A2], G2_elements[B2]), GT_elements[pair_reduceding_A2_B2]);
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A2], G2_elements[B2]),
                      pair_reduced<CurveType>(G1_elements[VKx], G2_elements[VKy]) *
                          pair_reduced<CurveType>(G1_elements[C2], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A1], G2_elements[B1]) *
                          pair_reduced<CurveType>(G1_elements[A2], G2_elements[B2]),
                      GT_elements[pair_reduceding_A1_B1_mul_pair_reduceding_A2_B2]);
    std::cout << " * Reduced pairing tests finished." << std::endl << std::endl;

    // TODO: activate when scalar multiplication done
    std::cout << " * Reduced pairing tests with scalar multiplication started..." << std::endl;
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(G1_elements[A1], G2_elements[B1]) *
                          pair_reduced<CurveType>(G1_elements[A2], G2_elements[B2]),
                      pair_reduced<CurveType>(Fr_value_type(2u) * G1_elements[VKx], G2_elements[VKy]) *
                          pair_reduced<CurveType>(G1_elements[C1] + G1_elements[C2], G2_elements[VKz]));
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
                      GT_elements[pair_reduceding_VKx_poly_A1_B1]);
    BOOST_CHECK_EQUAL(pair_reduced<CurveType>(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
                      pair_reduced<CurveType>(G1_elements[A1], Fr_elements[VKx_poly] * G2_elements[B1]));
    std::cout << " * Reduced pairing tests with scalar multiplication finished." << std::endl << std::endl;

    // TODO: activate when pow will be override with field element
    std::cout << " * Reduced pairing tests with pow started..." << std::endl;
    BOOST_CHECK_EQUAL(
        pair_reduced<CurveType>(Fr_elements[VKx_poly] * G1_elements[A1], G2_elements[B1]),
        // TODO: fix pow to accept field element as exponent
        pair_reduced<CurveType>(G1_elements[A1], G2_elements[B1]).pow(Fr_elements[VKx_poly].data));
    std::cout << " * Reduced pairing tests with pow finished." << std::endl << std::endl;

    std::cout << " * Miller loop tests started..." << std::endl;
    BOOST_CHECK_EQUAL(miller_loop<CurveType>(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1]),
                      GT_elements[miller_loop_prec_A1_prec_B1]);
    BOOST_CHECK_EQUAL(miller_loop<CurveType>(G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      GT_elements[miller_loop_prec_A2_prec_B2]);
    BOOST_CHECK_EQUAL(double_miller_loop<CurveType>(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1],
                                                   G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      GT_elements[double_miller_loop_prec_A1_prec_B1_prec_A2_prec_B2]);
    BOOST_CHECK_EQUAL(miller_loop<CurveType>(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1]) *
                          miller_loop<CurveType>(G1_prec_elements[prec_A2], G2_prec_elements[prec_B2]),
                      double_miller_loop<CurveType>(G1_prec_elements[prec_A1], G2_prec_elements[prec_B1],
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
        return element_type(typename element_type::integral_type(element_data.second.data()));
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
    using field_value_type = typename group_value_type::field_type::value_type;

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

template<typename CurveType, typename TestSet>
void pairing_test_G1_init(std::vector<typename CurveType::template g1_type<>::value_type> &elements, const TestSet &test_set) {

    using value_type = typename CurveType::template g1_type<>::value_type;

    for (auto &elem_coords : test_set.second.get_child("G1")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename CurveType, typename TestSet>
void pairing_test_G2_init(std::vector<typename CurveType::template g2_type<>::value_type> &elements, const TestSet &test_set) {

    using value_type = typename CurveType::template g2_type<>::value_type;

    for (auto &elem_coords : test_set.second.get_child("G2")) {
        elements.emplace_back(curve_point_init<value_type>(elem_coords));
    }
}

template<typename CurveType, typename TestSet>
void pairing_test_GT_init(std::vector<typename CurveType::gt_type::value_type> &elements, const TestSet &test_set) {

    using value_type = typename CurveType::gt_type::value_type;

    for (auto &elem_GT : test_set.second.get_child("GT")) {
        elements.emplace_back(field_element_init<value_type>::process(elem_GT));
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename pairing::pairing_policy<curves::bls12<381>>::g1_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::bls12<381>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g1_precomputed_type;

    using g1_field_value_type = typename curve_type::base_field_type::value_type;

    for (auto &elem : test_set.second.get_child("g1_precomputed_type")) {
        elements.emplace_back(
            value_type {field_element_init<g1_field_value_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<g1_field_value_type>::process(elem.second.get_child("PY").front())});
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename pairing::pairing_policy<curves::alt_bn128_254>::g1_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::alt_bn128_254;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g1_precomputed_type;

    using g1_field_value_type = typename curve_type::base_field_type::value_type;

    for (auto &elem : test_set.second.get_child("g1_precomputed_type")) {
        elements.emplace_back(
            value_type {field_element_init<g1_field_value_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<g1_field_value_type>::process(elem.second.get_child("PY").front())});
    }
}


template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename pairing::pairing_policy<curves::mnt4<298>>::g1_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::mnt4<298>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g1_precomputed_type;

    using g1_field_value_type = typename curve_type::base_field_type::value_type;
    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    for (auto &elem : test_set.second.get_child("g1_precomputed_type")) {
        elements.emplace_back(
            value_type {field_element_init<g1_field_value_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<g1_field_value_type>::process(elem.second.get_child("PY").front()),
                        field_element_init<g2_field_value_type>::process(elem.second.get_child("PX_twist").front()),
                        field_element_init<g2_field_value_type>::process(elem.second.get_child("PY_twist").front())});
    }
}

template<typename TestSet>
void pairing_test_g1_precomp_init(std::vector<typename pairing::pairing_policy<curves::mnt6<298>>::g1_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::mnt6<298>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g1_precomputed_type;

    using g1_field_value_type = typename curve_type::base_field_type::value_type;
    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    for (auto &elem : test_set.second.get_child("g1_precomputed_type")) {
        elements.emplace_back(
            value_type {field_element_init<g1_field_value_type>::process(elem.second.get_child("PX").front()),
                        field_element_init<g1_field_value_type>::process(elem.second.get_child("PY").front()),
                        field_element_init<g2_field_value_type>::process(elem.second.get_child("PX_twist").front()),
                        field_element_init<g2_field_value_type>::process(elem.second.get_child("PY_twist").front())});
    }
}

template<typename TestSet>
void pairing_test_g2_precomp_init(std::vector<typename pairing::pairing_policy<curves::alt_bn128_254>::g2_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::alt_bn128_254;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g2_precomputed_type;

    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    using coeffs_type = value_type::coeffs_type;
    using coeffs_value_type = g2_field_value_type;

    for (auto &elem : test_set.second.get_child("g2_precomputed_type")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<g2_field_value_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY").front());

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
void pairing_test_g2_precomp_init(std::vector<typename pairing::pairing_policy<curves::bls12<381>>::g2_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::bls12<381>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g2_precomputed_type;

    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    using coeffs_type = value_type::coeffs_type;
    using coeffs_value_type = g2_field_value_type;

    for (auto &elem : test_set.second.get_child("g2_precomputed_type")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<g2_field_value_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY").front());

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
void pairing_test_g2_precomp_init(std::vector<typename pairing::pairing_policy<curves::mnt4<298>>::g2_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::mnt4<298>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g2_precomputed_type;

    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    using dbl_coeffs_type = typename value_type::dbl_coeffs_type;
    using add_coeffs_type = typename value_type::add_coeffs_type;
    using dbl_coeffs_value_type = g2_field_value_type;
    using add_coeffs_value_type = g2_field_value_type;

    for (auto &elem : test_set.second.get_child("g2_precomputed_type")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<g2_field_value_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY").front());
        elements.back().QY2 = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY2").front());
        elements.back().QX_over_twist =
            field_element_init<g2_field_value_type>::process(elem.second.get_child("QX_over_twist").front());
        elements.back().QY_over_twist =
            field_element_init<g2_field_value_type>::process(elem.second.get_child("QY_over_twist").front());

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
void pairing_test_g2_precomp_init(std::vector<typename pairing::pairing_policy<curves::mnt6<298>>::g2_precomputed_type> &elements,
                                  const TestSet &test_set) {
    using curve_type = curves::mnt6<298>;
    using pairing_policy = typename pairing::pairing_policy<curve_type>;
    using value_type = typename pairing_policy::g2_precomputed_type;

    using g2_field_value_type = typename curve_type::template g2_type<>::field_type::value_type;

    using dbl_coeffs_type = typename value_type::dbl_coeffs_type;
    using add_coeffs_type = typename value_type::add_coeffs_type;
    using dbl_coeffs_value_type = g2_field_value_type;
    using add_coeffs_value_type = g2_field_value_type;

    for (auto &elem : test_set.second.get_child("g2_precomputed_type")) {
        elements.emplace_back(value_type());

        elements.back().QX = field_element_init<g2_field_value_type>::process(elem.second.get_child("QX").front());
        elements.back().QY = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY").front());
        elements.back().QY2 = field_element_init<g2_field_value_type>::process(elem.second.get_child("QY2").front());
        elements.back().QX_over_twist =
            field_element_init<g2_field_value_type>::process(elem.second.get_child("QX_over_twist").front());
        elements.back().QY_over_twist =
            field_element_init<g2_field_value_type>::process(elem.second.get_child("QY_over_twist").front());

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

template<typename CurveType, typename TestSet>
void pairing_operation_test(const TestSet &test_set) {
    std::vector<typename CurveType::scalar_field_type::value_type> Fr_elements;
    std::vector<typename CurveType::template g1_type<>::value_type> G1_elements;
    std::vector<typename CurveType::template g2_type<>::value_type> G2_elements;
    std::vector<typename CurveType::gt_type::value_type> GT_elements;
    std::vector<typename pairing::pairing_policy<CurveType>::g1_precomputed_type> G1_prec_elements;
    std::vector<typename pairing::pairing_policy<CurveType>::g2_precomputed_type> G2_prec_elements;

    pairing_test_init<CurveType>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements, G2_prec_elements,
                                test_set);
    check_pairing_operations<CurveType>(Fr_elements, G1_elements, G2_elements, GT_elements, G1_prec_elements,
                                       G2_prec_elements);
}

BOOST_AUTO_TEST_SUITE(pairing_manual_tests)

// TODO: fix pair_reduceding
BOOST_DATA_TEST_CASE(pairing_operation_test_bls12_381, string_data("pairing_operation_test_bls12_381"), data_set) {
    using curve_type = typename curves::bls12<381>;

    pairing_operation_test<curve_type>(data_set);
}

BOOST_DATA_TEST_CASE(pairing_operation_test_mnt4_298, string_data("pairing_operation_test_mnt4_298"), data_set) {
    using curve_type = typename curves::mnt4<298>;

    pairing_operation_test<curve_type>(data_set);
}

BOOST_DATA_TEST_CASE(pairing_operation_test_mnt6_298, string_data("pairing_operation_test_mnt6_298"), data_set) {
    using curve_type = typename curves::mnt6<298>;

    pairing_operation_test<curve_type>(data_set);
}

BOOST_DATA_TEST_CASE(pairing_operation_test_alt_bn128, string_data("pairing_operation_test_alt_bn128_254"), data_set) {
    using curve_type = typename curves::alt_bn128<254>;

    pairing_operation_test<curve_type>(data_set);
}

BOOST_AUTO_TEST_SUITE_END()
