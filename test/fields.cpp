//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE fields_algebra_test

#include <iostream>
#include <cstdint>
#include <string>

// #include <boost/multiprecision/cpp_modular.hpp>
// #include <boost/multiprecision/number.hpp>
// #include <boost/multiprecision/cpp_int.hpp>
// #include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>

// #include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
// #include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
//#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
// #include <nil/crypto3/algebra/fields/dsa_botan.hpp>
// #include <nil/crypto3/algebra/fields/dsa_jce.hpp>
// #include <nil/crypto3/algebra/fields/ed25519_fe.hpp>
// #include <nil/crypto3/algebra/fields/ffdhe_ietf.hpp>
// #include <nil/crypto3/algebra/fields/field.hpp>
// #include <nil/crypto3/algebra/fields/modp_ietf.hpp>
// #include <nil/crypto3/algebra/fields/modp_srp.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << e.data[0].data << " " << e.data[1].data << std::endl;
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

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
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

typedef int64_t constant_type;
enum field_operation_test_constants : std::size_t {
    C1
};

enum field_operation_test_elements : std::size_t {
    e1,
    e2,
    e1_plus_e2,
    e1_minus_e2,
    e1_mul_e2,
    e1_dbl,
    e2_inv,
    e1_pow_C1,
    e2_pow_2
    //e2_pow_2_sqrt
};

// if target == check-algebra just data/fields.json
const char *test_data = "libs/crypto3-algebra/test/data/fields.json";
//const char *test_data = "libs/algebra/test/data/fields.json";

boost::property_tree::ptree string_data(std::string test_name) {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

template<typename element_type>
void check_field_operations(const std::vector<element_type> &elements,
                            const std::vector<constant_type> &constants) {
    BOOST_CHECK_EQUAL(elements[e1] + elements[e2], elements[e1_plus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] - elements[e2], elements[e1_minus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] * elements[e2], elements[e1_mul_e2]);
    BOOST_CHECK_EQUAL(elements[e1].doubled(), elements[e1_dbl]);
    BOOST_CHECK_EQUAL(elements[e2].inversed(), elements[e2_inv]);
    BOOST_CHECK_EQUAL(elements[e1].pow(constants[C1]), elements[e1_pow_C1]);
    BOOST_CHECK_EQUAL(elements[e2].squared(), elements[e2_pow_2]);
    //BOOST_CHECK_EQUAL((elements[e2].squared()).sqrt(), elements[e2_pow_2_sqrt]);
}

template<typename FieldParams, typename TestSet>
void field_test_init(std::vector<typename fields::detail::element_fp<FieldParams>> &elements,
                     std::vector<constant_type> &constants,
                     const TestSet &test_set) {
    using element_type = typename fields::detail::element_fp<FieldParams>;

    for (auto &element : test_set.second.get_child("elements_values")) {
        elements.emplace_back(
            element_type(
                typename element_type::modulus_type(element.second.data())
            )
        );
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoll(constant.second.data()));
    }
}

template<typename FieldParams, typename TestSet>
void field_test_init(std::vector<typename fields::detail::element_fp2<FieldParams>> &elements,
                     std::vector<constant_type> &constants,
                     const TestSet &test_set) {
    using element_type = typename fields::detail::element_fp2<FieldParams>;
    using modulus_type = typename element_type::underlying_type::modulus_type;

    std::array<modulus_type, 2> element_values;

    for (auto &element : test_set.second.get_child("elements_values")) {
        auto i = 0;
        for (auto &element_value : element.second) {
            element_values[i++] = modulus_type(element_value.second.data());
        }
        elements.emplace_back(element_type(element_values[0], element_values[1]));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoll(constant.second.data()));
    }
}

template<typename FieldType, typename TestSet>
void curve_operation_test(const TestSet &test_set) {
    std::vector<typename FieldType::value_type> elements;
    std::vector<constant_type> constants;

    field_test_init(elements, constants, test_set);

    check_field_operations(elements, constants);
}

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

/*BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fr, string_data("field_operation_test_bls12_381_fr"), data_set) {
    using policy_type = fields::bls12_fr<381>;

    curve_operation_test<policy_type>(data_set);
}*/

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq2, string_data("field_operation_test_bls12_381_fq2"), data_set) {
    using policy_type = fields::fp2<fields::bls12_fq<381>>;

    curve_operation_test<policy_type>(data_set);
}

BOOST_AUTO_TEST_SUITE_END()
