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

#define BOOST_TEST_MODULE algebra_fields_test

#include <iostream>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>
#include <nil/crypto3/algebra/fields/curve25519/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/maxprime.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>

using namespace nil::crypto3::algebra;

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

typedef std::size_t constant_type;
enum field_operation_test_constants : std::size_t { C1, constants_set_size };

enum field_operation_test_elements : std::size_t {
    e1,
    e2,
    e1_plus_e2,
    e1_minus_e2,
    e1_mul_e2,
    e1_dbl,
    e2_inv,
    e1_pow_C1,
    e2_pow_2,
    e2_pow_2_sqrt,
    minus_e1,

    elements_set_size
};


boost::property_tree::ptree string_data(std::string test_name) {
    // if target == check-algebra just data/fields.json
    static std::string test_data = std::string(TEST_DATA_DIR) + R"(fields.json)";
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
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
struct field_element_init<fields::detail::element_fp6_3over2<FieldParams>> {
    using element_type = fields::detail::element_fp6_3over2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp2 over element_fp
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
            element_values[i++] = underlying_type_3over2(
                underlying_element_values[0], underlying_element_values[1], underlying_element_values[2]);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename element_type>
void check_field_operations(const std::vector<element_type> &elements, const std::vector<constant_type> &constants) {
    BOOST_CHECK_EQUAL(elements[e1] + elements[e2], elements[e1_plus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] - elements[e2], elements[e1_minus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] * elements[e2], elements[e1_mul_e2]);
    BOOST_CHECK_EQUAL(elements[e1].doubled(), elements[e1_dbl]);
    BOOST_CHECK_EQUAL(elements[e2].inversed(), elements[e2_inv]);
    BOOST_CHECK_EQUAL(elements[e1].pow(constants[C1]), elements[e1_pow_C1]);
    BOOST_CHECK_EQUAL(elements[e2].squared(), elements[e2_pow_2]);
    BOOST_CHECK_EQUAL((elements[e2].squared()).sqrt().squared(), elements[e2_pow_2_sqrt].squared());
    BOOST_CHECK_EQUAL(-elements[e1], elements[minus_e1]);
}

template<typename element_type>
void check_field_eq_operations(const std::vector<element_type> &elements) {
    element_type A;

    A = elements[e1]; A += elements[e2]; BOOST_CHECK_EQUAL(A, elements[e1_plus_e2]);
    A = elements[e1]; A -= elements[e2]; BOOST_CHECK_EQUAL(A, elements[e1_minus_e2]);
    A = elements[e1]; A *= elements[e2]; BOOST_CHECK_EQUAL(A, elements[e1_mul_e2]);
}

template<typename element_type>
void check_field_operations_wo_sqrt(const std::vector<element_type> &elements,
                                    const std::vector<constant_type> &constants) {
    BOOST_CHECK_EQUAL(elements[e1] + elements[e2], elements[e1_plus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] - elements[e2], elements[e1_minus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] * elements[e2], elements[e1_mul_e2]);
    BOOST_CHECK_EQUAL(elements[e1].doubled(), elements[e1_dbl]);
    BOOST_CHECK_EQUAL(elements[e2].inversed(), elements[e2_inv]);
    BOOST_CHECK_EQUAL(elements[e1].pow(constants[C1]), elements[e1_pow_C1]);
    BOOST_CHECK_EQUAL(elements[e2].squared(), elements[e2_pow_2]);
    // BOOST_CHECK_EQUAL((elements[e2].squared()).sqrt(), elements[e2_pow_2_sqrt]);
    BOOST_CHECK_EQUAL(-elements[e1], elements[minus_e1 - 1]);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp4<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
    check_field_eq_operations(elements);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp6_3over2<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
    check_field_eq_operations(elements);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp6_2over3<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
    check_field_eq_operations(elements);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp12_2over3over2<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
    check_field_eq_operations(elements);
}

template<typename ElementType, typename TestSet>
void field_test_init(std::vector<ElementType> &elements,
                     std::vector<constant_type> &constants,
                     const TestSet &test_set) {
    for (auto &element : test_set.second.get_child("elements_values")) {
        elements.emplace_back(field_element_init<ElementType>::process(element));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoll(constant.second.data()));
    }
}

template<typename FieldType, typename TestSet>
void field_operation_test(const TestSet &test_set) {
    std::vector<typename FieldType::value_type> elements;
    std::vector<constant_type> constants;

    field_test_init(elements, constants, test_set);

    check_field_operations(elements, constants);
    check_field_eq_operations(elements);
}

template<typename FieldType, typename TestSet>
void field_not_square_test(const TestSet &test_set) {
    std::vector<typename FieldType::value_type> elements;

    for (auto &element : test_set.second.get_child("elements_values")) {
        elements.emplace_back(field_element_init<typename FieldType::value_type>::process(element));
    }

    for (auto &not_square : elements) {
        BOOST_CHECK(!not_square.is_square());
        BOOST_CHECK(not_square.pow(2).is_square());
        auto sqrt = not_square.pow(2).sqrt();
        BOOST_CHECK(sqrt == not_square || (sqrt + not_square).is_zero());
    }
}

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

BOOST_DATA_TEST_CASE(field_operation_test_goldilocks64_fq, string_data("field_operation_test_goldilocks64_fq"), data_set) {
    using policy_type = fields::goldilocks64_fq;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fr, string_data("field_operation_test_bls12_381_fr"), data_set) {
    using policy_type = fields::bls12_fr<381>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq, string_data("field_operation_test_bls12_381_fq"), data_set) {
    using policy_type = fields::bls12_fq<381>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq2, string_data("field_operation_test_bls12_381_fq2"), data_set) {
    using policy_type = fields::fp2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq6, string_data("field_operation_test_bls12_381_fq6"), data_set) {
    using policy_type = fields::fp6_3over2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq12,
                     string_data("field_operation_test_bls12_381_fq12"),
                     data_set) {
    using policy_type = fields::fp12_2over3over2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_AUTO_TEST_CASE(field_operation_test_maxprime){
    using maxprime_field_type = fields::maxprime<64>;
    typename maxprime_field_type::value_type zero = maxprime_field_type::value_type::zero();
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq, string_data("field_operation_test_mnt4_fq"), data_set) {
    using policy_type = fields::mnt4<298>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq2, string_data("field_operation_test_mnt4_fq2"), data_set) {
    using policy_type = fields::fp2<fields::mnt4<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq4, string_data("field_operation_test_mnt4_fq4"), data_set) {
    using policy_type = fields::fp4<fields::mnt4<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq, string_data("field_operation_test_mnt6_fq"), data_set) {
    using policy_type = fields::mnt6<298>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq3, string_data("field_operation_test_mnt6_fq3"), data_set) {
    using policy_type = fields::fp3<fields::mnt6<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq6, string_data("field_operation_test_mnt6_fq6"), data_set) {
    using policy_type = fields::fp6_2over3<fields::mnt6<298>>;

    field_operation_test<policy_type>(data_set);
}

 BOOST_DATA_TEST_CASE(field_operation_test_secp256k1_fr, string_data("field_operation_test_secp256k1_fr"), data_set) {
     using policy_type = fields::secp_k1_fr<256>;

     field_operation_test<policy_type>(data_set);
 }

BOOST_DATA_TEST_CASE(field_operation_test_secp256r1_fr, string_data("field_operation_test_secp256r1_fr"), data_set) {
    using policy_type = fields::secp_r1_fr<256>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_secp256k1_fq, string_data("field_operation_test_secp256k1_fq"), data_set) {
    using policy_type = fields::secp_k1_fq<256>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_secp256r1_fq, string_data("field_operation_test_secp256r1_fq"), data_set) {
    using policy_type = fields::secp_r1_fq<256>;

    field_operation_test<policy_type>(data_set);
}

/* Fields covered with not_square test:
 * mnt4_298_base_field
 * mnt4_298_scalar_field
 * mnt4_298_g2 (Fp2)

 * mnt6_298_base_field
 * mnt6_298_scalar_field
 * mnt6_298_g2 (Fp3)

 * bls12_381_base_field
 * bls12_381_scalar_field
 * bls12_381_g2 (Fp2)

 * bls12_377_base_field
 * bls12_377_scalar_field
 * bls12_377_g2 (Fp2)

 * pallas_base_field
 * vesta_base_field

 * goldilocks64

 */

BOOST_DATA_TEST_CASE(field_not_square_test_mnt4_298_base_field, string_data("field_not_square_test_mnt4_298_base_field"), data_set) {
    using policy_type = typename curves::mnt4_298::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_mnt4_298_scalar_field, string_data("field_not_square_test_mnt4_298_scalar_field"), data_set) {
    using policy_type = typename curves::mnt4_298::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_mnt4_298_g2, string_data("field_not_square_test_mnt4_298_g2"), data_set) {
    using policy_type = typename curves::mnt4_298::template g2_type<>::field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_mnt6_298_base_field, string_data("field_not_square_test_mnt4_298_scalar_field"), data_set) {
    using policy_type = typename curves::mnt6_298::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_mnt6_298_scalar_field, string_data("field_not_square_test_mnt4_298_base_field"), data_set) {
    using policy_type = typename curves::mnt6_298::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_mnt6_298_g2, string_data("field_not_square_test_mnt6_298_g2"), data_set) {
    using policy_type = typename curves::mnt6_298::template g2_type<>::field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_bls12_381_base_field, string_data("field_not_square_test_bls12_381_base_field"), data_set) {
    using policy_type = typename curves::bls12_381::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_bls12_381_scalar_field, string_data("field_not_square_test_bls12_381_scalar_field"), data_set) {
    using policy_type = typename curves::bls12_381::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_bls12_381_g2, string_data("field_not_square_test_bls12_381_g2"), data_set) {
    using policy_type = typename curves::bls12_381::template g2_type<>::field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_bls12_377_base_field, string_data("field_not_square_test_bls12_377_base_field"), data_set) {
    using policy_type = typename curves::bls12_377::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_bls12_377_scalar_field, string_data("field_not_square_test_bls12_377_scalar_field"), data_set) {
    using policy_type = typename curves::bls12_377::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_bls12_377_g2, string_data("field_not_square_test_bls12_377_g2"), data_set) {
    using policy_type = typename curves::bls12_377::template g2_type<>::field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_pallas_base_field, string_data("field_not_square_test_pallas_base_field"), data_set) {
    using policy_type = typename curves::pallas::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_pallas_scalar_field, string_data("field_not_square_test_pallas_scalar_field"), data_set) {
    using policy_type = typename curves::pallas::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_vesta_base_field, string_data("field_not_square_test_pallas_scalar_field"), data_set) {
    using policy_type = typename curves::vesta::base_field_type;

    field_not_square_test<policy_type>(data_set);
}
BOOST_DATA_TEST_CASE(field_not_square_test_vesta_scalar_field, string_data("field_not_square_test_pallas_base_field"), data_set) {
    using policy_type = typename curves::vesta::scalar_field_type;

    field_not_square_test<policy_type>(data_set);
}


BOOST_DATA_TEST_CASE(field_not_square_test_goldilocks64_base_field, string_data("field_not_square_test_goldilocks64_base_field"), data_set) {
    using policy_type = typename fields::goldilocks64_base_field;

    field_not_square_test<policy_type>(data_set);
}

BOOST_AUTO_TEST_CASE(field_not_square_test_secp_k1) {

    for(auto const& data_set: string_data("field_not_square_test_secp_k1_160_base_field") ) {
        field_not_square_test<typename curves::secp_k1<160>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_192_base_field") ) {
        field_not_square_test<typename curves::secp_k1<192>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_224_base_field") ) {
        field_not_square_test<typename curves::secp_k1<224>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_256_base_field") ) {
        field_not_square_test<typename curves::secp_k1<256>::base_field_type>( data_set );
    }

    for(auto const& data_set: string_data("field_not_square_test_secp_k1_160_scalar_field") ) {
        field_not_square_test<typename curves::secp_k1<160>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_192_scalar_field") ) {
        field_not_square_test<typename curves::secp_k1<192>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_224_scalar_field") ) {
        field_not_square_test<typename curves::secp_k1<224>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_k1_256_scalar_field") ) {
        field_not_square_test<typename curves::secp_k1<256>::scalar_field_type>( data_set );
    }
}

BOOST_AUTO_TEST_CASE(field_not_square_test_secp_r1) {

    for(auto const& data_set: string_data("field_not_square_test_secp_r1_160_base_field") ) {
        field_not_square_test<typename curves::secp_r1<160>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_192_base_field") ) {
        field_not_square_test<typename curves::secp_r1<192>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_224_base_field") ) {
        field_not_square_test<typename curves::secp_r1<224>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_256_base_field") ) {
        field_not_square_test<typename curves::secp_r1<256>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_384_base_field") ) {
        field_not_square_test<typename curves::secp_r1<384>::base_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_521_base_field") ) {
        field_not_square_test<typename curves::secp_r1<521>::base_field_type>( data_set );
    }

    for(auto const& data_set: string_data("field_not_square_test_secp_r1_160_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<160>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_192_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<192>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_224_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<224>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_256_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<256>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_384_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<384>::scalar_field_type>( data_set );
    }
    for(auto const& data_set: string_data("field_not_square_test_secp_r1_521_scalar_field") ) {
        field_not_square_test<typename curves::secp_r1<521>::scalar_field_type>( data_set );
    }

}

BOOST_AUTO_TEST_SUITE_END()
