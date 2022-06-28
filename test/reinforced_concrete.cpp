
#define BOOST_TEST_MAIN

#include <iostream>
#include <boost/test/included/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include "nil/crypto3/hash/reinforced_concrete.hpp"
#include "nil/crypto3/algebra/fields/bls12/scalar_field.hpp"
#include <iostream>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
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

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

using rc_default_field_t = fields::bls12_fr<381>;
using rc_functions_t = hashes::detail::reinforced_concrete_functions<rc_default_field_t>;
using operators = rc_functions_t::reinforced_concrete_operators_type;
using element_type = rc_functions_t::element_type;
using integral_type = rc_functions_t::integral_type;
using state_type = rc_functions_t::state_type;

BOOST_AUTO_TEST_CASE(check_inversity_of_compose_decompose_for_0){
    element_type zero = element_type(integral_type(0));
    operators::bucket_type after_decompose = operators::decompose(zero);
    element_type zero_after = operators::compose(after_decompose);
    BOOST_CHECK_EQUAL(zero, zero_after);
}

BOOST_AUTO_TEST_CASE(check_inversity_of_compose_decompose_for_1){
    element_type one = element_type(integral_type(1));
    operators::bucket_type after_decompose = operators::decompose(one);
    element_type one_after = operators::compose(after_decompose);
    BOOST_CHECK_EQUAL(one, one_after);
}

BOOST_AUTO_TEST_CASE(bricks_for_bls12fr381){
    operators::state_vector_type state = {{2, 2, 2}};

    operators::bricks(state);
    BOOST_CHECK_EQUAL(state[0], element_type(integral_type(32)));
    BOOST_CHECK_EQUAL(state[1], element_type(integral_type(16)));
    BOOST_CHECK_EQUAL(state[2], element_type(integral_type(28)));
}

BOOST_AUTO_TEST_CASE(permute){
    state_type temp_state = {element_type(integral_type(0)), element_type(integral_type(0)), element_type(integral_type(0))};
    rc_functions_t::permute(temp_state);
}