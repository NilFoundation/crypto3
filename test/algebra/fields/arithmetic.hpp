//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_ELEMENT_FP2_COMPONENT_TEST_HPP
#define CRYPTO3_ZK_BLUEPRINT_ELEMENT_FP2_COMPONENT_TEST_HPP

#include <boost/test/unit_test.hpp>

using namespace nil::crypto3::zk;

template <typename FieldType, template<class> class Fpk_variableT, 
          template<class> class Fpk_mul_componentT>
components::blueprint<typename FieldType::base_field_type> test_field_element_mul(typename FieldType::value_type a_value, 
                                                      typename FieldType::value_type b_value){
    using field_type = FieldType;
    using element_component = Fpk_variableT<field_type>;
    using element_mul_component = Fpk_mul_componentT<field_type>;
    using base_field_type = typename field_type::base_field_type;

    components::blueprint<base_field_type> bp;

    element_component A(bp, a_value);
    element_component B(bp, b_value);
    element_component result(bp);

    element_mul_component el_mul_instance(bp, A, B, result);
    el_mul_instance.generate_r1cs_constraints();
    el_mul_instance.generate_r1cs_witness();

    const typename field_type::value_type res = result.get_element();

    BOOST_CHECK(bp.is_satisfied());
    BOOST_CHECK(res == (a_value * b_value));

    return bp;
}

template <typename FieldType, template<class> class Fpk_variableT, 
          template<class> class Fpk_squared_componentT>
components::blueprint<typename FieldType::base_field_type> test_field_element_squared(typename FieldType::value_type a_value){
    using field_type = FieldType;
    using element_component = Fpk_variableT<field_type>;
    using element_squared_component = Fpk_squared_componentT<field_type>;
    using base_field_type = typename field_type::base_field_type;

    components::blueprint<base_field_type> bp;

    element_component A(bp, a_value);
    element_component result(bp);

    element_squared_component el_squared_instance(bp, A, result);
    el_squared_instance.generate_r1cs_constraints();
    el_squared_instance.generate_r1cs_witness();

    const typename field_type::value_type res = result.get_element();

    BOOST_CHECK(bp.is_satisfied());
    BOOST_CHECK(res == (a_value.squared()));

    return bp;
}

#endif    // CRYPTO3_ZK_BLUEPRINT_ELEMENT_FP2_COMPONENT_TEST_HPP
