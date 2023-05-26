//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_plonk_gates_test

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <random>
#include <experimental/random>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename Field>
bool are_lookup_constraints_equal(
    const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &lhs,
    const nil::crypto3::zk::snark::plonk_lookup_constraint<Field> &rhs
){
    if(lhs.lookup_input.size() != rhs.lookup_input.size() ) return false;
    for( size_t i = 0; i < lhs.lookup_input.size(); i++ ){
        if(lhs.lookup_input[i] != rhs.lookup_input[i]) return false;
    }

    if(lhs.lookup_value.size() != rhs.lookup_value.size() ) return false;
    for( size_t i = 0; i < lhs.lookup_value.size(); i++ ){
        if(lhs.lookup_value[i] != rhs.lookup_value[i]) return false;
    }
    return true;
}

template<typename Field>
bool are_plonk_gates_equal(
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> &lhs,
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> &rhs
) {
    if (lhs.selector_index != rhs.selector_index)
        return false;
    if (lhs.constraints.size() != rhs.constraints.size())
        return false;
    for (auto i = 0; i < lhs.constraints.size(); i++) {
        if (lhs.constraints[i] != rhs.constraints[i])
            return false;
    }
    return true;
}

template<typename Field>
bool are_plonk_lookup_gates_equal(
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> &lhs,
    const nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> &rhs
) {
    if (lhs.selector_index != rhs.selector_index)
        return false;
    if (lhs.constraints.size() != rhs.constraints.size())
        return false;
    for (auto i = 0; i < lhs.constraints.size(); i++) {
        if (!are_lookup_constraints_equal<Field>(lhs.constraints[i], rhs.constraints[i]))
            return false;
    }
    return true;
}

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::random_device rd;
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return rd() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

template<typename PlonkVariable>
PlonkVariable generate_random_plonk_variable() {
    return PlonkVariable(std::random_device()(),
        std::experimental::randint(0, std::numeric_limits<int>::max()), 
        std::experimental::randint(0, 1) == 0,
        typename PlonkVariable::column_type(
            std::experimental::randint(int(PlonkVariable::column_type::witness), int(PlonkVariable::column_type::selector))
        )
    );
}

template<typename PlonkVariable>
nil::crypto3::math::term<PlonkVariable> generate_random_plonk_term(std::size_t vars_n) {
    nil::crypto3::math::term<PlonkVariable> result;
    nil::crypto3::random::algebraic_random_device<typename PlonkVariable::field_type> d;
    result.coeff = d();
    for (auto i = 0; i < vars_n; i++) {
        result.vars.emplace_back(generate_random_plonk_variable<PlonkVariable>());
    }
    return result;
}

template<typename PlonkVariable>
nil::crypto3::math::expression<PlonkVariable>
    generate_random_plonk_expression(std::size_t vars_n, std::size_t terms_n) {
    nil::crypto3::math::expression<PlonkVariable> expr(generate_random_plonk_term<PlonkVariable>(vars_n));
    for (auto i = 0; i < terms_n - 1; i++) {
        expr += generate_random_plonk_term<PlonkVariable>(vars_n);
    }
    return expr;
}

template<typename Field>
nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> 
generate_random_plonk_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = typename nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = typename nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;

    std::size_t selector_index = std::random_device()();
    std::vector<constraint_type> constraints;
    for (auto i = 0; i < constr_n; i++) {
        constraints.template emplace_back(
            generate_random_plonk_expression<nil::crypto3::zk::snark::plonk_variable<Field>>(vars_n,
                                                                                                         terms_n));
    }
    return {selector_index, constraints};
}

template<typename Field>
nil::crypto3::zk::snark::plonk_lookup_constraint<Field> generate_random_plonk_lookup_constraint(size_t vars_n, size_t inp_len, size_t value_len){
    nil::crypto3::zk::snark::plonk_lookup_constraint<Field> result;

    for( size_t i = 0; i < inp_len; i++ ){
        result.lookup_input.push_back(generate_random_plonk_term<nil::crypto3::zk::snark::plonk_variable<Field>>(vars_n));
    }
    for( size_t i = 0; i < value_len; i++ ){
        result.lookup_value.push_back(generate_random_plonk_variable<nil::crypto3::zk::snark::plonk_variable<Field>>());
    }

    return result;
}

template<typename Field>
nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<Field>>> 
generate_random_plonk_lookup_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = typename nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = typename nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;

    std::size_t selector_index = std::random_device()();
    std::vector<constraint_type> constraints;
    for (auto i = 0; i < constr_n; i++) {
        constraints.template emplace_back(
            generate_random_plonk_lookup_constraint<Field>(vars_n, terms_n, terms_n));
    }
    return {selector_index, constraints};
}

template<typename Field, typename Endianness>
void test_plonk_variable() {
    using namespace nil::crypto3::marshalling;

    using value_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_marshalling_type = typename types::variable<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_variable<value_type>();

    auto filled_val = nil::crypto3::marshalling::types::fill_variable<value_type, Endianness>(val);
    auto _val = types::make_variable<value_type, Endianness>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_variable<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_variables(std::size_t n) {
    using namespace nil::crypto3::marshalling;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using value_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_marshalling_type = typename types::variables<nil::marshalling::field_type<Endianness>, Field>;

    std::vector<value_type> val;
    for( size_t i = 0; i < n; i++){
        val.push_back( generate_random_plonk_variable<value_type>() );
    }

    auto filled_val = nil::crypto3::marshalling::types::fill_variables<value_type, Endianness>(val);
    auto _val = types::make_variables<value_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for( std::size_t i = 0; i < val.size(); i++ ){
        BOOST_CHECK(val[i] == _val[i]);
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_variables<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val.size() == _val.size());
    for( std::size_t i = 0; i < val.size(); i++ ){
        BOOST_CHECK(val[i] == _val[i]);
    }
}

template<typename Field, typename Endianness>
void test_plonk_term(std::size_t vars_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::math::term<variable_type>;
    using value_marshalling_type =
        typename types::term<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_term<variable_type>(vars_n);

    auto filled_val = types::fill_term<value_type, Endianness>(val);
    auto _val = types::make_term<value_type, Endianness>(filled_val);
    BOOST_CHECK_EQUAL(val, _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_term<value_type, Endianness>(test_val_read);
    BOOST_CHECK_EQUAL(val, constructed_val_read);
}

template<typename Field, typename Endianness>
void test_expression(std::size_t vars_n, std::size_t terms_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::math::expression<variable_type>;
    using value_marshalling_type =
        typename types::expression<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_expression<variable_type>(vars_n, terms_n);

    auto filled_val = types::fill_expression<value_type, Endianness>(val);
    auto _val = types::make_expression<value_type, Endianness>(filled_val);
    BOOST_CHECK_EQUAL(val, _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_expression<value_type, Endianness>(test_val_read);
    BOOST_CHECK_EQUAL(val, constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_constraint(std::size_t vars_n, std::size_t terms_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_marshalling_type = types::plonk_constraint<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = value_type(generate_random_plonk_expression<variable_type>(vars_n, terms_n));

    auto filled_val = types::fill_plonk_constraint<value_type, Endianness>(val);
    auto _val = types::make_plonk_constraint<value_type, Endianness>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_constraint<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_constraints(std::size_t vars_n, std::size_t terms_n, std::size_t constraints_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = std::vector<constraint_type>;
    using value_marshalling_type = types::plonk_constraints<nil::marshalling::field_type<Endianness>, constraint_type>;

    value_type val;
    for( std::size_t i = 0; i < constraints_n; i++ ){
        val.emplace_back(generate_random_plonk_expression<variable_type>(vars_n, terms_n));
    }

    auto filled_val = types::fill_plonk_constraints<constraint_type, Endianness>(val);
    auto _val = types::make_plonk_constraints<constraint_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for( std::size_t i = 0; i < _val.size(); i++){
        BOOST_CHECK(val[i] == _val[i]);
    }  

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_constraints<constraint_type, Endianness>(test_val_read);

    BOOST_CHECK(val.size() == constructed_val_read.size());
    for( std::size_t i = 0; i < val.size(); i++){
        BOOST_CHECK(val[i] == constructed_val_read[i]);
    }  
}
    
template<typename Field, typename Endianness>
void test_plonk_lookup_constraints(std::size_t vars_n, std::size_t terms_n, std::size_t constraints_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = std::vector<constraint_type>;
    using value_marshalling_type = types::plonk_constraints<nil::marshalling::field_type<Endianness>, constraint_type>;

    value_type val;
    for( std::size_t i = 0; i < constraints_n; i++ ){
        val.emplace_back(generate_random_plonk_lookup_constraint<Field>(vars_n, terms_n, terms_n));
    }

    auto filled_val = types::fill_plonk_constraints<constraint_type, Endianness>(val);
    auto _val = types::make_plonk_constraints<constraint_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for( std::size_t i = 0; i < _val.size(); i++){
        BOOST_CHECK(are_lookup_constraints_equal(val[i], _val[i]));
    }  

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_constraints<constraint_type, Endianness>(test_val_read);

    BOOST_CHECK(val.size() == constructed_val_read.size());
    for( std::size_t i = 0; i < val.size(); i++){
        BOOST_CHECK(are_lookup_constraints_equal(val[i], constructed_val_read[i]));
    } 
}

template<typename Field, typename Endianness>
void test_plonk_lookup_constraint(std::size_t vars_n, std::size_t lookups_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using value_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_marshalling_type = typename types::plonk_gate_constraint<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_lookup_constraint<Field>(vars_n, lookups_n, lookups_n);

    auto filled_val = types::fill_plonk_constraint<value_type, Endianness>(val);
    auto _val = types::make_plonk_constraint<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_lookup_constraints_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_constraint<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_lookup_constraints_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gate<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = generate_random_plonk_gate<Field>(vars_n, terms_n, constr_n);

    auto filled_val = types::fill_plonk_gate<value_type, Endianness>(val);
    auto _val = types::make_plonk_gate<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_plonk_gates_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gate<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_plonk_gates_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_lookup_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using namespace nil::crypto3::marshalling;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gate<TTypeBase, value_type>;

    auto val = generate_random_plonk_lookup_gate<Field>(vars_n, terms_n, constr_n);

    auto filled_val = types::fill_plonk_gate<value_type, Endianness>(val);
    auto _val = types::make_plonk_gate<value_type, Endianness>(filled_val);
    BOOST_CHECK(are_plonk_lookup_gates_equal(val, _val));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gate<value_type, Endianness>(test_val_read);
    BOOST_CHECK(are_plonk_lookup_gates_equal(val, constructed_val_read));
}

template<typename Field, typename Endianness>
void test_plonk_gates(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n, std::size_t gates_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gates<nil::marshalling::field_type<Endianness>, value_type>;

    std::vector<value_type> val;
    for (auto i = 0; i < gates_n; i++) {
        val.template emplace_back(generate_random_plonk_gate<Field>(vars_n, terms_n, constr_n));
    }

    auto filled_val = types::fill_plonk_gates<value_type, Endianness>(val);
    auto _val = types::make_plonk_gates<value_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_gates_equal(val[i], _val[i]));
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gates<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val.size() == constructed_val_read.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_gates_equal(val[i], constructed_val_read[i]));
    }
}

template<typename Field, typename Endianness>
void test_plonk_lookup_gates(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n, std::size_t gates_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<Field>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gates<nil::marshalling::field_type<Endianness>, value_type>;

    std::vector<value_type> val;
    for (auto i = 0; i < gates_n; i++) {
        val.template emplace_back(generate_random_plonk_lookup_gate<Field>(vars_n, terms_n, constr_n));
    }

    auto filled_val = types::fill_plonk_gates<value_type, Endianness>(val);
    auto _val = types::make_plonk_gates<value_type, Endianness>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_lookup_gates_equal(val[i], _val[i]));
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_plonk_gates<value_type, Endianness>(test_val_read);
    BOOST_CHECK(val.size() == constructed_val_read.size());
    for (auto i = 0; i < val.size(); i++) {
        BOOST_CHECK(are_plonk_lookup_gates_equal(val[i], constructed_val_read[i]));
    }
}

// TODO add test_plonk_lookup_constraint
BOOST_AUTO_TEST_SUITE(alt_bn128_254_scalar)
    using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
    using field_type = typename curve_type::scalar_field_type;
    using endianness = nil::marshalling::option::big_endian;

BOOST_AUTO_TEST_CASE(marshalling_plonk_variable) {
    for (auto i = 0; i < 100; i++) {
        test_plonk_variable<field_type, endianness>();
    }
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_variables) {
    test_plonk_variables<field_type,endianness>(50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_term) {
    test_plonk_term<field_type, endianness>(50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_expression) {
    test_expression<field_type, endianness>(50, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_constraint) {
    test_plonk_constraint<field_type, endianness>(50, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_constraints) {
    test_plonk_constraints<field_type, endianness>(50, 50, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_gate){
    test_plonk_gate<field_type, endianness>(50, 50, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_gates){
    test_plonk_gates<field_type, endianness>(50, 50, 50, 5);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_constraint){
    test_plonk_lookup_constraint<field_type, endianness>(10, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_constraints){
    test_plonk_lookup_constraints<field_type, endianness>(10, 50, 10);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_gate){
    test_plonk_lookup_gate<field_type, endianness>(50, 50, 50);
}

BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_gates){
    test_plonk_lookup_gates<field_type, endianness>(50, 50, 50, 5);
}
BOOST_AUTO_TEST_SUITE_END()
