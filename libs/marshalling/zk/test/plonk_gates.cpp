//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/lookup_table.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table.hpp>

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

template<typename PlonkVariable>
PlonkVariable generate_random_plonk_variable() {
    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<int> intmax(0, std::numeric_limits<int>::max());
    std::uniform_int_distribution<int> boolmax(0, 1);
    std::uniform_int_distribution<std::size_t> plonkvar(PlonkVariable::column_type::witness,
                                                        PlonkVariable::column_type::selector);

    return PlonkVariable(r(), intmax(e1), boolmax(e1) == 0, typename PlonkVariable::column_type(plonkvar(e1)));
}

template<typename FieldType, typename PlonkVariable>
nil::crypto3::math::term<PlonkVariable> generate_random_plonk_term(std::size_t vars_n) {
    std::vector<PlonkVariable> vars;
    for (std::size_t i = 0; i < vars_n; i++) {
        vars.emplace_back(generate_random_plonk_variable<PlonkVariable>());
    }
    return nil::crypto3::math::term<PlonkVariable>(vars, nil::crypto3::algebra::random_element<FieldType>());
}

template<typename FieldType, typename PlonkVariable>
nil::crypto3::math::expression<PlonkVariable>
generate_random_plonk_expression(std::size_t vars_n, std::size_t depth) {
    if( depth == 0 ){
        auto term = generate_random_plonk_term<FieldType, PlonkVariable>(vars_n);
        return nil::crypto3::math::expression<PlonkVariable>(term).pow(rand() % 5 + 1);
    }
    auto expr1 = generate_random_plonk_expression<FieldType, PlonkVariable>(vars_n, depth - 1);
    auto expr2 = generate_random_plonk_expression<FieldType, PlonkVariable>(vars_n, depth - 1);
    auto op = rand() % 3;
    if( op == 0){
        return expr1 + expr2;
    }
    if( op == 1 ){
        return expr1 - expr2;
    }
    if( op == 2 ){
        return expr1 * expr2;
    }
    return expr1 + expr2;
}

template<typename Field>
nil::crypto3::zk::snark::plonk_gate<Field, nil::crypto3::zk::snark::plonk_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>>
generate_random_plonk_gate(std::size_t vars_n, std::size_t depth, std::size_t constr_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = typename nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;

    std::size_t selector_index = rand() % vars_n;
    std::vector<constraint_type> constraints;
    for (std::size_t i = 0; i < constr_n; i++) {
        constraints.template emplace_back(
            generate_random_plonk_expression<Field, variable_type>( vars_n, depth )
        );
    }
    return {selector_index, constraints};
}

template<typename Field>
nil::crypto3::zk::snark::plonk_lookup_constraint<Field>
generate_random_plonk_lookup_constraint(size_t vars_n, std::size_t depth, std::size_t expr_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;

    nil::crypto3::zk::snark::plonk_lookup_constraint<Field> result;

    std::size_t n = rand()%expr_n + 1;
    for (size_t i = 0; i < n; i++) {
        result.lookup_input.push_back(
            generate_random_plonk_expression<Field, variable_type>(vars_n, depth)
        );
    }
    result.table_id = rand() % vars_n;

    return result;
}

template<typename Field>
nil::crypto3::zk::snark::plonk_lookup_gate<Field, nil::crypto3::zk::snark::plonk_lookup_constraint<Field, nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>>>
generate_random_plonk_lookup_gate(std::size_t vars_n, std::size_t depth, std::size_t expr_n, std::size_t constr_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = typename nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;

    std::size_t selector_index = std::random_device()();
    std::vector<constraint_type> constraints;
    for (std::size_t i = 0; i < constr_n; i++) {
        constraints.template emplace_back(generate_random_plonk_lookup_constraint<Field>(vars_n, depth, expr_n));
    }
    return {selector_index, constraints};
}

template<typename Field>
nil::crypto3::zk::snark::plonk_lookup_table<Field>
generate_random_plonk_lookup_table(std::size_t col_n, std::size_t op_n) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    std::size_t n = rand()%op_n + 1;
    nil::crypto3::zk::snark::plonk_lookup_table<Field> table(col_n, rand());
    for( std::size_t i = 0; i < n; i++ ){
        std::vector<variable_type> input;
        for( std::size_t j = 0; j < col_n; j++ ){
            input.emplace_back(generate_random_plonk_variable<variable_type>());
        }
        table.append_option(input);
    }
    return table;
}

template<typename Field, typename Endianness>
void test_plonk_variable() {
    using namespace nil::crypto3::marshalling;

    using varialbe_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_marshalling_type = typename types::variable<nil::marshalling::field_type<Endianness>, varialbe_type>::type;

    auto val = generate_random_plonk_variable<varialbe_type>();

    auto filled_val = nil::crypto3::marshalling::types::fill_variable<Endianness, varialbe_type>(val);
    auto _val = types::make_variable<Endianness,varialbe_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_variable<Endianness, varialbe_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_variables(std::size_t n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_marshalling_type = typename types::variables<nil::marshalling::field_type<Endianness>, Field>;

    std::vector<variable_type> val;
    for (size_t i = 0; i < n; i++) {
        val.push_back(generate_random_plonk_variable<variable_type>());
    }

    auto filled_val = nil::crypto3::marshalling::types::fill_variables<Endianness, variable_type>(val);
    auto _val = types::make_variables<Endianness, variable_type>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for (std::size_t i = 0; i < val.size(); i++) {
        BOOST_CHECK(val[i] == _val[i]);
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_variables<Endianness, variable_type>(test_val_read);
    BOOST_CHECK(val.size() == _val.size());
    for (std::size_t i = 0; i < val.size(); i++) {
        BOOST_CHECK(val[i] == _val[i]);
    }
}

template<typename Field, typename Endianness>
void test_plonk_term(std::size_t vars_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_type = nil::crypto3::math::term<variable_type>;
    using value_marshalling_type =
            typename types::term<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_term<Field, variable_type>(vars_n);
    auto filled_val = types::fill_term<Endianness, value_type>(val);
    auto _val = types::make_term<Endianness, value_type>(filled_val);
    BOOST_CHECK_EQUAL(val, _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_term<Endianness, value_type>(test_val_read);
    BOOST_CHECK_EQUAL(val, constructed_val_read);
}

template<typename Field, typename Endianness>
void test_expression(std::size_t vars_n, std::size_t terms_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_type = nil::crypto3::math::expression<variable_type>;
    using value_marshalling_type =
            typename types::expression<nil::marshalling::field_type<Endianness>, value_type>::type;

    auto val = generate_random_plonk_expression<Field, variable_type>(vars_n, terms_n);

    auto filled_val = types::fill_expression<value_type, Endianness>(val);
    auto _val = types::make_expression<value_type, Endianness>(filled_val);
    BOOST_CHECK_EQUAL(val, _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_expression<value_type, Endianness>(test_val_read);
    BOOST_CHECK_EQUAL(val, constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_constraint(std::size_t vars_n, std::size_t depth) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_marshalling_type = types::plonk_constraint<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = value_type(generate_random_plonk_expression<Field, variable_type>(vars_n, depth));

    auto filled_val = types::fill_plonk_constraint<Endianness, value_type>(val);
    auto _val = types::make_plonk_constraint<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_constraint<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_constraints(std::size_t vars_n, std::size_t depth, std::size_t constraints_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = std::vector<constraint_type>;
    using value_marshalling_type = types::plonk_constraints<nil::marshalling::field_type<Endianness>, constraint_type>;

    value_type val;
    for (std::size_t i = 0; i < constraints_n; i++) {
        val.emplace_back(generate_random_plonk_expression<Field, variable_type>(vars_n, depth));
    }

    auto filled_val = types::fill_plonk_constraints<Endianness, constraint_type>(val);
    auto _val = types::make_plonk_constraints<Endianness, constraint_type>(filled_val);
    BOOST_CHECK(val.size() == _val.size());
    for (std::size_t i = 0; i < _val.size(); i++) {
        BOOST_CHECK(val[i] == _val[i]);
    }

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_constraints<Endianness, constraint_type>(test_val_read);

    BOOST_CHECK(val.size() == constructed_val_read.size());
    for (std::size_t i = 0; i < val.size(); i++) {
        BOOST_CHECK(val[i] == constructed_val_read[i]);
    }
}

template<typename Field, typename Endianness>
void test_plonk_lookup_constraints(std::size_t vars_n, std::size_t depth, std::size_t expr_n, std::size_t constraints_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = std::vector<constraint_type>;
    using value_marshalling_type = types::plonk_lookup_constraints<nil::marshalling::field_type<Endianness>, constraint_type>;

    value_type val;
    for (std::size_t i = 0; i < constraints_n; i++) {
        val.emplace_back(generate_random_plonk_lookup_constraint<Field>(vars_n, depth, expr_n));
    }

    auto filled_val = types::fill_plonk_lookup_constraints<Endianness, constraint_type>(val);
    auto _val = types::make_plonk_lookup_constraints<Endianness, constraint_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_constraints<Endianness, constraint_type>(test_val_read);

    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_lookup_constraint(std::size_t vars_n, std::size_t depth, std::size_t expr_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using value_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_marshalling_type = types::plonk_lookup_constraint<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = generate_random_plonk_lookup_constraint<Field>(vars_n, depth, expr_n);

    auto filled_val = types::fill_plonk_lookup_constraint<Endianness, value_type>(val);
    auto _val = types::make_plonk_lookup_constraint<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_constraint<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_gate(std::size_t vars_n, std::size_t terms_n, std::size_t constr_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gate<nil::marshalling::field_type<Endianness>, value_type>;

    auto val = generate_random_plonk_gate<Field>(vars_n, terms_n, constr_n);

    auto filled_val = types::fill_plonk_gate<Endianness, value_type>(val);
    auto _val = types::make_plonk_gate<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_gate<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_lookup_gate(std::size_t vars_n, std::size_t depth, std::size_t expr_n, std::size_t constr_n) {
    using namespace nil::crypto3::marshalling;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_lookup_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_lookup_gate<TTypeBase, value_type>;

    auto val = generate_random_plonk_lookup_gate<Field>(vars_n, depth, expr_n, constr_n);
    auto filled_val = types::fill_plonk_lookup_gate<Endianness, value_type>(val);
    auto _val = types::make_plonk_lookup_gate<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_gate<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_gates(std::size_t vars_n, std::size_t depth, std::size_t constr_n, std::size_t gates_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_gates<nil::marshalling::field_type<Endianness>, value_type>;

    std::vector<value_type> val;
    for (std::size_t i = 0; i < gates_n; i++) {
        val.template emplace_back(generate_random_plonk_gate<Field>(vars_n, depth, constr_n));
    }

    auto filled_val = types::fill_plonk_gates<Endianness, value_type>(val);
    auto _val = types::make_plonk_gates<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_gates<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_lookup_gates(std::size_t vars_n, std::size_t depth, std::size_t expr_n, std::size_t constr_n, std::size_t gates_n) {
    using namespace nil::crypto3::marshalling;

    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename Field::value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<Field, variable_type>;
    using value_type = nil::crypto3::zk::snark::plonk_lookup_gate<Field, constraint_type>;
    using value_marshalling_type = types::plonk_lookup_gates<nil::marshalling::field_type<Endianness>, value_type>;

    std::vector<value_type> val;
    for (std::size_t i = 0; i < gates_n; i++) {
        val.template emplace_back(generate_random_plonk_lookup_gate<Field>(vars_n, depth, expr_n, constr_n));
    }

    auto filled_val = types::fill_plonk_lookup_gates<Endianness, value_type>(val);
    auto _val = types::make_plonk_lookup_gates<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_gates<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_lookup_table(std::size_t col_n, std::size_t op_n) {
    using namespace nil::crypto3::marshalling;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using value_type = nil::crypto3::zk::snark::plonk_lookup_table<Field>;
    using value_marshalling_type = types::plonk_lookup_table<TTypeBase, value_type>;

    auto val = generate_random_plonk_lookup_table<Field>(col_n, op_n);
    auto filled_val = types::fill_plonk_lookup_table<Endianness, value_type>(val);
    auto _val = types::make_plonk_lookup_table<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_table<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

template<typename Field, typename Endianness>
void test_plonk_lookup_tables(std::size_t col_n, std::size_t op_n, std::size_t t_n) {
    using namespace nil::crypto3::marshalling;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using value_type = nil::crypto3::zk::snark::plonk_lookup_table<Field>;
    using value_marshalling_type = types::plonk_lookup_tables<TTypeBase, value_type>;

    std::vector<value_type> val;
    for( std::size_t i = 0; i < t_n; i++ ){
        std::size_t m = rand()%col_n + 1;
        val.push_back( generate_random_plonk_lookup_table<Field>(m, op_n) );
    }

    auto filled_val = types::fill_plonk_lookup_tables<Endianness, value_type>(val);
    auto _val = types::make_plonk_lookup_tables<Endianness, value_type>(filled_val);
    BOOST_CHECK(val == _val);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);

    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());
    value_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_plonk_lookup_tables<Endianness, value_type>(test_val_read);
    BOOST_CHECK(val == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(plonk_constraint_system_details)
    using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
    using field_type = typename curve_type::scalar_field_type;
    using endianness = nil::marshalling::option::big_endian;

    BOOST_AUTO_TEST_CASE(marshalling_plonk_variable) {
        for (auto i = 0; i < 100; i++) {
            test_plonk_variable<field_type, endianness>();
        }
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_variables) {
        test_plonk_variables<field_type, endianness>(50);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_term) {
        test_plonk_term<field_type, endianness>(50);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_expression) {
        test_expression<field_type, endianness>(20, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_constraint) {
        test_plonk_constraint<field_type, endianness>(20, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_constraints) {
        test_plonk_constraints<field_type, endianness>(20, 5, 20);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_gate) {
        test_plonk_gate<field_type, endianness>(20, 5, 20);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_gates) {
        test_plonk_gates<field_type, endianness>(20, 5, 20, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_constraint) {
        test_plonk_lookup_constraint<field_type, endianness>(20, 5, 10);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_constraints) {
        test_plonk_lookup_constraints<field_type, endianness>(20, 5, 10, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_gate) {
        test_plonk_lookup_gate<field_type, endianness>(20, 5, 10, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_gates) {
        test_plonk_lookup_gates<field_type, endianness>(20, 5, 10, 5, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_table) {
        test_plonk_lookup_table<field_type, endianness>(3, 5);
    }

    BOOST_AUTO_TEST_CASE(marshalling_plonk_lookup_tables) {
        test_plonk_lookup_tables<field_type, endianness>(3, 5, 5);
    }
BOOST_AUTO_TEST_SUITE_END()
