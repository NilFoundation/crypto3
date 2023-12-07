//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef MARSHALLING_ZK_TEST_PLONK_CIRCUITS_HPP
#define MARSHALLING_ZK_TEST_PLONK_CIRCUITS_HPP

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/math/permutation.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType, std::size_t usable_rows_amount, std::size_t permutation_size>
                class circuit_description {
                    typedef zk::snark::detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_input_columns;

                public:
                    std::size_t table_rows;
                    std::size_t usable_rows = usable_rows_amount;

                    typename policy_type::variable_assignment_type table;

                    std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates;
                    std::vector<plonk_copy_constraint<FieldType>> copy_constraints;
                    std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates;

                    std::vector<plonk_lookup_table<FieldType>> lookup_tables;

                    circuit_description() : table_rows(0){
                    }
                };

                //---------------------------------------------------------------------------//
                // Test circuit 1 -- gate argument without rotations
                //  i  | GATE | w_0 | w_1 | w_2 | q_add | q_mul |
                //  0  |  --  |  x  |  y  |  z  |   0   |   0   |
                //  1  | ADD  |  x  |  y  |  z  |   1   |   0   |
                // ... | ADD  |  x  |  y  |  z  |   1   |   0   |
                // k-2 | MUL  |  x  |  y  |  z  |   0   |   1   |
                // k-1 | MUL  |  x  |  y  |  z  |   0   |   1   |
                //
                // ADD: x + y = z
                // MUL: x * y = z
                //---------------------------------------------------------------------------//
                const std::size_t witness_columns_1 = 3;
                const std::size_t public_columns_1 = 1;
                const std::size_t constant_columns_1 = 0;
                const std::size_t selector_columns_1 = 2;
                const std::size_t rows_amount_1 = 13;

                using arithmetization_params_1 = plonk_arithmetization_params<witness_columns_1,
                    public_columns_1, constant_columns_1, selector_columns_1>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_1>, rows_amount_1, 4> circuit_test_1(
                    typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>(),
                    boost::random::mt11213b rnd = boost::random::mt11213b()
                ) {
                    using assignment_type  = typename FieldType::value_type;

                    constexpr static const std::size_t usable_rows = 13;
                    constexpr static const std::size_t permutation = 4;

                    constexpr static const std::size_t witness_columns = witness_columns_1;
                    constexpr static const std::size_t public_columns = public_columns_1;
                    constexpr static const std::size_t constant_columns = constant_columns_1;
                    constexpr static const std::size_t selector_columns = selector_columns_1;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_1> circuit_params;
                    circuit_description<FieldType, circuit_params, usable_rows, permutation> test_circuit;
                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.usable_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.usable_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }

                    // init values
                    typename FieldType::value_type one = FieldType::value_type::one();
                    table[0][0] = alg_rnd();
                    table[1][0] = alg_rnd();
                    table[2][0] = alg_rnd();
                    table[3][0] = table[2][0];
                    plonk_variable<assignment_type> x(2, 0, false,
                        plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> y(0, 0, false,
                        plonk_variable<assignment_type>::column_type::public_input);
                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));

                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < test_circuit.usable_rows - 5; i++) {
                        table[0][i] = alg_rnd();
                        table[1][i] = alg_rnd();
                        table[2][i] = table[0][i] + table[1][i];
                        table[3][i] = table[3][0];
                        q_add[i] = one;
                        q_mul[i] = FieldType::value_type::zero();
                        plonk_variable<assignment_type> x(0, i, false,
                            plonk_variable<assignment_type>::column_type::public_input);
                        plonk_variable<assignment_type> y(0, 0, false,
                            plonk_variable<assignment_type>::column_type::public_input);
                        test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = test_circuit.table_rows - 5; i < test_circuit.table_rows; i++) {
                        table[0][i] = alg_rnd();
                        table[1][i] = alg_rnd();
                        table[2][i] = table[0][i] * table[1][i];
                        table[3][i] = table[2][i];
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = one;

                        plonk_variable<assignment_type> x(2, i, false,
                            plonk_variable<assignment_type>::column_type::witness);
                        plonk_variable<assignment_type> y(0, i, false,
                            plonk_variable<assignment_type>::column_type::public_input);
                        test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
                    }

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment;
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment = {};

                    selectors_assignment[0] = q_add;
                    selectors_assignment[1] = q_mul;

                    public_input_assignment[0] = table[3];
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_1>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_1>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_1>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    test_circuit.table_rows = zk_padding<FieldType, arithmetization_params_1, plonk_column<FieldType>>(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(0, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true, plonk_variable<assignment_type>::column_type::witness);

                    plonk_constraint<FieldType> add_constraint;
                    add_constraint += w0;
                    add_constraint += w1;
                    add_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> add_gate(0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_constraint<FieldType> mul_constraint;
                    typename plonk_constraint<FieldType>::term_type w0_term(w0);
                    typename plonk_constraint<FieldType>::term_type w1_term(w1);
                    mul_constraint += w0_term * w1_term;
                    mul_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> mul_gate(1, mul_gate_costraints);
                    test_circuit.gates.push_back(mul_gate);

                    return test_circuit;
                }

                //---------------------------------------------------------------------------//
                // Test circuit 2 (with rotations)
                //  i  | GATE | w_0 | w_1 | w_2 | public | q_add | q_mul |
                //  0  |  --  |  x  |  y  |  z  |   p1   |   0   |   0   |
                //  1  | ADD  |  x  |  y  |  z  |   0    |   1   |   0   |
                // ... | ADD  |  x  |  y  |  z  |   0    |   1   |   0   |
                // k-2 | MUL  |  x  |  y  |  z  |   0    |   0   |   1   |
                // k-1 | MUL  |  x  |  y  |  z  |   0    |   0   |   1   |
                //
                // ADD: x + y = z, copy(prev(z), y)
                // MUL: x * y + prev(x) = z, copy(p1, y)
                //---------------------------------------------------------------------------//
                constexpr static const std::size_t witness_columns_t = 3;
                constexpr static const std::size_t public_columns_t = 1;
                constexpr static const std::size_t constant_columns_t = 0;
                constexpr static const std::size_t selector_columns_t = 2;
                constexpr static const std::size_t usable_rows_t = 5;

                using arithmetization_params_t = plonk_arithmetization_params<witness_columns_t,
                    public_columns_t, constant_columns_t, selector_columns_t>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_t>, 5, 4>
                circuit_test_t(
                    typename FieldType::value_type pi0,// = 0,
                    typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd, //= nil::crypto3::random::algebraic_engine<FieldType>(),
                    boost::random::mt11213b rnd// = boost::random::mt11213b()
                ) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = 4;
                    constexpr static const std::size_t witness_columns = witness_columns_t;
                    constexpr static const std::size_t public_columns = public_columns_t;
                    constexpr static const std::size_t constant_columns = constant_columns_t;
                    constexpr static const std::size_t selector_columns = selector_columns_t;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_t> circuit_params;

                    circuit_description<FieldType, circuit_params, 5, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.usable_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.usable_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }

                    // init values
                    typename FieldType::value_type one = FieldType::value_type::one();
                    table[0][0] = alg_rnd();
                    table[1][0] = alg_rnd();
                    table[2][0] = alg_rnd();
                    table[3][0] = pi0;
                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < 3; i++) {
                        table[0][i] = alg_rnd();
                        table[1][i] = table[2][i - 1];
                        table[2][i] = table[0][i] + table[1][i];
                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = one;
                        q_mul[i] = FieldType::value_type::zero();

                        plonk_variable<assignment_type> x(1, i, false,
                            plonk_variable<assignment_type>::column_type::witness);
                        plonk_variable<assignment_type> y(2, i - 1, false,
                            plonk_variable<assignment_type>::column_type::witness);
                        test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = 3; i < 5; i++) {
                        table[0][i] = alg_rnd();
                        table[1][i] = table[3][0];
                        table[2][i] = table[0][i] * table[1][i] + table[0][i - 1];
                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = one;

                        plonk_variable<assignment_type> x(1, i, false,
                            plonk_variable<assignment_type>::column_type::witness);
                        plonk_variable<assignment_type> y(0, 0, false,
                            plonk_variable<assignment_type>::column_type::public_input);
                        test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
                    }
                    table[3][1] = FieldType::value_type::zero();
                    table[3][2] = FieldType::value_type::one();

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment;
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment = {};

                    selectors_assignment[0] = q_add;
                    selectors_assignment[1] = q_mul;

                    for (std::size_t i = 0; i < public_columns; i++) {
                        public_input_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_t>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_t>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_t>(
                            public_input_assignment, constant_assignment, selectors_assignment));
                    test_circuit.table_rows = zk_padding<FieldType, arithmetization_params_t, plonk_column<FieldType>>(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(0, 0, true,
                                                 plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true,
                                                 plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true,
                                                 plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0_prev(0, -1, true,
                                                 plonk_variable<assignment_type>::column_type::witness);

                    plonk_constraint<FieldType> add_constraint;
                    add_constraint += w0;
                    add_constraint += w1;
                    add_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> add_gate(0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_constraint<FieldType> mul_constraint;
                    typename plonk_constraint<FieldType>::term_type w0_term(w0);
                    typename plonk_constraint<FieldType>::term_type w1_term(w1);
                    mul_constraint += w0_term * w1_term;
                    mul_constraint -= w2;
                    mul_constraint += w0_prev;

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> mul_gate(1, mul_gate_costraints);
                    test_circuit.gates.push_back(mul_gate);

                    return test_circuit;
                }


                constexpr static const std::size_t witness_columns_3 = 3;
                constexpr static const std::size_t public_columns_3 = 0;
                constexpr static const std::size_t constant_columns_3 = 3;
                constexpr static const std::size_t selector_columns_3 = 2;
                constexpr static const std::size_t usable_rows_3 = 4;
                constexpr static const std::size_t permutation_size_3 = 3;

                using arithmetization_params_3 = plonk_arithmetization_params<witness_columns_3,
                    public_columns_3, constant_columns_3, selector_columns_3>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_3>, usable_rows_3, permutation_size_3> circuit_test_3(
                    typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>(),
                    boost::random::mt11213b rnd = boost::random::mt11213b()
                ) {
                    using assignment_type = typename FieldType::value_type;
                    using field_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = permutation_size_3;
                    constexpr static const std::size_t witness_columns = witness_columns_3;
                    constexpr static const std::size_t public_columns = public_columns_3;
                    constexpr static const std::size_t constant_columns = constant_columns_3;
                    constexpr static const std::size_t selector_columns = selector_columns_3;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns;
                    constexpr static const std::size_t usable_rows = usable_rows_3;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_3> circuit_params;

                    circuit_description<FieldType, circuit_params, usable_rows, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    table[0] = {1, 3, 0, 0}; // Witness 1
                    table[1] = {0, 0, 0, 0};
                    table[2] = {0, 0, 0, 3};

                    plonk_variable<assignment_type> x(0, 1, false,
                        plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> y(2, 3, false,
                        plonk_variable<assignment_type>::column_type::witness);
                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));


                    table[3] = {0, 1,  0, 1};  //Lookup values
                    table[4] = {0, 0,  1, 0}; //Lookup values
                    table[5] = {0, 1,  0, 0}; //Lookup values

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    std::vector<typename FieldType::value_type> sel_lookup(test_circuit.table_rows);
                    sel_lookup = {1, 0, 0, 0};
                    selectors_assignment[0] = sel_lookup;

                    std::vector<typename FieldType::value_type> sel_lookup_table(test_circuit.table_rows);
                    sel_lookup_table = {0, 1, 1, 1};
                    selectors_assignment[1] = sel_lookup_table;

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_3>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_3>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_3>(
                            public_input_assignment, constant_assignment, selectors_assignment));
                    test_circuit.table_rows = zk_padding(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(0, 0, true,  plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true,  plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true,  plonk_variable<assignment_type>::column_type::witness);

                    plonk_variable<assignment_type> c0(0, 0, true,  plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c1(1, 0, true,  plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c2(2, 0, true,  plonk_variable<assignment_type>::column_type::constant);


                    plonk_lookup_constraint<FieldType> lookup_constraint;
                    lookup_constraint.lookup_input.push_back(w0);
                    lookup_constraint.lookup_input.push_back(w1);
                    lookup_constraint.lookup_input.push_back(w2);
                    lookup_constraint.table_id = 1;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(0, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);

                    // Add constructor for lookup table
                    plonk_lookup_table<FieldType> table1(3, 1); // 1 -- selector_id, 3 -- number of columns;
                    table1.append_option({c0, c1, c2});

                    test_circuit.lookup_tables.push_back(table1);
                    return test_circuit;
                }

                // Binary multiplication.
                //      b_i -- random binaries,
                //      r_i ordinary random numbers.
                // One gate: w1*w2 - w3 = 0
                // ----------------------------------------------------------------------------------
                // | Selector Gate| Selector Lookup| W1 | W2 |   W3   |  Lookup_tag | L1 | L2 | L3 |
                // -------------------------------------------------------------------
                // |      1       |       1        | b1 | b2 |  b1*b2 |      0      | 0  |  0 |  0 | -- reserved for unselected rows
                // |      1       |       1        | b3 | b4 |  b3*b4 |      1      | 0  |  0 |  0 |
                // |      1       |       0        | r1 | r2 |  r1*r2 |      1      | 0  |  1 |  0 | -- unselected for lookups
                // |      1       |       1        | b5 | b6 |  b5*b6 |      1      | 1  |  0 |  0 |
                // |      1       |       1        | b7 | b8 |  b7*b8 |      1      | 1  |  1 |  1 |
                // ----------------------------------------------------------------------------------

                constexpr static const std::size_t witness_columns_4= 3;
                constexpr static const std::size_t public_columns_4 = 0;
                constexpr static const std::size_t constant_columns_4 = 3;
                constexpr static const std::size_t selector_columns_4 = 3;

                using arithmetization_params_4 = plonk_arithmetization_params<witness_columns_4,
                    public_columns_4, constant_columns_4, selector_columns_4>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType,
                    arithmetization_params_4>, 3, 3> circuit_test_4(
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>(),
                        boost::random::mt11213b rnd = boost::random::mt11213b()
                    ) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t rows_log = 3;
                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_4;
                    constexpr static const std::size_t public_columns = public_columns_4;
                    constexpr static const std::size_t constant_columns = constant_columns_4;
                    constexpr static const std::size_t selector_columns = selector_columns_4;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_4> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    table[0] = {rnd() % 2, rnd() % 2, rnd(), rnd() % 2, rnd() % 2, 0, 0, 0};
                    table[1] = {rnd() % 2, rnd() % 2, rnd(), rnd() % 2, rnd() % 2, 0, 0, 0};;
                    table[2] = {table[0][0] * table[1][0], table[0][1] * table[1][1], table[0][2] * table[1][2], table[0][3] * table[1][3], table[0][4] * table[1][4], 0, 0, 0};


                    //lookup values
                    // Reserved zero row for unselected lookup input rows
                    table[3] = {0, 0, 0, 1, 1, 0, 0, 0};
                    table[4] = {0, 0, 1, 0, 1, 0, 0, 0};
                    table[5] = {0, 0, 0, 0, 1, 0, 0, 0};

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    std::vector<typename FieldType::value_type> sel_lookup(test_circuit.table_rows);
                    sel_lookup ={1, 1, 0, 1, 1, 0, 0, 0};
                    selectors_assignment[0] = sel_lookup;

                    std::vector<typename FieldType::value_type> sel_gate0(test_circuit.table_rows);
                    sel_gate0 = {1, 1, 1, 1, 1, 0, 0, 0};
                    selectors_assignment[1] = sel_gate0;


                    std::vector<typename FieldType::value_type> sel_lookup_table(test_circuit.table_rows);
                    sel_lookup_table = {0, 1, 1, 1, 1, 0, 0, 0};
                    selectors_assignment[2] = sel_lookup_table;

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_4>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_4>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_4>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    plonk_variable<assignment_type> w0(0, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true, plonk_variable<assignment_type>::column_type::witness);

                    plonk_variable<assignment_type> c0(0, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c1(1, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c2(2, 0, true, plonk_variable<assignment_type>::column_type::constant);

                    plonk_constraint<FieldType> mul_constraint;
                    typename plonk_constraint<FieldType>::term_type w0_term(w0);
                    typename plonk_constraint<FieldType>::term_type w1_term(w1);
                    mul_constraint += w0_term * w1_term;
                    mul_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> mul_gate(1, mul_gate_costraints);
                    test_circuit.gates.push_back(mul_gate);

                    plonk_lookup_constraint<FieldType> lookup_constraint;
                    lookup_constraint.lookup_input.push_back(w0);
                    lookup_constraint.lookup_input.push_back(w1);
                    lookup_constraint.lookup_input.push_back(w2);
                    lookup_constraint.table_id = 1;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(0, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);

                    // Add constructor for lookup table
                    plonk_lookup_table<FieldType> table1(3, 2); // 2 -- selector_id, 3 -- number of columns;
                    table1.append_option({c0, c1, c2});

                    test_circuit.lookup_tables.push_back(table1);
                    return test_circuit;
                }

                //---------------------------------------------------------------------------//
                // Test fibonacci circuit
                //  i  | GATE | w_0     | public | q_add |
                //  0  |  --  |  f(0)   |   a    |   0   |
                //  1  | FIB  |  f(1)   |   b    |   1   |
                // ... | FIB  |         |   0    |   1   |
                // k-2 | FIB  |  f(k-2) |   0    |   0   |
                // k-1 |  --  |  f(k-1) |   0    |   0   |
                //
                // public input is copy constrainted to f(0) and f(1)
                // FIB: w_0(i-1) + w_0(i) == w_0(i+1)
                //---------------------------------------------------------------------------//
                constexpr static const std::size_t witness_columns_fib = 1;
                constexpr static const std::size_t public_columns_fib = 1;
                constexpr static const std::size_t constant_columns_fib = 0;
                constexpr static const std::size_t selector_columns_fib = 1;

                using arithmetization_params_fib = plonk_arithmetization_params<witness_columns_fib,
                    public_columns_fib, constant_columns_fib, selector_columns_fib>;

                template<typename FieldType, std::size_t usable_rows>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_fib>, usable_rows, 2>
                circuit_test_fib(
                    typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>()
                ) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = 2;

                    constexpr static const std::size_t witness_columns = witness_columns_fib;
                    constexpr static const std::size_t public_columns = public_columns_fib;
                    constexpr static const std::size_t constant_columns = constant_columns_fib;
                    constexpr static const std::size_t selector_columns = selector_columns_fib;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + selector_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_fib> circuit_params;

                    circuit_description<FieldType, circuit_params, usable_rows, permutation> test_circuit;
                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.usable_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.usable_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }
                    // init values
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    typename FieldType::value_type one = FieldType::value_type::one();
                    // witness
                    table[0][0] = one;
                    table[0][1] = one;

                    // public input
                    table[1][0] = one;
                    table[1][1] = one;

                    // selector
                    table[2][0] = zero;
                    table[2][1] = one;

                    plonk_variable<FieldType> x0(0, 0, false, plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> x1(0, 1, false, plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> p0(1, 0, false, plonk_variable<FieldType>::column_type::public_input);
                    plonk_variable<FieldType> p1(1, 1, false, plonk_variable<FieldType>::column_type::public_input);

//                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x0, p0));
//                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x1, p1));

                    for (std::size_t i = 2; i < test_circuit.usable_rows - 1; i++) {
                        table[0][i] = table[0][i-2] + table[0][i-1];
                        table[1][i] = zero;
                        table[2][i-1] = one;
                    }

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    private_assignment[0] = table[0];

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment;
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment = {};

                    selectors_assignment[0] = table[2];

                    public_input_assignment[0] = table[1];
                    selectors_assignment[0] = table[2];


                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_fib>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_fib>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_fib>(
                            public_input_assignment, constant_assignment, selectors_assignment));
                    test_circuit.table_rows = zk_padding<FieldType, arithmetization_params_fib, plonk_column<FieldType>>(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(0, -1, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(0, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(0, 1, true, plonk_variable<assignment_type>::column_type::witness);

                    typename plonk_constraint<FieldType>::term_type w0_term(w0);
                    typename plonk_constraint<FieldType>::term_type w1_term(w1);
                    typename plonk_constraint<FieldType>::term_type w2_term(w2);

                    plonk_constraint<FieldType> fib_constraint;
                    fib_constraint += w0_term;
                    fib_constraint += w1_term;
                    fib_constraint -= w2_term;

                    std::vector<plonk_constraint<FieldType>> fib_costraints {fib_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> fib_gate(0, fib_costraints);
                    test_circuit.gates.push_back(fib_gate);

                    return test_circuit;
                }

                // Long range check:
                //      Table 1: Selector LT1 options L1
                //      Table 2: Selector LT1 options L1 || L2 || L3
                // Lookup gate1:
                //      w1 \in Table 1
                //      W2 \in Table 2
                // Lookup gate2:
                //      w1{-1} + w1 \in Table 2
                // ---------------------------------------------------------------------------------
                // |  s1 | s2 | W1 | W2    |  LT1 | L1 | L2 | L3 |
                // ---------------------------------------------------------------------------------
                // |   1 |  0 | r1 | 7     |   0  | 0  |  0 |  0 | -- reserved for unselected rows
                // |   1 |  1 | r2 | r1+r2 |   1  | 2  |  7 | 12 | -- reserved for unselected rows
                // |   1 |  1 | r3 | r2+r3 |   1  | 3  |  8 | 12 |
                // |   1 |  1 | r4 | r3+r4 |   1  | 4  |  9 | 12 | -- unselected for lookups
                // |   1 |  1 | r5 | r4+r5 |   1  | 5  | 10 | 12 |
                // |   1 |  1 | r6 | r5+r6 |   1  | 6  | 11 | 12 |
                // ---------------------------------------------------------------------------------

                constexpr static const std::size_t witness_columns_6= 2;
                constexpr static const std::size_t public_columns_6 = 0;
                constexpr static const std::size_t constant_columns_6 = 3;
                constexpr static const std::size_t selector_columns_6 = 3;
                constexpr static const std::size_t usable_rows_6 = 6;

                using arithmetization_params_6 = plonk_arithmetization_params<witness_columns_6,
                    public_columns_6, constant_columns_6, selector_columns_6>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType,
                    arithmetization_params_6>, usable_rows_6, 3> circuit_test_6(
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>(),
                        boost::random::mt11213b rnd = boost::random::mt11213b()
                    ) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_6;
                    constexpr static const std::size_t public_columns = public_columns_6;
                    constexpr static const std::size_t constant_columns = constant_columns_6;
                    constexpr static const std::size_t selector_columns = selector_columns_6;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns + selector_columns;
                    constexpr static const std::size_t usable_rows = usable_rows_6;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_6> circuit_params;

                    circuit_description<FieldType, circuit_params, usable_rows_6, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    table[0] = {rnd() % 5 + 2, rnd() % 5 + 2, rnd() % 5 + 2, rnd() % 5 + 2, rnd() % 5 + 2, rnd() % 5 + 2};
                    table[1] = {7, table[0][0] + table[0][1],  table[0][1] + table[0][2],  table[0][2] + table[0][3],  table[0][3] + table[0][4],  table[0][4] + table[0][5]};


                    // selectors
                    // Reserved zero row for unselected lookup input rows
                    table[2] = {0, 1, 1, 1, 1, 1}; // LT1
                    table[3] = {1, 1, 1, 1, 1, 1}; // For the first lookup gate
                    table[4] = {0, 1, 1, 1, 1, 1}; // For the second lookup gate

                    // Lookup values
                    table[5] = {0,  2,  3,  4,  5,  6}; // L1
                    table[6] = {0,  7,  8,  9, 10, 11}; // L2
                    table[7] = {0, 12, 12, 12, 12, 12}; // L3

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    selectors_assignment[0] = table[2];
                    selectors_assignment[1] = table[3];
                    selectors_assignment[2] = table[4];

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + selector_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_6>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_6>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_6>(
                            public_input_assignment, constant_assignment, selectors_assignment));
                    test_circuit.table_rows = zk_padding(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(  0, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0_1(0,-1, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(  1, 0, true, plonk_variable<assignment_type>::column_type::witness);

                    plonk_variable<assignment_type> c0(0, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c1(1, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c2(2, 0, true, plonk_variable<assignment_type>::column_type::constant);

                    plonk_lookup_constraint<FieldType> lookup_constraint1;
                    lookup_constraint1.lookup_input.push_back(w0);
                    lookup_constraint1.table_id = 1;

                    plonk_lookup_constraint<FieldType> lookup_constraint2;
                    lookup_constraint2.lookup_input.push_back(w1);
                    lookup_constraint2.table_id = 2;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint1, lookup_constraint2};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(1, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);


                    plonk_lookup_constraint<FieldType> lookup_constraint3;
                    plonk_constraint<FieldType> add_constraint;
                    add_constraint += w0_1;
                    add_constraint += w0;
                    lookup_constraint3.lookup_input.push_back(add_constraint);
                    lookup_constraint3.table_id = 2;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints2 = {lookup_constraint3};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate2(2, lookup_constraints2);
                    test_circuit.lookup_gates.push_back(lookup_gate2);

                    // Add constructor for lookup table
                    plonk_lookup_table<FieldType> table1(1, 0); // 2 -- selector_id, 3 -- number of columns;
                    table1.append_option({c0});
                    test_circuit.lookup_tables.push_back(table1);

                    plonk_lookup_table<FieldType> table2(1, 0); // 2 -- selector_id, 3 -- number of columns;
                    table2.append_option({c0});
                    table2.append_option({c1});
                    table2.append_option({c2});
                    test_circuit.lookup_tables.push_back(table2);

                    return test_circuit;
                }

                // Big columns rotations check:
                //      Table 1: LT1 options: {L1, L2, L3, L4, L5, L6, L7}
                //      Table 2: LT2 options: {L1, L2} || { L3, L4 }
                //      Table 3: LT2 options: {L5} || {L6} || {L7}
                // Lookup gate1:
                //      w1{-3}, w1{-2}, w1{-1}, w1, w1{+1}, w1{+2},w1{+3},   \in Table 1 selector s2
                //      w1, w2                                               \in Table 2 selector s0
                //      w2{-1} * w2                                          \in Table 3 selector s3
                // Gate1
                //      w1{+7} - w1 = 0
                // ----------------------------------------------------------------------------------------
                // |  s0 |  s1 | s2 | s3 | W1 | W2    |  LT1 |  LT2  | L1 | L2 | L3 | L4 | L5 | L6 | L7
                // ----------------------------------------------------------------------------------------
                // |   1 |   1 |  0 |  0 | 1  | 2^w1  |   0  |   0   | 0  |  0 |  0 |  0 |  0 |  0 |  0  -- reserved for unselected rows
                // |   1 |   1 |  0 |  1 | 2  | 2^w1  |   1  |   0   | 1  |  2 |  3 |  4 |  5 |  6 |  7
                // |   1 |   1 |  0 |  1 | 3  | 2^w1  |   1  |   0   | 0  |  2 |  3 |  4 |  5 |  6 |  7
                // |   1 |   1 |  1 |  1 | 4  | 2^w1  |   1  |   0   | 0  |  1 |  3 |  4 |  5 |  6 |  7 -- unselected for lookups
                // |   1 |   1 |  1 |  1 | 5  | 2^w1  |   1  |   0   | 0  |  1 |  2 |  4 |  5 |  6 |  7
                // |   1 |   1 |  1 |  1 | 6  | 2^w1  |   1  |   0   | 0  |  1 |  2 |  3 |  4 |  6 |  7
                // |   1 |   0 |  1 |  1 | 7  | 2^w1  |   1  |   0   | 0  |  1 |  2 |  3 |  4 |  5 |  7
                // |   1 |   0 |  1 |  1 | 0  | 2^w1  |   1  |   0   | 0  |  1 |  2 |  3 |  4 |  5 |  6
                // |   1 |   0 |  1 |  1 | 1  | 2^w1  |   0  |   1   | 0  |  1 |  6 |  64|  1 | 64 |4096
                // |   1 |   0 |  1 |  1 | 2  | 2^w1  |   0  |   1   | 1  |  2 |  7 | 128|  2 |128 |8192
                // |   1 |   0 |  1 |  1 | 3  | 2^w1  |   0  |   1   | 2  |  4 |  7 | 128|  4 |256 |16384
                // |   1 |   0 |  0 |  1 | 4  | 2^w1  |   0  |   1   | 3  |  8 |  7 | 128|  8 |512 |16384
                // |   1 |   0 |  0 |  1 | 5  | 2^w1  |   0  |   1   | 4  | 16 |  7 | 128| 16 |1024|16384
                // |   1 |   0 |  0 |  1 | 6  | 2^w1  |   0  |   1   | 5  | 32 |  7 | 128| 32 |2048|16384
                // ---------------------------------------------------------------------------------
                constexpr static const std::size_t witness_columns_7= 2;
                constexpr static const std::size_t public_columns_7 = 0;
                constexpr static const std::size_t constant_columns_7 = 7;
                constexpr static const std::size_t selector_columns_7 = 6;
                constexpr static const std::size_t usable_rows_7 = 14;

                using arithmetization_params_7 = plonk_arithmetization_params<witness_columns_7,
                    public_columns_7, constant_columns_7, selector_columns_7>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType,
                    arithmetization_params_7>, usable_rows_7, 4> circuit_test_7(
                        typename nil::crypto3::random::algebraic_engine<FieldType> alg_rnd = nil::crypto3::random::algebraic_engine<FieldType>(),
                        boost::random::mt11213b rnd = boost::random::mt11213b()
                    ) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = 4;

                    constexpr static const std::size_t witness_columns = witness_columns_7;
                    constexpr static const std::size_t public_columns = public_columns_7;
                    constexpr static const std::size_t constant_columns = constant_columns_7;
                    constexpr static const std::size_t selector_columns = selector_columns_7;
                    constexpr static const std::size_t table_columns =
                            witness_columns + public_columns + constant_columns + selector_columns;
                    constexpr static const std::size_t usable_rows = usable_rows_7;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_7> circuit_params;

                    circuit_description<FieldType, circuit_params, usable_rows_7, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.usable_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();

                    auto r = rnd() % 7;
                    std::size_t j = 0;
                    for( std::size_t i = 0; i < 7; i++){
                        if( j == r ) j++;
                        table[0][i] = j;
                        table[1][i] = (typename FieldType::value_type(2)).pow(j);
                        j++;
                    }
                    for( std::size_t i = 7; i < 14; i++){
                        table[0][i]=table[0][i-7];
                        table[1][i]=table[1][i-7];
                    }

                    // selectors
                    // Reserved zero row for unselected lookup input rows
                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    selectors_assignment[0] = {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1 }; // Selector for single gate
                    selectors_assignment[1] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 }; // Selector lookup gate with multiple rotations
                    selectors_assignment[2] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }; // Selector for gate w1 = 2^w0
                    selectors_assignment[3] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }; // Selector for gate w1_{-1} * w1 \in Table 3
                    selectors_assignment[4] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1 }; // Selector for lookup tables 2, 3
                    selectors_assignment[5] = {0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0 }; // Selector for lookup table with 7 columns

                    // Lookup values
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;
                    constant_assignment[0] = {0, 1, 0, 0, 0, 0, 0, 0,   0,   1,    2,    3,    4,    5 }; // Lookup tables
                    constant_assignment[1] = {0, 2, 2, 1, 1, 1, 1, 1,   1,   2,    4,    8,   16,   32 }; // Lookup tables
                    constant_assignment[2] = {0, 3, 3, 3, 2, 2, 2, 2,   6,   7,    7,    7,    7,    7 }; // Lookup tables
                    constant_assignment[3] = {0, 4, 4, 4, 4, 3, 3, 3,  64, 128,  128,  128,  128,  128 }; // Lookup tables
                    constant_assignment[4] = {0, 5, 5, 5, 5, 5, 4, 4,   1,   2,    4,    8,   16,   32 }; // Lookup tables
                    constant_assignment[5] = {0, 6, 6, 6, 6, 6, 6, 5,  64, 128,  256,  512, 1024, 2048 }; // Lookup tables
                    constant_assignment[6] = {0, 7, 7, 7, 7, 7, 7, 7,4096,8192,16384,16384,16384,16384 }; // Lookup tables

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};

                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_7>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_7>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_7>(
                            public_input_assignment, constant_assignment, selectors_assignment));
                    test_circuit.table_rows = zk_padding(test_circuit.table, alg_rnd);

                    plonk_variable<assignment_type> w0(  0, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0__7(0,-7, true, plonk_variable<assignment_type>::column_type::witness);

                    plonk_constraint<FieldType> add_constraint;
                    add_constraint += w0;
                    add_constraint -= w0__7;

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> add_gate(0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_variable<assignment_type> w0__3(  0,-3, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0__2(  0,-2, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0__1(  0,-1, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0_1 (  0, 1, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0_2 (  0, 2, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w0_3 (  0, 3, true, plonk_variable<assignment_type>::column_type::witness);


                    plonk_variable<assignment_type> c0   (  0, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c1   (  1, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c2   (  2, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c3   (  3, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c4   (  4, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c5   (  5, 0, true, plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c6   (  6, 0, true, plonk_variable<assignment_type>::column_type::constant);

                    plonk_lookup_constraint<FieldType> lookup_constraint1;
                    lookup_constraint1.lookup_input = {w0__3, w0__2, w0__1, w0, w0_1, w0_2, w0_3};
                    lookup_constraint1.table_id = 1;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint1};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(1, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);

                    plonk_variable<assignment_type> w1(  1, 0, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_lookup_constraint<FieldType> lookup_constraint2;
                    lookup_constraint2.lookup_input = {w0, w1};
                    lookup_constraint2.table_id = 2;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints2 = {lookup_constraint2};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate2(2, lookup_constraints2);
                    test_circuit.lookup_gates.push_back(lookup_gate2);

                    plonk_variable<assignment_type> w1__1(  1, -1, true, plonk_variable<assignment_type>::column_type::witness);
                    plonk_lookup_constraint<FieldType> lookup_constraint3;
                    typename plonk_constraint<FieldType>::term_type w1__1_term(w1__1);
                    typename plonk_constraint<FieldType>::term_type w1_term(w1);
                    lookup_constraint3.lookup_input = {w1__1_term* w1_term};
                    lookup_constraint3.table_id = 3;

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints3 = {lookup_constraint3};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate3(3, lookup_constraints3);
                    test_circuit.lookup_gates.push_back(lookup_gate3);

                    plonk_lookup_table<FieldType> lookup_table(7, 5); // 5 -- selector_id, 7 -- number of columns;
                    lookup_table.append_option({c0, c1, c2, c3, c4, c5, c6});
                    test_circuit.lookup_tables.push_back(lookup_table);

                    plonk_lookup_table<FieldType> lookup_table2(2, 4); // 4 -- selector_id, 2 -- number of columns;
                    lookup_table2.append_option({c0, c1});
                    lookup_table2.append_option({c2, c3});
                    test_circuit.lookup_tables.push_back(lookup_table2);

                    plonk_lookup_table<FieldType> lookup_table3(1, 4); // 4 -- selector_id, 1 -- number of columns;
                    lookup_table3.append_option({c4});
                    lookup_table3.append_option({c5});
                    lookup_table3.append_option({c6});
                    test_circuit.lookup_tables.push_back(lookup_table3);

                    return test_circuit;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil


#endif    // MARSHALLING_ZK_TEST_PLONK_CIRCUITS_HPP
