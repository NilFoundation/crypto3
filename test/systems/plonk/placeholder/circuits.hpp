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

#ifndef CRYPTO3_ZK_TEST_PLONK_CIRCUITS_HPP
#define CRYPTO3_ZK_TEST_PLONK_CIRCUITS_HPP

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
                template<typename FieldType, typename ParamsType, std::size_t rows_log, std::size_t permutation_size>
                class circuit_description {
                    typedef zk::snark::detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_input_columns;

                public:
                    const std::size_t table_rows = 1 << rows_log;

                    std::shared_ptr<math::evaluation_domain<FieldType>> domain;

                    typename FieldType::value_type omega;
                    typename FieldType::value_type delta;

                    typename policy_type::variable_assignment_type table;

                    std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates;
                    std::vector<plonk_copy_constraint<FieldType>> copy_constraints;
                    std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates;

                    plonk_lookup_table<FieldType> lookup_table;

                    circuit_description()
                        : domain(math::make_evaluation_domain<FieldType>(table_rows))
                        , omega(domain->get_domain_element(1))
                        , delta(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator) {
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
                constexpr static const std::size_t witness_columns_1 = 3;
                constexpr static const std::size_t public_columns_1 = 1;
                constexpr static const std::size_t constant_columns_1 = 0;
                constexpr static const std::size_t selector_columns_1 = 2;

                using arithmetization_params_1 = plonk_arithmetization_params<witness_columns_1,
                    public_columns_1, constant_columns_1, selector_columns_1>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_1>, 4, 4> circuit_test_1() {
                    using assignment_type  = typename FieldType::value_type;

                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 4;

                    constexpr static const std::size_t witness_columns = witness_columns_1;
                    constexpr static const std::size_t public_columns = public_columns_1;
                    constexpr static const std::size_t constant_columns = constant_columns_1;
                    constexpr static const std::size_t selector_columns = selector_columns_1;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_1> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.table_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.table_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // init values
                    typename FieldType::value_type one = FieldType::value_type::one();
                    table[0][0] = algebra::random_element<FieldType>();
                    table[1][0] = algebra::random_element<FieldType>();
                    table[2][0] = algebra::random_element<FieldType>();
//                    table[3][0] = algebra::random_element<FieldType>();
                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < test_circuit.table_rows - 5; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] + table[1][i];
//                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = one;
                        q_mul[i] = FieldType::value_type::zero();

                        plonk_variable<assignment_type> x(1, i, false, 
                            plonk_variable<assignment_type>::column_type::witness);
                        plonk_variable<assignment_type> y(2, i - 1, false, 
                            plonk_variable<assignment_type>::column_type::witness);
                        //test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = test_circuit.table_rows - 5; i < test_circuit.table_rows - 3; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] * table[1][i];
//                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = one;

                        plonk_variable<assignment_type> x(1, i, false, 
                            plonk_variable<assignment_type>::column_type::witness);
                        plonk_variable<assignment_type> y(0, 0, false, 
                            plonk_variable<assignment_type>::column_type::public_input);
                        //test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x, y));
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

                    for (std::size_t i = 0; i < public_columns; i++) {
                        public_input_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_1>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_1>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_1>(
                            public_input_assignment, constant_assignment, selectors_assignment));

//                    test_circuit.init();

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

                using arithmetization_params_t = plonk_arithmetization_params<witness_columns_t,
                    public_columns_t, constant_columns_t, selector_columns_t>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_t>, 4, 4> 
                circuit_test_t(typename FieldType::value_type pi0 = FieldType::value_type::zero()) {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 4;

                    constexpr static const std::size_t witness_columns = witness_columns_t;
                    constexpr static const std::size_t public_columns = public_columns_t;
                    constexpr static const std::size_t constant_columns = constant_columns_t;
                    constexpr static const std::size_t selector_columns = selector_columns_t;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_t> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.table_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.table_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // init values
                    typename FieldType::value_type one = FieldType::value_type::one();
                    table[0][0] = algebra::random_element<FieldType>();
                    table[1][0] = algebra::random_element<FieldType>();
                    table[2][0] = algebra::random_element<FieldType>();
                    table[3][0] = pi0;
                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < test_circuit.table_rows - 5; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
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
                    for (std::size_t i = test_circuit.table_rows - 5; i < test_circuit.table_rows - 3; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
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

                using arithmetization_params_3 = plonk_arithmetization_params<witness_columns_3,
                    public_columns_3, constant_columns_3, selector_columns_3>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_3>, 3, 3> circuit_test_3() {
                    using assignment_type = typename FieldType::value_type;
                    using field_type = typename FieldType::value_type;

                    constexpr static const std::size_t rows_log = 3;
                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_3;
                    constexpr static const std::size_t public_columns = public_columns_3;
                    constexpr static const std::size_t constant_columns = constant_columns_3;
                    constexpr static const std::size_t selector_columns = selector_columns_3;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_3> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    table[0] = {1, 0, 0, 0, 0, 0, 0, 0}; // Witness 1
                    table[1] = {0, 0, 0, 0, 0, 0, 0, 0};
                    table[2] = {0, 0, 0, 0, 0, 0, 0, 0};

                    table[3] = {0, 1,  0, 1, 0, 0, 0, 0};  //Lookup values
                    table[4] = {0, 0,  1, 0, 0, 0, 0, 0}; //Lookup values
                    table[5] = {0, 1,  0, 0, 0, 0, 0, 0}; //Lookup values

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    std::vector<typename FieldType::value_type> sel_lookup(test_circuit.table_rows);
                    sel_lookup[0] = one;
                    sel_lookup[1] = zero;
                    sel_lookup[2] = zero;
                    sel_lookup[3] = zero;
                    selectors_assignment[0] = sel_lookup;

                    std::vector<typename FieldType::value_type> sel_lookup_table(test_circuit.table_rows);
                    sel_lookup_table[0] = zero;
                    sel_lookup_table[1] = one;
                    sel_lookup_table[2] = one;
                    sel_lookup_table[3] = one;
                    selectors_assignment[1] = sel_lookup_table;

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_3>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_3>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_3>(
                            public_input_assignment, constant_assignment, selectors_assignment));

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

                    test_circuit.lookup_table.tag_index = 1;
                    test_circuit.lookup_table.lookup_columns = {c0, c1, c2};
                    return test_circuit;
                }

                // Binary multiplication. 
                //      b_i -- random binaries, 
                //      r_i ordinary random numbers.
                // One gate: w1*w2 - w3 = 0
                // -------------------------------------------------------------------
                // | Selector Gate| Selector Lookup| W1 | W2 |   W3   |  Lookup_tag | L1 | L2 | L3 |
                // -------------------------------------------------------------------
                // |      1       |       1        | b1 | b2 |  b1*b2 |      0      | 0 |  0 |  0 | -- reserved for unselected rows
                // |      1       |       1        | b3 | b4 |  b3*b4 |      1      | 0 |  0 |  0 |
                // |      1       |       0        | r1 | r2 |  r1*r2 |      1      | 0 |  1 |  0 | -- unselected for lookups
                // |      1       |       1        | b5 | b6 |  b5*b6 |      1      | 1 |  0 |  0 |
                // |      1       |       1        | b7 | b8 |  b7*b8 |      1      | 1 |  1 |  1 |
                // -------------------------------------------------------------------

                constexpr static const std::size_t witness_columns_4= 3;
                constexpr static const std::size_t public_columns_4 = 0;
                constexpr static const std::size_t constant_columns_4 = 3;
                constexpr static const std::size_t selector_columns_4 = 3;

                using arithmetization_params_4 = plonk_arithmetization_params<witness_columns_4,
                    public_columns_4, constant_columns_4, selector_columns_4>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType,
                    arithmetization_params_4>, 3, 3> circuit_test_4() {
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
                    table[0][0] = rand() % 2 ? one : zero;
                    table[1][0] = rand() % 2 ? one : zero;
                    table[2][0] = table[0][0] * table[1][0];

                    table[0][1] = rand() % 2 ? one : zero;
                    table[1][1] = rand() % 2 ? one : zero;
                    table[2][1] = table[0][1] * table[1][1];

                    table[0][2] = rand();
                    table[1][2] = rand();
                    table[2][2] = table[0][2] * table[1][2];

                    table[0][3] = rand() % 2 ? one : zero;
                    table[1][3] = rand() % 2 ? one : zero;
                    table[2][3] = table[0][3] * table[1][3];

                    table[0][4] = rand() % 2 ? one : zero;
                    table[1][4] = rand() % 2 ? one : zero;
                    table[2][4] = table[0][4] * table[1][4];
                    
                    //lookup values
                    // Reserved zero row for unselected lookup input rows                    
                    table[3][0] = zero;
                    table[4][0] = zero;
                    table[5][0] = zero;

                    table[3][1] = zero;
                    table[4][1] = one;
                    table[5][1] = zero;


                    table[3][2] = one;
                    table[4][2] = zero;
                    table[5][2] = zero;

                    table[3][3] = one;
                    table[4][3] = one;
                    table[5][3] = one;

                    table[3][4] = zero;
                    table[4][4] = zero;
                    table[5][4] = zero;

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    std::vector<typename FieldType::value_type> sel_lookup(test_circuit.table_rows);
                    sel_lookup[0] = one;
                    sel_lookup[1] = one;
                    sel_lookup[2] = zero;
                    sel_lookup[3] = one;
                    sel_lookup[4] = one;
                    selectors_assignment[0] = sel_lookup;

                    std::vector<typename FieldType::value_type> sel_gate0(test_circuit.table_rows);
                    sel_gate0[0] = one;
                    sel_gate0[1] = one;
                    sel_gate0[2] = one;
                    sel_gate0[3] = one;
                    sel_gate0[4] = one;
                    selectors_assignment[1] = sel_gate0;

                    std::vector<typename FieldType::value_type> sel_lookup_table(test_circuit.table_rows);
                    sel_lookup_table[0] = zero;
                    sel_lookup_table[1] = one;
                    sel_lookup_table[2] = one;
                    sel_lookup_table[3] = one;
                    sel_lookup_table[4] = one;
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
                    lookup_constraint.table_id = 1;
                    lookup_constraint.lookup_input.push_back(w0);
                    lookup_constraint.lookup_input.push_back(w1);
                    lookup_constraint.lookup_input.push_back(w2);

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint};
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(0, lookup_constraints);
//                    test_circuit.lookup_gates.push_back(lookup_gate);

                    plonk_lookup_table<FieldType> lookup_table({c0, c1, c2}, 2);
                    test_circuit.lookup_table = lookup_table;

                    return test_circuit;
                }


                // Lookup complex test
                // 1. Lookup gate with 4 constraints
                //      1.1 w1 \in table 1
                //      1.2 w3 \in table1
                //      1.3 w1 \in table 2
                //      1.4 w1, w2, w3 \in table 3
                // 2. Lookup gate with 2 constraints
                //      2.1 w2 \in table 1
                //      2.2 w2 \in table 2
                // ---------------------------------------------------------------------------
                // |  Table tag 0 | Table tag 1 | W1 | W2 |  W3  | Lookup tag | L1 | L2 | L3 |
                // ---------------------------------------------------------------------------
                // |     1        |    1        | 1  |  2 |  123 |   0        |  0 |  0 |  0 | 
                // |     2        |    1        | 124|  2 | 3    |   1        |  1 |  0 |  0 |
                // |     1        |    1        | 3  |  4 |  125 |   1        |  2 |  0 |  0 |
                // |     2        |    1        | 127|  4 |  5   |   1        |  3 |  0 |  0 |
                // |     1        |    2        | 5  |  6 |  128 |   1        |  4 |  0 |  0 |
                // |     3        |    2        | 6  |  7 |  129 |   1        |  5 |  0 |  0 |
                // |     3        |    2        | 7  |  8 |  130 |   2        |  6 |  0 |  0 |
                // |     3        |    2        | 8  |  9 |  131 |   2        |  7 |  0 |  0 |
                // |     3        |    2        | 9  | 10 |  132 |   2        |  8 |  0 |  0 |
                // |     4        |    0        | 0  |  0 |   1  |   2        |  9 |  0 |  0 |
                // |     4        |    0        | 0  |  1 |   0  |   2        |  10|  0 |  0 |
                // |     4        |    0        | 1  |  0 |   0  |   3        |  0 |  0 |  1 |
                // |     4        |    0        | 1  |  1 |   1  |   3        |  1 |  0 |  0 |
                // |     0        |    0        | 0  |  0 |   128|   3        |  0 |  1 |  0 |
                // |     0        |    0        | 0  |  0 |   129|   3        |  1 |  1 |  1 |
                // |     0        |    0        | 0  |  0 |   130|   0        |  0 |  0 |  0 |
                ///---------------------------------------------------------------------------
                constexpr static const std::size_t witness_columns_5= 3;
                constexpr static const std::size_t public_columns_5 = 0;
                constexpr static const std::size_t constant_columns_5 = 3;
                constexpr static const std::size_t selector_columns_5 = 3;

                using arithmetization_params_5 = plonk_arithmetization_params<witness_columns_5,
                    public_columns_5, constant_columns_5, selector_columns_5>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType,
                    arithmetization_params_5>, 4, 3> circuit_test_5() {
                    using assignment_type = typename FieldType::value_type;
                    
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_5;
                    constexpr static const std::size_t public_columns = public_columns_5;
                    constexpr static const std::size_t constant_columns = constant_columns_5;
                    constexpr static const std::size_t selector_columns = selector_columns_5;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns + selector_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_5> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();

                    // Witness
                    table[0] = {  1, 124,   3, 127,   5,   6,   7,   8,  9, 0,  0, 1, 1, 131, 133, 135}; // W0
                    table[1] = {  2,   2,   4,   4,   6,   7,   8,   9, 10, 0,  1, 0, 1, 132, 134, 136}; // W1
                    table[2] = {123,   3, 125,   5, 129, 130, 131, 132, 10, 1,  0, 0, 0, 128, 129, 130}; // W2

                    // Tags
                    table[3] = {  0,   1,   1,   1,   1,   1,   2,   2,  2, 2,  2, 3, 3,   3,   3,   0}; // Lookup table tag
                    table[4] = {  1,   2,   1,   2,   1,   3,   3,   3,  3, 4,  4, 4, 4,   0,   0, 136}; // Lookup tag1
                    table[5] = {  1,   1,   1,   1,   2,   2,   2,   2,  2, 0,  0, 0, 0,   0,   0, 130}; // Lookup tag2

                    // Lookups
                    table[6] = {  0,   1,   2,   3,   4,   5,   6,   7,  8, 9, 10, 0, 0,   1,   1,   0}; // L1
                    table[7] = {  0,   0,   0,   0,   0,   0,   0,   0,  0, 0,  0, 0, 1,   0,   1, 136}; // L2
                    table[8] = {  0,   0,   0,   0,   0,   0,   0,   0,  0, 0,  0, 1, 0,   0,   0, 130}; // L3
                                       
                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }


                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    for (std::size_t i = 0; i < selector_columns; i++) {
                        selectors_assignment[i] = table[witness_columns + i];
                    }

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + selector_columns + i];
                    }

                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_5>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_5>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_5>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    plonk_variable<assignment_type> w0(0, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);

                    plonk_variable<assignment_type> l0(0, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> l1(1, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> l2(2, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints0(4);
                    lookup_constraints0[0].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w0));
                    lookup_constraints0[0].table_id = 1;
                    lookup_constraints0[1].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w2));
                    lookup_constraints0[1].table_id = 1;
                    lookup_constraints0[2].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w1));
                    lookup_constraints0[2].table_id = 2;
                    lookup_constraints0[3].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w0));
                    lookup_constraints0[3].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w1));
                    lookup_constraints0[3].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w2));
                    lookup_constraints0[3].table_id = 3;
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate0(1, lookup_constraints0);

                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints1(2);
                    lookup_constraints1[0].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w1));
                    lookup_constraints1[0].table_id = 1;                    
                    lookup_constraints1[1].lookup_input.push_back(typename plonk_constraint<FieldType>::term_type(w1));
                    lookup_constraints1[1].table_id = 2;                    
                    plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate1(2, lookup_constraints1);

                    test_circuit.lookup_gates.push_back(lookup_gate0);
                    test_circuit.lookup_gates.push_back(lookup_gate1);

                    plonk_lookup_table<FieldType> lookup_table({l0, l1, l2}, 0);
                    test_circuit.lookup_table = lookup_table;

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

                template<typename FieldType, std::size_t rows_log>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_fib>, rows_log, 2> 
                circuit_test_fib() {
                    using assignment_type = typename FieldType::value_type;

                    constexpr static const std::size_t permutation = 2;

                    constexpr static const std::size_t witness_columns = witness_columns_fib;
                    constexpr static const std::size_t public_columns = public_columns_fib;
                    constexpr static const std::size_t constant_columns = constant_columns_fib;
                    constexpr static const std::size_t selector_columns = selector_columns_fib;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + selector_columns;

                    typedef placeholder_circuit_params<FieldType, arithmetization_params_fib> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;
                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.table_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.table_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
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
                    table[2][0] = one;

                    plonk_variable<FieldType> x0(0, 0, false, plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> x1(0, 1, false, plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> p0(1, 0, false, plonk_variable<FieldType>::column_type::public_input);
                    plonk_variable<FieldType> p1(1, 1, false, plonk_variable<FieldType>::column_type::public_input);

//                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x0, p0));
//                    test_circuit.copy_constraints.push_back(plonk_copy_constraint<FieldType>(x1, p1));

                    for (std::size_t i = 2; i < test_circuit.table_rows - 1; i++) {
                        table[0][i] = table[0][i-2] + table[0][i-1];
                        table[1][i] = zero;
                        table[2][i] = one;
                    }
                    table[2][test_circuit.table_rows - 4] = zero;
                    table[2][test_circuit.table_rows - 3] = zero;
                    table[2][test_circuit.table_rows - 2] = zero;
                    table[2][test_circuit.table_rows - 1] = zero;

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
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TEST_PLONK_CIRCUITS_HPP
