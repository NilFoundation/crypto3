//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
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
                    using merkle_hash_type = typename ParamsType::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;

                public:
                    const std::size_t table_rows = 1 << rows_log;

                    std::shared_ptr<math::evaluation_domain<FieldType>> domain;

                    typename FieldType::value_type omega;
                    typename FieldType::value_type delta;

                    typename policy_type::variable_assignment_type table;

                    std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates;
                    std::vector<plonk_copy_constraint<FieldType>> copy_constraints;
                    std::vector<plonk_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates;

                    circuit_description() {
                        domain = math::make_evaluation_domain<FieldType>(table_rows);

                        omega = domain->get_domain_element(1);
                        delta = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;
                    }

                    void init() {
                    }
                };

                //---------------------------------------------------------------------------//
                // Test circuit 1
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
                constexpr static const std::size_t public_columns_1 = 0;
                constexpr static const std::size_t constant_columns_1 = 0;
                constexpr static const std::size_t selector_columns_1 = 2;

                using arithmetization_params_1 = plonk_arithmetization_params<witness_columns_1,
                    public_columns_1, constant_columns_1, selector_columns_1>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_params<FieldType, arithmetization_params_1>, 4, 3> circuit_test_1() {
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_1;
                    constexpr static const std::size_t public_columns = public_columns_1;
                    constexpr static const std::size_t constant_columns = constant_columns_1;
                    constexpr static const std::size_t selector_columns = selector_columns_1;
                    constexpr static const std::size_t table_columns = 
                        witness_columns + public_columns + constant_columns;

                    typedef placeholder_params<FieldType, arithmetization_params_1> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;

                    std::vector<typename FieldType::value_type> q_add(test_circuit.table_rows);
                    std::vector<typename FieldType::value_type> q_mul(test_circuit.table_rows);
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // init values
                    table[0][0] = algebra::random_element<FieldType>();
                    table[0][1] = algebra::random_element<FieldType>();
                    table[0][2] = algebra::random_element<FieldType>();
                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < test_circuit.table_rows - 5; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] + table[1][i];
                        q_add[i] = FieldType::value_type::one();
                        q_mul[i] = FieldType::value_type::zero();
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = test_circuit.table_rows - 5; i < test_circuit.table_rows - 3; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] * table[1][i];
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = FieldType::value_type::one();
                    }

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                            private_assignment[i][j] = table[i][j];
                        }
                    }

                    std::vector<plonk_column<FieldType>> selectors_assignment(selector_columns);
                    std::vector<plonk_column<FieldType>> public_input_assignment(public_columns);
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment = {};
                    for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                        selectors_assignment[0][j] = q_add[j];
                        selectors_assignment[1][j] = q_mul[j];
                    }

                    for (std::size_t i = 0; i < public_columns; i++) {
                        for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                            public_input_assignment[i][j] = table[witness_columns + i][j];
                        }
                    }

                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_1>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_1>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_1>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    test_circuit.init();

                    plonk_variable<FieldType> w0(0, 0,
                                                 plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w1(0, 0,
                                                 plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w2(0, 0,
                                                 plonk_variable<FieldType>::column_type::witness);

                    plonk_constraint<FieldType> add_constraint;
                    add_constraint += w0;
                    add_constraint += w1;
                    add_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> add_gate(0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_constraint<FieldType> mul_constraint;
                    add_constraint += w0 * w1;
                    add_constraint -= w2;

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType, plonk_constraint<FieldType>> mul_gate(1, mul_gate_costraints);
                    test_circuit.gates.push_back(mul_gate);

                    return test_circuit;
                }

                //---------------------------------------------------------------------------//
                // Test circuit 2
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
                constexpr static const std::size_t witness_columns_2 = 3;
                constexpr static const std::size_t public_columns_2 = 1;
                constexpr static const std::size_t constant_columns_2 = 0;
                constexpr static const std::size_t selector_columns_2 = 2;

                using arithmetization_params_2 = plonk_arithmetization_params<witness_columns_2,
                    public_columns_2, constant_columns_2, selector_columns_2>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_params<FieldType,
                    arithmetization_params_2>, 4, 4> circuit_test_2() {
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 4;

                    constexpr static const std::size_t witness_columns = witness_columns_2;
                    constexpr static const std::size_t public_columns = public_columns_2;
                    constexpr static const std::size_t constant_columns = constant_columns_2;
                    constexpr static const std::size_t selector_columns = selector_columns_2;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_params<FieldType, arithmetization_params_2> circuit_params;

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
                    table[3][0] = algebra::random_element<FieldType>();
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

                        plonk_variable<FieldType> x(1, i, false, 
                            plonk_variable<FieldType>::column_type::witness);
                        plonk_variable<FieldType> y(2, i - 1, false, 
                            plonk_variable<FieldType>::column_type::witness);
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

                        plonk_variable<FieldType> x(1, i, false, 
                            plonk_variable<FieldType>::column_type::witness);
                        plonk_variable<FieldType> y(0, 0, false, 
                            plonk_variable<FieldType>::column_type::public_input);
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

                    for (std::size_t i = 0; i < public_columns; i++) {
                        public_input_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_2>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_2>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_2>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    test_circuit.init();

                    plonk_variable<FieldType> w0(0, 0, true,
                                                 plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w1(1, 0, true,
                                                 plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w2(2, 0, true,
                                                 plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w0_prev(0, -1, true,
                                                 plonk_variable<FieldType>::column_type::witness);

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
                constexpr static const std::size_t selector_columns_3 = 1;

                using arithmetization_params_3 = plonk_arithmetization_params<witness_columns_3,
                    public_columns_3, constant_columns_3, selector_columns_3>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_params<FieldType,
                    arithmetization_params_3>, 4, 3> circuit_test_3() {
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 3;

                    constexpr static const std::size_t witness_columns = witness_columns_3;
                    constexpr static const std::size_t public_columns = public_columns_3;
                    constexpr static const std::size_t constant_columns = constant_columns_3;
                    constexpr static const std::size_t selector_columns = selector_columns_3;
                    constexpr static const std::size_t table_columns = 
                            witness_columns + public_columns + constant_columns;

                    typedef placeholder_params<FieldType, arithmetization_params_3> circuit_params;

                    circuit_description<FieldType, circuit_params, rows_log, permutation> test_circuit;

                    std::array<std::vector<typename FieldType::value_type>, table_columns> table;
                    for (std::size_t j = 0; j < table_columns; j++) {
                        table[j].resize(test_circuit.table_rows);
                    }

                    // lookup inputs
                    typename FieldType::value_type one = FieldType::value_type::one();
                    typename FieldType::value_type zero = FieldType::value_type::zero();
                    table[0][0] = one;
                    table[1][0] = zero;
                    table[2][0] = one;

                    //lookup values
                    table[3][0] = zero;
                    table[4][0] = zero;
                    table[5][0] = zero;
                    table[3][1] = zero;
                    table[4][1] = one;
                    table[5][1] = one;
                    table[3][2] = one;
                    table[4][2] = zero;
                    table[5][2] = one;
                    table[3][3] = one;
                    table[4][3] = one;
                    table[5][3] = zero;

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};
                    std::array<plonk_column<FieldType>, constant_columns> constant_assignment;

                    std::vector<typename FieldType::value_type> sel_lookup(test_circuit.table_rows);
                    sel_lookup[0] = one;
                    sel_lookup[1] = zero;
                    sel_lookup[2] = zero;
                    sel_lookup[3] = zero;
                    selectors_assignment[0] = sel_lookup;

                    for (std::size_t i = 0; i < constant_columns; i++) {
                        constant_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, arithmetization_params_3>(
                        plonk_private_assignment_table<FieldType, arithmetization_params_3>(private_assignment),
                        plonk_public_assignment_table<FieldType, arithmetization_params_3>(
                            public_input_assignment, constant_assignment, selectors_assignment));

                    test_circuit.init();
                    plonk_variable<FieldType> w0(0, 0, true,
                                                plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w1(1, 0, true,
                                                plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w2(2, 0, true,
                                                plonk_variable<FieldType>::column_type::witness);

                    plonk_variable<FieldType> c0(0, 0, true,
                                                plonk_variable<FieldType>::column_type::constant);
                    plonk_variable<FieldType> c1(1, 0, true,
                                                plonk_variable<FieldType>::column_type::constant);
                    plonk_variable<FieldType> c2(2, 0, true,
                                                plonk_variable<FieldType>::column_type::constant);


                    plonk_lookup_constraint<FieldType> lookup_constraint;
                    math::term<plonk_variable<FieldType>> w0_term(w0);
                    math::term<plonk_variable<FieldType>> w1_term(w1);
                    math::term<plonk_variable<FieldType>> w2_term(w2);
                    lookup_constraint.lookup_input.push_back(w0_term);
                    lookup_constraint.lookup_input.push_back(w1_term);
                    lookup_constraint.lookup_input.push_back(w2_term);
                    lookup_constraint.lookup_value.push_back(c0);
                    lookup_constraint.lookup_value.push_back(c1);
                    lookup_constraint.lookup_value.push_back(c2);
                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint};
                    plonk_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(0, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);
                    return test_circuit;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TEST_PLONK_CIRCUITS_HPP
