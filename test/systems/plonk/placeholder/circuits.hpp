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
                    std::vector<plonk_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates;

                    circuit_description()
                        : domain(math::make_evaluation_domain<FieldType>(table_rows))
                        , omega(domain->get_domain_element(1))
                        , delta(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator) {
                    }
                };

                //---------------------------------------------------------------------------//
                // Test circuit 
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
                constexpr static const std::size_t selector_columns_3 = 1;

                using arithmetization_params_3 = plonk_arithmetization_params<witness_columns_3,
                    public_columns_3, constant_columns_3, selector_columns_3>;

                template<typename FieldType>
                circuit_description<FieldType, placeholder_circuit_params<FieldType, arithmetization_params_3>, 4, 4> circuit_test_3() {
                    using assignment_type = typename FieldType::value_type;
                    using field_type = typename FieldType::value_type;

                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t permutation = 4;

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

                    std::array<plonk_column<FieldType>, public_columns> public_input_assignment = {};

                    std::array<plonk_column<FieldType>, selector_columns> selectors_assignment;
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

                    plonk_variable<assignment_type> w0(0, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(1, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(2, 0, true,
                                                plonk_variable<assignment_type>::column_type::witness);

                    plonk_variable<assignment_type> c0(0, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c1(1, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);
                    plonk_variable<assignment_type> c2(2, 0, true,
                                                plonk_variable<assignment_type>::column_type::constant);


                    plonk_lookup_constraint<FieldType> lookup_constraint;
                    lookup_constraint.lookup_input.insert(
                        lookup_constraint.lookup_input.end(), 
                        {w0, w1, w2, c0, c1, c2});
                    std::vector<plonk_lookup_constraint<FieldType>> lookup_constraints = {lookup_constraint};
                    plonk_gate<FieldType, plonk_lookup_constraint<FieldType>> lookup_gate(0, lookup_constraints);
                    test_circuit.lookup_gates.push_back(lookup_gate);
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

                    plonk_variable<FieldType> x0(0, 0, false, 
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> x1(0, 1, false, 
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> p0(1, 0, false, 
                        plonk_variable<FieldType>::column_type::public_input);
                    plonk_variable<FieldType> p1(1, 1, false, 
                        plonk_variable<FieldType>::column_type::public_input);

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

                    plonk_variable<assignment_type> w0(0, -1, true,
                                                 plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w1(0, 0, true,
                                                 plonk_variable<assignment_type>::column_type::witness);
                    plonk_variable<assignment_type> w2(0, 1, true,
                                                 plonk_variable<assignment_type>::column_type::witness);

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
