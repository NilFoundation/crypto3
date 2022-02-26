//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#include <nil/crypto3/zk/snark/relations/plonk/permutation.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/table.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                    template <typename FieldType,
                        typename RedshiftParams,
                        std::size_t rows_log,
                        std::size_t permutation_size,
                        std::size_t usable_rows>
                        class circuit_description
                    {
                        using types_policy = zk::snark::detail::redshift_types_policy<FieldType, RedshiftParams>;
                        constexpr static const std::size_t witness_columns = RedshiftParams::witness_columns;
                        constexpr static const std::size_t public_columns = RedshiftParams::public_columns;
                        using merkle_hash_type = typename RedshiftParams::merkle_hash_type;
                        using transcript_hash_type = typename RedshiftParams::transcript_hash_type;

                        public:
                        const std::size_t table_rows = 1 << rows_log;

                        std::shared_ptr<math::evaluation_domain<FieldType>> domain;

                        typename FieldType::value_type omega;
                        typename FieldType::value_type delta;

                        plonk_permutation permutation;

                        std::vector<math::polynomial<typename FieldType::value_type>> S_id;
                        std::vector<math::polynomial<typename FieldType::value_type>> S_sigma;

                        typename types_policy::variable_assignment_type table;
                        std::vector<math::polynomial<typename FieldType::value_type>> column_polynomials;

                        // construct q_last, q_blind
                        math::polynomial<typename FieldType::value_type> q_last;
                        math::polynomial<typename FieldType::value_type> q_blind;

                        std::vector<plonk_gate<FieldType>> gates;

                        circuit_description() {
                            domain = math::make_evaluation_domain<FieldType>(table_rows);

                            omega = domain->get_domain_element(1);
                            delta = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

                            permutation = plonk_permutation(witness_columns + public_columns, table_rows);
                        }

                        void init() {
                            S_id = redshift_public_preprocessor<FieldType, RedshiftParams, 1>::identity_polynomials(
                            permutation_size, table_rows, omega, delta, domain);
                            S_sigma = redshift_public_preprocessor<FieldType, RedshiftParams, 1>::permutation_polynomials(
                            permutation_size, table_rows, omega, delta, permutation, domain);

                            q_last = redshift_public_preprocessor<FieldType, RedshiftParams, 1>::selector_last(
                            table_rows, usable_rows, domain);
                            q_blind = redshift_public_preprocessor<FieldType, RedshiftParams, 1>::selector_blind(
                            table_rows, usable_rows, domain);
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
                typedef redshift_params<3, 0> circuit_1_params; 
                template<typename FieldType>
                 circuit_description<FieldType, circuit_1_params, 4, 3, 16> circuit_test_1() {
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t table_columns = 3;
                    constexpr static const std::size_t witness_columns = 3;
                    std::size_t selectors_columns = 2;
                    constexpr static const std::size_t public_columns = 0;
                    constexpr static const std::size_t permutation = 3;
                    constexpr static const std::size_t usable = 1 << rows_log;

                    circuit_description<FieldType, circuit_1_params, rows_log, permutation, usable> test_circuit;
                    test_circuit.column_polynomials.resize(witness_columns + public_columns);

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
                    for (std::size_t i = 1; i < test_circuit.table_rows - 2; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] + table[1][i];
                        q_add[i] = FieldType::value_type::one();
                        q_mul[i] = FieldType::value_type::zero();
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = test_circuit.table_rows - 2; i < test_circuit.table_rows; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = algebra::random_element<FieldType>();
                        table[2][i] = table[0][i] * table[1][i];
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = FieldType::value_type::one();
                    }

                    for (std::size_t i = 0; i < table_columns; i++) {
                        test_circuit.domain->inverse_fft(table[i]);
                        test_circuit.column_polynomials[i] = math::polynomial<typename FieldType::value_type>(table[i]);
                    }

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                            private_assignment[i][j] = table[i][j];
                        }
                    }

                    std::vector<plonk_column<FieldType>> selectors_assignment(selectors_columns);
                    std::vector<plonk_column<FieldType>> public_input_assignment(public_columns);
                    for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                        selectors_assignment[0][j] = q_add[j];
                        selectors_assignment[1][j] = q_mul[j];
                    }

                    for (std::size_t i = 0; i < public_columns; i++) {
                        for (std::size_t j = 0; j < test_circuit.table_rows; j++) {
                            public_input_assignment[i][j] = table[witness_columns + i][j];
                        }
                    }

                    test_circuit.table = plonk_assignment_table<FieldType, circuit_1_params>(
                        plonk_private_assignment_table<FieldType, circuit_1_params>(private_assignment),
                        plonk_public_assignment_table<FieldType, circuit_1_params>(selectors_assignment,
                            public_input_assignment));

                    test_circuit.init();

                    
                    plonk_variable<FieldType> w0(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w1(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w2(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    
                    plonk_constraint<FieldType> add_constraint;
                    add_constraint.add_term(w0);
                    add_constraint.add_term(w1);
                    add_constraint.add_term(-w2);

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType> add_gate (0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_constraint<FieldType> mul_constraint;
                    add_constraint.add_term(w0 * w1);
                    add_constraint.add_term(-w2);

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType> mul_gate (1, mul_gate_costraints);
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
                // MUL: x * y = z, copy(p1, y)
                //---------------------------------------------------------------------------//
                typedef redshift_params<3, 1> circuit_2_params;
                template<typename FieldType>
                 circuit_description<FieldType, circuit_2_params, 4, 4, 16> circuit_test_2() {
                    constexpr static const std::size_t rows_log = 4;
                    constexpr static const std::size_t table_columns = 4;
                    constexpr static const std::size_t witness_columns = 3;
                    std::size_t selectors_columns = 2;
                    constexpr static const std::size_t public_columns = 1;
                    constexpr static const std::size_t permutation = 4;
                    constexpr static const std::size_t usable = 1 << rows_log;

                    circuit_description<FieldType, circuit_2_params, rows_log, permutation, usable> test_circuit;
                    test_circuit.column_polynomials.resize(witness_columns + public_columns);

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
                    table[0][3] = algebra::random_element<FieldType>();
                    q_add[0] = FieldType::value_type::zero();
                    q_mul[0] = FieldType::value_type::zero();

                    // fill rows with ADD gate
                    for (std::size_t i = 1; i < test_circuit.table_rows - 2; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = table[2][i - 1];
                        table[2][i] = table[0][i] + table[1][i];
                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = FieldType::value_type::one();
                        q_mul[i] = FieldType::value_type::zero();

                        test_circuit.permutation.cells_equal(1, i, 2, i - 1);
                    }

                    // fill rows with MUL gate
                    for (std::size_t i = test_circuit.table_rows - 2; i < test_circuit.table_rows; i++) {
                        table[0][i] = algebra::random_element<FieldType>();
                        table[1][i] = table[3][0];
                        table[2][i] = table[0][i] * table[1][i];
                        table[3][i] = FieldType::value_type::zero();
                        q_add[i] = FieldType::value_type::zero();
                        q_mul[i] = FieldType::value_type::one();

                        test_circuit.permutation.cells_equal(1, i, 3, 0);
                    }

                    for (std::size_t i = 0; i < table_columns; i++) {
                        test_circuit.domain->inverse_fft(table[i]);
                        test_circuit.column_polynomials[i] = math::polynomial<typename FieldType::value_type>(table[i]);
                    }

                    std::array<plonk_column<FieldType>, witness_columns> private_assignment;
                    for (std::size_t i = 0; i < witness_columns; i++) {
                        private_assignment[i] = table[i];
                    }

                    std::vector<plonk_column<FieldType>> selectors_assignment(selectors_columns);
                    std::vector<plonk_column<FieldType>> public_input_assignment(public_columns);

                    selectors_assignment[0] = q_add;
                    selectors_assignment[1] = q_mul;

                    for (std::size_t i = selectors_columns; i < selectors_columns + public_columns; i++) {
                        public_input_assignment[i] = table[witness_columns + i];
                    }
                    test_circuit.table = plonk_assignment_table<FieldType, circuit_2_params>(
                        plonk_private_assignment_table<FieldType, circuit_2_params>(private_assignment),
                        plonk_public_assignment_table<FieldType, circuit_2_params>(selectors_assignment,
                            public_input_assignment));

                    test_circuit.init();
                    
                    plonk_variable<FieldType> w0(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w1(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    plonk_variable<FieldType> w2(0, plonk_variable<FieldType>::rotation_type::current,
                        plonk_variable<FieldType>::column_type::witness);
                    
                    plonk_constraint<FieldType> add_constraint;
                    add_constraint.add_term(w0);
                    add_constraint.add_term(w1);
                    add_constraint.add_term(-w2);

                    std::vector<plonk_constraint<FieldType>> add_gate_costraints {add_constraint};
                    plonk_gate<FieldType> add_gate (0, add_gate_costraints);
                    test_circuit.gates.push_back(add_gate);

                    plonk_constraint<FieldType> mul_constraint;
                    add_constraint.add_term(w0 * w1);
                    add_constraint.add_term(-w2);

                    std::vector<plonk_constraint<FieldType>> mul_gate_costraints {mul_constraint};
                    plonk_gate<FieldType> mul_gate (1, mul_gate_costraints);
                    test_circuit.gates.push_back(mul_gate);

                    return test_circuit;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TEST_PLONK_CIRCUITS_HPP