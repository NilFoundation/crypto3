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
// @file Declaration of interfaces for a TBCS-to-USCS reduction, that is, constructing
// a USCS ("Unitary-Square Constraint System") from a TBCS ("Two-input Boolean Circuit Satisfiability").
//
// The reduction is straightforward: each non-output wire is mapped to a
// corresponding USCS constraint that enforces the wire to carry a boolean value;
// each 2-input boolean gate is mapped to a corresponding USCS constraint that
// enforces correct computation of the gate; each output wire is mapped to a
// corresponding USCS constraint that enforces that the output is zero.
//
// The mapping of a gate to a USCS constraint is due to \[GOS12].
//
// References:
//
// \[GOS12]:
// "New techniques for noninteractive zero-knowledge",
// Jens Groth, Rafail Ostrovsky, Amit Sahai
// JACM 2012,
// <http://www0.cs.ucl.ac.uk/staff/J.Groth/NIZKJournal.pdf>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_TO_USCS_BASIC_POLICY_HPP
#define CRYPTO3_ZK_TBCS_TO_USCS_BASIC_POLICY_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace reductions {
                    template<typename FieldType>
                    struct tbcs_to_uscs {
                        typedef FieldType field_type;

                        /**
                         * Instance map for the TBCS-to-USCS reduction.
                         */
                        static uscs_constraint_system<FieldType> instance_map(const tbcs_circuit &circuit) {
                            assert(circuit.is_valid());
                            uscs_constraint_system<FieldType> result;

                            result.primary_input_size = circuit.primary_input_size;
                            result.auxiliary_input_size = circuit.auxiliary_input_size + circuit.gates.size();

                            for (auto &g : circuit.gates) {
                                const variable<FieldType> x(g.left_wire);
                                const variable<FieldType> y(g.right_wire);
                                const variable<FieldType> z(g.output);

                                switch (g.type) {
                                    case TBCS_GATE_CONSTANT_0:
                                        /* Truth table (00, 01, 10, 11): (0, 0, 0, 0)
                                           0 * x + 0 * y + 1 * z + 1 \in {-1, 1} */
                                        result.add_constraint(0 * x + 0 * y + 1 * z + 1);
                                        break;
                                    case TBCS_GATE_AND:
                                        /* Truth table (00, 01, 10, 11): (0, 0, 0, 1)
                                           -2 * x + -2 * y + 4 * z + 1 \in {-1, 1} */
                                        result.add_constraint(-2 * x + -2 * y + 4 * z + 1);
                                        break;
                                    case TBCS_GATE_X_AND_NOT_Y:
                                        /* Truth table (00, 01, 10, 11): (0, 0, 1, 0)
                                           -2 * x + 2 * y + 4 * z + -1 \in {-1, 1} */
                                        result.add_constraint(-2 * x + 2 * y + 4 * z + -1);
                                        break;
                                    case TBCS_GATE_X:
                                        /* Truth table (00, 01, 10, 11): (0, 0, 1, 1)
                                           -1 * x + 0 * y + 1 * z + 1 \in {-1, 1} */
                                        result.add_constraint(-1 * x + 0 * y + 1 * z + 1);
                                        break;
                                    case TBCS_GATE_NOT_X_AND_Y:
                                        /* Truth table (00, 01, 10, 11): (0, 1, 0, 0)
                                           2 * x + -2 * y + 4 * z + -1 \in {-1, 1} */
                                        result.add_constraint(2 * x + -2 * y + 4 * z + -1);
                                        break;
                                    case TBCS_GATE_Y:
                                        /* Truth table (00, 01, 10, 11): (0, 1, 0, 1)
                                           0 * x + 1 * y + 1 * z + -1 \in {-1, 1} */
                                        result.add_constraint(0 * x + 1 * y + 1 * z + -1);
                                        break;
                                    case TBCS_GATE_XOR:
                                        /* Truth table (00, 01, 10, 11): (0, 1, 1, 0)
                                           1 * x + 1 * y + 1 * z + -1 \in {-1, 1} */
                                        result.add_constraint(1 * x + 1 * y + 1 * z + -1);
                                        break;
                                    case TBCS_GATE_OR:
                                        /* Truth table (00, 01, 10, 11): (0, 1, 1, 1)
                                           -2 * x + -2 * y + 4 * z + -1 \in {-1, 1} */
                                        result.add_constraint(-2 * x + -2 * y + 4 * z + -1);
                                        break;
                                    case TBCS_GATE_NOR:
                                        /* Truth table (00, 01, 10, 11): (1, 0, 0, 0)
                                           2 * x + 2 * y + 4 * z + -3 \in {-1, 1} */
                                        result.add_constraint(2 * x + 2 * y + 4 * z + -3);
                                        break;
                                    case TBCS_GATE_EQUIVALENCE:
                                        /* Truth table (00, 01, 10, 11): (1, 0, 0, 1)
                                           1 * x + 1 * y + 1 * z + -2 \in {-1, 1} */
                                        result.add_constraint(1 * x + 1 * y + 1 * z + -2);
                                        break;
                                    case TBCS_GATE_NOT_Y:
                                        /* Truth table (00, 01, 10, 11): (1, 0, 1, 0)
                                           0 * x + -1 * y + 1 * z + 0 \in {-1, 1} */
                                        result.add_constraint(0 * x + -1 * y + 1 * z + 0);
                                        break;
                                    case TBCS_GATE_IF_Y_THEN_X:
                                        /* Truth table (00, 01, 10, 11): (1, 0, 1, 1)
                                           -2 * x + 2 * y + 4 * z + -3 \in {-1, 1} */
                                        result.add_constraint(-2 * x + 2 * y + 4 * z + -3);
                                        break;
                                    case TBCS_GATE_NOT_X:
                                        /* Truth table (00, 01, 10, 11): (1, 1, 0, 0)
                                           -1 * x + 0 * y + 1 * z + 0 \in {-1, 1} */
                                        result.add_constraint(-1 * x + 0 * y + 1 * z + 0);
                                        break;
                                    case TBCS_GATE_IF_X_THEN_Y:
                                        /* Truth table (00, 01, 10, 11): (1, 1, 0, 1)
                                           2 * x + -2 * y + 4 * z + -3 \in {-1, 1} */
                                        result.add_constraint(2 * x + -2 * y + 4 * z + -3);
                                        break;
                                    case TBCS_GATE_NAND:
                                        /* Truth table (00, 01, 10, 11): (1, 1, 1, 0)
                                           2 * x + 2 * y + 4 * z + -5 \in {-1, 1} */
                                        result.add_constraint(2 * x + 2 * y + 4 * z + -5);
                                        break;
                                    case TBCS_GATE_CONSTANT_1:
                                        /* Truth table (00, 01, 10, 11): (1, 1, 1, 1)
                                           0 * x + 0 * y + 1 * z + 0 \in {-1, 1} */
                                        result.add_constraint(0 * x + 0 * y + 1 * z + 0);
                                        break;
                                    default:
                                        assert(0);
                                }
                            }

                            for (std::size_t i = 0;
                                 i < circuit.primary_input_size + circuit.auxiliary_input_size + circuit.gates.size();
                                 ++i) {
                                /* require that 2 * wire - 1 \in {-1,1}, that is wire \in {0,1} */
                                result.add_constraint(2 * variable<FieldType>(i) - 1);
                            }

                            for (auto &g : circuit.gates) {
                                if (g.is_circuit_output) {
                                    /* require that output + 1 \in {-1,1}, this together with output binary (above)
                                     * enforces output = 0 */
                                    result.add_constraint(variable<FieldType>(g.output) + 1);
                                }
                            }

                            return result;
                        }

                        /**
                         * Witness map for the TBCS-to-USCS reduction.
                         */
                        static uscs_variable_assignment<FieldType>
                            witness_map(const tbcs_circuit &circuit,
                                        const tbcs_primary_input &primary_input,
                                        const tbcs_auxiliary_input &auxiliary_input) {

                            const tbcs_variable_assignment all_wires =
                                circuit.get_all_wires(primary_input, auxiliary_input);
                            const uscs_variable_assignment<FieldType> result =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(all_wires);
                            return result;
                        }
                    };
                }    // namespace reductions
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_TO_USCS_BASIC_POLICY_HPP
