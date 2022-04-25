//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class pickles_verifier_scalar_field;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class pickles_verifier_scalar_field<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using poseidon_component = poseidon<ArithmetizationType, BlueprintFieldType,
                                W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                public:

                    constexpr static const std::size_t rows_amount = 1 + poseidon_component::rows_amount;

                    struct params_type {
                        std::array<typename ArithmetizationType::field_type::value_type, 3> input_data;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(rows_amount);
                    }

                    static void generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);
                    }

                    static void generate_assignments(
                        blueprint_assignment_table<ArithmetizationType>
                            &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                            
                        std::size_t row = component_start_row;
                        row++;

                        std::array<typename ArithmetizationType::field_type::value_type, 3> input_state = params.input_data;
                        typename poseidon_component::params_type poseidon_params = {input_state};
                        poseidon_component::generate_assignments(assignment, 
                            poseidon_params, row);
                        assignment.public_input(0)[component_start_row] = assignment.witness(1)[row + 11];

                    }

                    private:
                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                        std::size_t row = component_start_row;
                        row++;                       
                        typename poseidon_component::params_type poseidon_params = {};
                        poseidon_component::generate_gates(bp, assignment,
                            poseidon_params, row);
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        row++;

                        typename poseidon_component::params_type poseidon_params = {};
                        poseidon_component::generate_copy_constraints(bp, assignment,
                            poseidon_params, row);
                        bp.add_copy_constraint({{W1, row + rows_amount - 1, false}, {0, row - 1, false, snark::plonk_variable<BlueprintFieldType>::column_type::public_input}});

                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP
