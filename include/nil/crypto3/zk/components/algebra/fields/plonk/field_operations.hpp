//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_OPERATIONS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_OPERATIONS_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class multiplication;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class multiplication<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:
                    constexpr static const std::size_t required_rows_amount = 1;

                    struct params_type {
                        var x;
                        var y;
                    };

                    struct result_type {
                        var result = var(0, 0);

                        result_type(const params_type &params,
                            const std::size_t &component_start_row) {

                        }
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp,
                        std::size_t components_amount = 1){
                        return bp.allocate_rows(required_rows_amount *
                            components_amount);
                    }

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row) {

                        return result_type(params, component_start_row);
                    }

                    private:
                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment, 
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t row_start_index) {

                        if (!allocated_data.previously_allocated) {
                        } else { 
                        }

                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row){

                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_OPERATIONS_HPP