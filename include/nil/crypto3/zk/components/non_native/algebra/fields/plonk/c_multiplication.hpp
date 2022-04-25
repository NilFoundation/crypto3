//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_C_MULTIPLICATION_COMPONENT_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_C_MULTIPLICATION_COMPONENT_9_WIRES_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class non_native_field_element_c_multiplication;

                template<typename BlueprintFieldType,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class non_native_field_element_c_multiplication<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       FieldType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    

                public:

                constexpr static const std::size_t rows_amount = 9;

                   struct params_type {
                        typename FieldType::value_type A;
                        typename FieldType::value_type B;
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                        std::array<std::size_t, 1> selectors;
                    };

                    struct result_type {
                        std::array<var, 1> output = {var(0, 0, false)};

                        result_type(const std::size_t &component_start_row) {
                            std::array<var, 1> output = {var(W0, component_start_row + rows_amount - 1, false)};
                        }
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(rows_amount);
                    }

                     static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);
                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const assignment_params_type &params,
                        const std::size_t &component_start_row) {
                        return result_type(component_start_row);
                    }

                    private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;

                        std::size_t selector_index = public_assignment.add_selector({j + 0, j + 2, j + 4, j + 6});

                        snark::plonk_constraint<BlueprintFieldType> s = 
                            (var(W1, 0) + var(W2, 0) + var(W3, 0) +
                             var(W4, 0) + var(W5, 0) + var(W6, 0) +
                             var(W7, 0) + var(W2, +1) + var(W3, +1) +
                             var(W4, +1) + var(W5, +1) + var(W6, +1)
                             - 12 * ((2^20) - 1));

                        bp.add_gate(selector_index, s * (var(W8, 0) * s - 1));
                        bp.add_gate(selector_index, var(W8, 0) * s + (1 - var(W8, 0) * s) * var(W8, +1) - 1);
                        bp.add_gate(selector_index, var(W0, 0) - (var(W7, +1) + var(W6, +1) * (2^15) + var(W5, +1) * (2^35) + var(W4, +1) * (2^55)));
                        bp.add_gate(selector_index, var(W0, +1) - (var(W3, +1) + var(W2, +1) * (2^20) + var(W7, 0) * (2^40)));
                        bp.add_gate(selector_index, var(W1, +1) - (var(W6, 0) + var(W5, 0) * (2^20) + var(W4, 0) * (2^40)));

                        selector_index = public_assignment.add_selector(j + 7);
                        bp.add_gate(selector_index, var(W3, +1) - var(W1, 0));
                        bp.add_gate(selector_index, var(W5, +1) - var(W0, 0));
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;
                        
                        bp.add_copy_constraint({var(W0, j + 8, false), var(W0, j + 4, false)});
                        bp.add_copy_constraint({var(W1, j + 8, false), var(W0, j + 5, false)});
                        bp.add_copy_constraint({var(W2, j + 8, false), var(W1, j + 5, false)});
                        bp.add_copy_constraint({var(W6, j + 8, false), var(W0, j + 6, false)});
                        bp.add_copy_constraint({var(W7, j + 8, false), var(W1, j + 4, false)});
                        bp.add_copy_constraint({var(W6, j + 8, false), var(W0, j + 6, false)});
                        bp.add_copy_constraint({var(W7, j + 8, false), var(W1, j + 4, false)});
                        bp.add_copy_constraint({var(W8, j + 8, false), var(W2, j + 4, false)});
                        bp.add_copy_constraint({var(W0, j + 9, false), var(W0, j + 3, false)});
                        bp.add_copy_constraint({var(W1, j + 9, false), var(W1, j + 3, false)});
                        bp.add_copy_constraint({var(W2, j + 9, false), var(W3, j + 4, false)});
                        bp.add_copy_constraint({var(W3, j + 9, false), var(W1, j + 2, false)});
                        bp.add_copy_constraint({var(W4, j + 9, false), var(W2, j + 2, false)});
                        bp.add_copy_constraint({var(W5, j + 9, false), var(W3, j + 2, false)});
                        bp.add_copy_constraint({var(W7, j + 9, false), var(W0, j + 11, false)});
                        bp.add_copy_constraint({var(W8, j + 9, false), var(W4, j + 11, false)});
                        bp.add_copy_constraint({var(W0, j + 10, false), var(W0, j + 0, false)});
                        bp.add_copy_constraint({var(W1, j + 10, false), var(W0, j + 1, false)});
                        bp.add_copy_constraint({var(W2, j + 10, false), var(W1, j + 1, false)});
                        bp.add_copy_constraint({var(W3, j + 10, false), var(W0, j + 2, false)});
                        bp.add_copy_constraint({var(W4, j + 10, false), var(W1, j + 0, false)});
                        bp.add_copy_constraint({var(W5, j + 10, false), var(W2, j + 0, false)});
                        bp.add_copy_constraint({var(W6, j + 10, false), var(W3, j + 0, false)});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_C_MULTIPLICATION_COMPONENT_9_WIRES_HPP
