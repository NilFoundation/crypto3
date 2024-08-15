//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_constant_pow_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_constant_pow_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: array of pairs <<a1, b1>, <a2, b2>, ..., <an, bn>>
            // Output: array <a1+b1, a2+b2, ..., an+bn>
            // Configuration is suboptimal: we do rows of the form
            // a1, b1, o1, a2, b2, o2, ...
            template<typename BlueprintFieldType>
            std::size_t integral_type_log2(typename BlueprintFieldType::integral_type pow){
                std::size_t result = 0;
                typename BlueprintFieldType::integral_type a = 1;
                while( a < pow ){
                    a *= 2;
                    result++;
                }
                return result;
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> integral_type_four_chunks(typename BlueprintFieldType::integral_type pow){
                std::vector<std::size_t> result;
                typename BlueprintFieldType::integral_type tmp = pow;
                while( tmp > 0 ) {
                    result.push_back(std::size_t(tmp%4));
                    tmp /= 4;
                }
                std::reverse(result.begin(), result.end());
                return result;
            }

            template<typename ArithmetizationType, typename FieldType>
            class flexible_constant_pow;

            template<typename BlueprintFieldType>
            class flexible_constant_pow<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                typename BlueprintFieldType::integral_type pow;
                std::size_t bits;
                std::vector<std::size_t>  four_chunks;
                std::size_t cells;
                std::size_t row_capacity;

                class gate_manifest_type : public component_gate_manifest {
                    std::size_t _witness_amount;
                    typename BlueprintFieldType::integral_type _pow;
                public:
                    gate_manifest_type(std::size_t witness_amount, typename BlueprintFieldType::integral_type pow) :
                        _witness_amount(witness_amount), _pow(pow) {};

                    std::uint32_t gates_amount() const override {
                        // related to pow
                        std::size_t one_row_cells = _witness_amount-2;
                        std::vector<std::size_t> four_chunks = integral_type_four_chunks<BlueprintFieldType>(_pow);
                        std::vector<typename BlueprintFieldType::integral_type> larger_chunks;
                        std::size_t cur = 0;
                        for(std::size_t i = 0; i < four_chunks.size(); i++){
                            if ( i%one_row_cells == 0 ){
                                larger_chunks.push_back(0);
                                cur++;
                            }
                            larger_chunks[cur-1] *= 4;
                            larger_chunks[cur-1] += four_chunks[i];
                        }
                        std::vector<typename BlueprintFieldType::integral_type> unique_chunks;
                        std::unique_copy(larger_chunks.begin(), larger_chunks.end(), std::back_inserter(unique_chunks));
                        return unique_chunks.size();
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    typename BlueprintFieldType::integral_type pow
                ) {
                    // related to pow
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, pow));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(5, 300, 1)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             typename BlueprintFieldType::integral_type pow) {

                    std::size_t bits = integral_type_log2<BlueprintFieldType>(pow);
                    std::size_t cells = (bits+1)/2;
                    std::size_t one_row_cells = witness_amount-2;
                    return cells%one_row_cells == 0? cells/one_row_cells: cells/one_row_cells + 1;
                }

                //constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), pow);

                struct input_type {
                    var x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(x);
                        return result;
                    }
                };

                struct result_type {
                    var y;

                    result_type(const flexible_constant_pow &component, std::size_t start_row_index) {
                        // TODO define output var
                        std::size_t witness_amount = component.witness_amount();
                        std::size_t last_column_id = component.four_chunks.size()%(witness_amount - 2) + 1;
                        y = var(component.W(last_column_id), start_row_index + component.rows_amount-1, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(y);
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit flexible_constant_pow(ContainerType witness, typename BlueprintFieldType::integral_type _pow) :
                    component_type(witness, {}, {}, get_manifest()),
                    pow(_pow), bits(integral_type_log2<BlueprintFieldType>(_pow)),
                    four_chunks(integral_type_four_chunks<BlueprintFieldType>(_pow)) {
                        assert(four_chunks.size() == (bits+1)/2);
                    }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_constant_pow(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, typename BlueprintFieldType::integral_type _pow) :
                    component_type(witness, constant, public_input, get_manifest()),
                    pow(_pow), bits(integral_type_log2<BlueprintFieldType>(_pow)),
                    four_chunks(integral_type_four_chunks<BlueprintFieldType>(_pow)) {
                        assert(four_chunks.size() == (bits+1)/2);
                    };

                flexible_constant_pow(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    typename BlueprintFieldType::integral_type _pow) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    pow(_pow), bits(integral_type_log2<BlueprintFieldType>(_pow)),
                    four_chunks(integral_type_four_chunks<BlueprintFieldType>(_pow)) {
                        assert(four_chunks.size() == (bits+1)/2);
                    };
            };

            template<typename BlueprintFieldType>
            using plonk_flexible_constant_pow =
                flexible_constant_pow<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_flexible_constant_pow<BlueprintFieldType>::result_type generate_assignments(
                const plonk_flexible_constant_pow<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_constant_pow<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;
                auto four_chunks = component.four_chunks;
                auto x = var_value(assignment, instance_input.x);

                std::size_t cur = 0;
                value_type cur_val = 1;
                for (std::size_t row = 0; row < rows_amount; row++) {
                    assignment.witness(component.W(0), start_row_index+row) = x;
                    assignment.witness(component.W(1), start_row_index+row) = cur_val;
                    for (std::size_t cell = 2; cell < witness_amount; cell++ ) {
                        if (cur < four_chunks.size()) {
                            cur_val = cur_val.pow(4) * x.pow(four_chunks[cur]);
                            assignment.witness(component.W(cell), start_row_index + row) = cur_val;
                            cur++;
                        } else {
                            assignment.witness(component.W(cell), start_row_index + row) = 0;
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
            generate_gates(
                const plonk_flexible_constant_pow<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_constant_pow<BlueprintFieldType>::input_type
                    &instance_input) {

                using component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<std::size_t> selectors;
                const std::size_t witness_amount = component.witness_amount();
                auto four_chunks = component.four_chunks;

                std::size_t cur = 0;
                for( std::size_t row = 0; row < component.rows_amount; row++ ) {
                    std::vector<constraint_type> constraints;
                    var x_var = var(component.W(0),0,true);

                    for (std::size_t cell = 2; cell < witness_amount; cell++ ) {
                        if (cur < four_chunks.size()) {
                            var cur_var = var(component.W(cell),0,true);
                            constraints.push_back(var(component.W(cell), 0, true) -  var(component.W(cell-1),0,true).pow(4) * x_var.pow(four_chunks[cur]));
                            cur++;
                        } else {
                            break;
                        }
                    }
                    selectors.push_back(bp.add_gate(constraints));
                }
                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_flexible_constant_pow<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_constant_pow<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                    using component_type = plonk_flexible_constant_pow<BlueprintFieldType>;
                    using var = typename component_type::var;

                    // Input variable
                    for( std::size_t row = 0; row < component.rows_amount; row++){
                        bp.add_copy_constraint({instance_input.x, var(component.W(0), start_row_index+row, false)});
                        if(row != 0){
                            bp.add_copy_constraint({var(component.W(1), start_row_index+row, false), var(component.W(component.witness_amount()-1), start_row_index+row-1, false)});
                        }
                    }
            }

            template<typename BlueprintFieldType>
            typename plonk_flexible_constant_pow<BlueprintFieldType>::result_type generate_circuit(
                const plonk_flexible_constant_pow<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_constant_pow<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_flexible_constant_pow<BlueprintFieldType>;

                auto selector_indices = generate_gates(component, bp, assignment, instance_input);
                for( std::size_t i = 0; i < selector_indices.size(); i++){
                    assignment.enable_selector(selector_indices[i], start_row_index+i);
                }
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_constant_pow_HPP
