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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_x_index_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_x_index_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: field value x, bit-array <b1,...b_k>
            // Constant: omega
            // Output: bit b0
            // Configuration:
            //      1, b_0, w_0^2 * [(1-b_0)+\omega * b_0], b1, w_1^2 * [(1-b_1)+\omega * b_1] ...
            template<typename ArithmetizationType, typename FieldType>
            class flexible_x_index;

            template<typename BlueprintFieldType>
            class flexible_x_index<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t n;
                value_type  omega;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return flexible_x_index::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    std::size_t n
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(3, 300, 3)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t n) {
                    std::size_t cells = 2 * n;
                    std::size_t one_row_cells = ((witness_amount-1) / 2)*2;
                    return cells%one_row_cells == 0? cells/one_row_cells: cells/one_row_cells + 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), n);

                struct input_type {
                    var x;
	                std::vector<var> b; // the array of pairs of elements

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(x);
                        for( std::size_t i = 0; i < b.size(); i++ ){
                            result.push_back(b[i]);
                        }
                        return result;
                    }
                };

                struct result_type {
                    var b0;

                    result_type(const flexible_x_index &component, std::size_t start_row_index) {
//                      Think carefully!
                        b0 = var(component.W(1), start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(b0);
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit flexible_x_index(ContainerType witness, std::size_t _n, value_type _omega) :
                    component_type(witness, {}, {}, get_manifest()),
                    n(_n), omega(_omega) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_x_index(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, std::size_t _n, value_type _omega) :
                    component_type(witness, constant, public_input, get_manifest()),
                    n(_n), omega(_omega) {};

                flexible_x_index(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _n, value_type _omega) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    n(_n), omega(_omega) {};
            };

            template<typename BlueprintFieldType>
            using plonk_flexible_x_index =
                flexible_x_index<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_flexible_x_index<BlueprintFieldType>::result_type generate_assignments(
                const plonk_flexible_x_index<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_x_index<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                const std::size_t n = instance_input.b.size();
                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;

                std::size_t cur = 0;
                value_type x = var_value(assignment, instance_input.x);
                value_type b0;
                value_type tmp = 1;
                value_type omega = component.omega;
                value_type x_index = 0;
                for( std::size_t i = 0; i < n; i++){
                    value_type b = var_value(assignment, instance_input.b[n - 1 -i]);
                    tmp = tmp * tmp * (b + omega *(1-b));
                    x_index *= 2;
                    x_index += (1-b);
                }
                BOOST_ASSERT(tmp == x || tmp == -x);
                if( tmp == x )  b0 = 1; else b0 =0;

                std::vector<value_type> all_ordered_bits;
                all_ordered_bits.push_back(b0);
                for( std::size_t i = 0; i < n; i++){
                    all_ordered_bits.push_back(var_value(assignment, instance_input.b[n - 1 -i]));
                }

                tmp = 1;
                for (std::size_t row = 0; row < rows_amount; row++) {
                    assignment.constant(component.C(0), start_row_index + row) = omega;
                    assignment.witness(component.W(0), start_row_index + row) = tmp;
                    for (std::size_t block = 0; block < (witness_amount-1)/2; block++, cur++) {
                        if (cur < all_ordered_bits.size()) {
                            assignment.witness(component.W(block*2 + 1), start_row_index + row) = all_ordered_bits[cur];
                            tmp = tmp * tmp * (all_ordered_bits[cur] + (1-all_ordered_bits[cur]) * omega);
                            assignment.witness(component.W(block*2 + 2), start_row_index + row) = tmp;
                        } else {
                            assignment.witness(component.W(block*2 + 1), start_row_index + row) = 1;
                            tmp = tmp * tmp;
                            assignment.witness(component.W(block*2 + 2), start_row_index + row) = tmp;
                            cur ++;
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_flexible_x_index<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_x_index<BlueprintFieldType>::input_type
                    &instance_input) {

                using component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                BOOST_ASSERT(component.n == instance_input.b.size());

                std::vector<constraint_type> constraints;
                var omega = var(component.C(0), 0, true,  var::column_type::constant);
                for( std::size_t block = 0; block < (component.witness_amount()-1)/2; block++){
                    var prev =  var(component.W(block*2), 0, true);
                    var b = var(component.W(block*2 + 1), 0, true);
                    var next = var(component.W(block*2 + 2), 0, true);
                    constraints.push_back( next - prev * prev *(b + omega - omega * b));
                }
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_flexible_x_index<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_x_index<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_flexible_x_index<BlueprintFieldType>;
                using var = typename component_type::var;

                std::size_t cur = 0;
                for( std::size_t row = 0; row < component.rows_amount; row++){
                    if( row != 0) bp.add_copy_constraint({
                        var(component.W((component.witness_amount() - 1) / 2 * 2), start_row_index+row - 1, false),
                        var(component.W(0), start_row_index+row, false),
                    });
                    for( std::size_t block = 0; block < (component.witness_amount() - 1) / 2; block++ ){
                        if( cur != 0){
                            bp.add_copy_constraint({instance_input.b[component.n - cur], var(component.W(block * 2 + 1), start_row_index + row, false)});
                        }
                        cur++;
                        if( cur == component.n + 1 ){
                            bp.add_copy_constraint({instance_input.x, var(component.W(block * 2 + 2), start_row_index + row, false)});
                            break;
                        }
                    }
                }

/*
                BOOST_ASSERT(component.n == instance_input.arr.size());
                std::size_t n = instance_input.arr.size();
                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;

                std::size_t cur = 0;
                for (std::size_t row = 0; row < rows_amount; row++) {
                    if(cur >= n) break;
                    for (std::size_t block = 0; block < witness_amount/3; block++, cur++) {
                        if(cur >= n) break;
                        bp.add_copy_constraint(
                            {instance_input.arr[cur].first, var(component.W(3*block), start_row_index + row, false)});
                        bp.add_copy_constraint(
                            {instance_input.arr[cur].second, var(component.W(3*block+1), start_row_index + row, false)});
                    }
                }*/
            }

            template<typename BlueprintFieldType>
            typename plonk_flexible_x_index<BlueprintFieldType>::result_type generate_circuit(
                const plonk_flexible_x_index<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_x_index<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_flexible_x_index<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_x_index_HPP