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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_COLINEAR_CHECKS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_COLINEAR_CHECKS_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: array of n tuples x, {b_1, b_2, ..., b_r}, {y_0, y_1, ..., y_2r} {alpha_0, alpha_2, ..., alpha_r-1}
            // Constant: omega
            // Output: x -- challenge for final polynomial
            // If check is wrong -- copy constraints failes
            // Structure:
            // {x,b,y_0,y_1,omega^\sum{b}}\alpha
            template<typename ArithmetizationType, typename FieldType>
            class flexible_colinear_checks;

            template<typename BlueprintFieldType>
            class flexible_colinear_checks<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t r;
                value_type omega;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return flexible_colinear_checks::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    std::size_t r
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(9, 300, 5)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t r) {
                    std::size_t cells = 5 * r + 4;
                    std::size_t one_row_cells = ((witness_amount-4) / 5);
                    return (cells-4)%one_row_cells == 0? (cells-4)/one_row_cells: (cells-4)/one_row_cells + 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), r);

                struct input_type {
                    var x;                   // first challenge x
	                std::vector<var> ys;     // array of pairs of elements r+1 pairs
                    std::vector<var> bs;     // array of r+1 signs
                    std::vector<var> alphas; // array size r
                    std::size_t r;

                    input_type(std::size_t r){
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        BOOST_ASSERT(ys.size() == bs.size()*2);
                        BOOST_ASSERT(alphas.size() + 1 == bs.size());
                        result.push_back(x);

                        for( std::size_t i = 0; i < ys.size(); i++ ){
                            result.push_back(ys[i]);
                        }
                        for( std::size_t i = 0; i < bs.size(); i++ ){
                            result.push_back(bs[i]);
                        }
                        for( std::size_t i = 0; i < alphas.size(); i++ ){
                            result.push_back(alphas[i]);
                        }
                        return result;
                    }
                };

                struct result_type {
                    result_type(const flexible_colinear_checks &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit flexible_colinear_checks(ContainerType witness, std::size_t _r) :
                    component_type(witness, {}, {}, get_manifest()),
                    r(_r) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_colinear_checks(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, std::size_t _r) :
                    component_type(witness, constant, public_input, get_manifest()),
                    r(_r) {};

                flexible_colinear_checks(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _r) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    r(_r) {};
            };

            template<typename BlueprintFieldType>
            using plonk_flexible_colinear_checks =
                flexible_colinear_checks<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_flexible_colinear_checks<BlueprintFieldType>::result_type generate_assignments(
                const plonk_flexible_colinear_checks<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_colinear_checks<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {
                assert(instance_input.ys.size() == instance_input.bs.size()*2);
                assert(instance_input.alphas.size() + 1 == instance_input.bs.size());

                using component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                BOOST_ASSERT(component.r == instance_input.alphas.size());
                BOOST_ASSERT(component.r + 1 == instance_input.bs.size());
                BOOST_ASSERT(2 * (component.r + 1) == instance_input.ys.size());

                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;

                std::size_t cur = 0;
                value_type x = var_value(assignment, instance_input.x);
                for (std::size_t row = 0; row < rows_amount; row++) {
                    std::size_t block = 0;
                    for (; block < (witness_amount-4)/5; block++) {
                        if (cur < component.r){
                            value_type b = var_value(assignment, instance_input.bs[cur]);
                            value_type y0_val = var_value(assignment, instance_input.ys[2*cur]);
                            value_type y1_val = var_value(assignment, instance_input.ys[2*cur+1]);
                            value_type alpha = var_value(assignment, instance_input.alphas[cur]);

                            // value_type s = 2 * b * x - x;
                            // value_type interpolant = ((alpha + s ) * y0_val - (alpha - s) * y1_val ) / (2 * s);
//                            std::cout << "Interpolant  " << cur << " index " << b << ":";
//                            for( std::size_t k = 0; k < instance_input.bs.size(); k++) {
//                                std::cout << var_value(assignment, instance_input.bs[k]) << " ";
//                            }
//                            std::cout << std::endl << interpolant << std::endl;

                            assignment.witness(component.W(block*5), start_row_index + row) = x;
                            assignment.witness(component.W(block*5+1), start_row_index + row) = b;
                            assignment.witness(component.W(block*5+2), start_row_index + row) = y0_val;
                            assignment.witness(component.W(block*5+3), start_row_index + row) = y1_val;
                            assignment.witness(component.W(block*5+4), start_row_index + row) = alpha;
                            cur++;
                            x = x * x;
                            y0_val = var_value(assignment, instance_input.ys[2*cur]);
                            y1_val = var_value(assignment, instance_input.ys[2*cur+1]);
                            value_type b_val = var_value(assignment, instance_input.bs[cur]);
                            //std::cout << b_val * y0_val + (1 - b_val) * y1_val << std::endl;
                            assignment.witness(component.W(block*5 + 5), start_row_index + row) = x;
                            assignment.witness(component.W(block*5 + 6), start_row_index + row) = b_val;
                            assignment.witness(component.W(block*5 + 7), start_row_index + row) = y0_val;
                            assignment.witness(component.W(block*5 + 8), start_row_index + row) = y1_val;
                        } else {
                            // Fill it with something to prevent new gate from being added
                            value_type x = assignment.witness(component.W(block * 5), start_row_index + row);
                            value_type b = assignment.witness(component.W(block * 5 + 1), start_row_index + row);
                            value_type y0 = assignment.witness(component.W(block * 5 + 2), start_row_index + row);
                            value_type y1 = assignment.witness(component.W(block * 5 + 3), start_row_index + row);
                            value_type alpha = 0;

                            value_type s = 2 * b * x - x;

                            assignment.witness(component.W(block*5 + 4), start_row_index + row) = 0; // fake alpha
                            assignment.witness(component.W(block*5 + 5), start_row_index + row) = x*x; // new fake x
                            assignment.witness(component.W(block*5 + 6), start_row_index + row) = 0;   // new fake b
                            assignment.witness(component.W(block*5 + 7), start_row_index + row) = 0;   // new fake b = 0 so, it doesn't matter
                            // TODO(martun): check if s being a zero, which I handled on the next line is ok. Maybe it was not supposed to be 0?
                            assignment.witness(component.W(block*5 + 8), start_row_index + row) = ((alpha + s ) * y0 - (alpha - s) * y1 ) * (s == 0u ? 0u : (2 * s).inversed());   // new fake y
                            x = x * x;
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_flexible_colinear_checks<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_colinear_checks<BlueprintFieldType>::input_type
                    &instance_input) {

                using component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<constraint_type> constraints;
                const std::size_t witness_amount = component.witness_amount();
                for( std::size_t block = 0; block < (witness_amount-4)/5; block++ ) {
                    if( block == 0) continue;
                    var x = var(component.W(block*5), 0, true);
                    var b = var(component.W(block*5+1), 0, true);
                    var y0_var = var(component.W(block * 5+2), 0, true);
                    var y1_var = var(component.W(block * 5+3), 0, true);
                    var alpha = var(component.W(block * 5+4), 0, true);

                    auto s = 2 * b * x - x;
                    auto left = ((alpha + s ) * y0_var - (alpha - s) * y1_var );// / (2 * s);
                    auto y1 = y1_var * b + (1-b) * y0_var;

                    var x_next = var(component.W(block * 5 + 5), 0, true);
                    var b_next = var(component.W(block * 5 + 6), 0, true);
                    var y0_next = var(component.W(block * 5 + 7), 0, true);
                    var y1_next = var(component.W(block * 5 + 8), 0, true);

                    auto right = (b_next * y0_next + (1 - b_next) * y1_next) * 2 * s;

                    constraints.emplace_back(left - right);
                }
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_flexible_colinear_checks<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_colinear_checks<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
/*
                using component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;
                using var = typename component_type::var;

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
            typename plonk_flexible_colinear_checks<BlueprintFieldType>::result_type generate_circuit(
                const plonk_flexible_colinear_checks<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_colinear_checks<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                assert(instance_input.ys.size() == instance_input.bs.size()*2);
                assert(instance_input.alphas.size() + 1 == instance_input.bs.size());

                using component_type = plonk_flexible_colinear_checks<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_colinear_checks_HPP
