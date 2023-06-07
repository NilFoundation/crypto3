//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_OR_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_OR_FLAG_HPP


#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount> 
            class logic_or_flag;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_or_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 7>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       7, 0, 0>{

                constexpr static const std::uint32_t WitnessesAmount = 7;
                

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 7, 0, 0>;
                using value_type = typename BlueprintFieldType::value_type;
            public:
                using var = typename component_type::var;

                const std::size_t gates_amount = 1;

                struct input_type{
                    var x;
                    var y;
                };

                struct result_type{
                    var output;

                    result_type(const logic_or_flag<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            WitnessesAmount> &component, std::uint32_t start_row_index){
                                output = var(component.W(6), start_row_index);
                    }
                };

                template<typename ContainerType>
                logic_or_flag(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_or_flag(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_or_flag(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount> 
                using plonk_logic_or_flag_component = logic_or_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessesAmount>;


                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::result_type generate_assignments(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>& component, 
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                        std::size_t row = start_row_index;

                        typename BlueprintFieldType::value_type x = var_value(assignment, instance_input.x);
                        typename BlueprintFieldType::value_type y = var_value(assignment, instance_input.y);
                        typename BlueprintFieldType::value_type vx = x.is_zero() ? x : x.inversed();
                        typename BlueprintFieldType::value_type vy = y.is_zero() ? y : y.inversed();
                        typename BlueprintFieldType::value_type fx = x*vx;
                        typename BlueprintFieldType::value_type fy = y*vy;
                        typename BlueprintFieldType::value_type f = fx +fy - fx*fy;
                        
                        assignment.witness(component.W(0), row) = x;
                        assignment.witness(component.W(1), row) = y;
                        assignment.witness(component.W(2), row) = vx;
                        assignment.witness(component.W(3), row) = vy;
                        assignment.witness(component.W(4), row) = fx;
                        assignment.witness(component.W(5), row) = fy;
                        assignment.witness(component.W(6), row) = f;

                        return typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_gates(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::input_type &instance_input, 
                    const std::uint32_t first_selector_index
                ){
                    
                    using var = typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::var;
                    

                    auto constraint_1 = bp.add_constraint(var(component.W(4), 0) - var(component.W(2), 0) * var(component.W(0),0));  // fx =x*vx
                    auto constraint_2 = bp.add_constraint(var(component.W(5), 0) - var(component.W(3), 0) * var(component.W(1),0));  // fy =y*vy
                   
                    auto constraint_3 = bp.add_constraint(var(component.W(4), 0)*(var(component.W(4),0) - 1));                       // fx(fx-1)=0
                    auto constraint_4 = bp.add_constraint(var(component.W(5), 0)*(var(component.W(5),0) - 1));                       // fy(fy-1)=0

                    auto constraint_5 = bp.add_constraint((var(component.W(2), 0) - var(component.W(0),0))*(var(component.W(4),0) - 1));  // (vx-x)(fx-1)=0
                    auto constraint_6 = bp.add_constraint((var(component.W(3), 0) - var(component.W(1),0))*(var(component.W(5),0) - 1));  // (vy-y)(fy-1)=0

                    auto constraint_7 = bp.add_constraint(var(component.W(6), 0) - var(component.W(4), 0) - var(component.W(5), 0) + var(component.W(4), 0)*var(component.W(5), 0));
                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6, constraint_7});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_copy_constraints(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                    std::size_t row = start_row_index;
                    using var = typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::var;

                    bp.add_copy_constraint({var(component.W(0), row, false), instance_input.x});
                    bp.add_copy_constraint({var(component.W(1), row, false), instance_input.y});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::result_type generate_circuit(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }
                    assignment.enable_selector(first_selector_index, start_row_index);

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                    return typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, 7>::result_type(component, start_row_index);
                }
        }
    }
}

#endif CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_OR_FLAG_HPP