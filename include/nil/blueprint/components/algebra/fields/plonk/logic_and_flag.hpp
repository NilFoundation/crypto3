//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_AND_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_AND_FLAG_HPP


#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {


            /**
             * 
             * 
             * */
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount> 
            class logic_and_flag;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessesAmount>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>{

                // constexpr static const std::uint32_t WitnessesAmount = WitnessesAmount;
                

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;
                using value_type = typename BlueprintFieldType::value_type;
            public:
                using var = typename component_type::var;

                const std::size_t gates_amount = 1;
                const std::size_t rows_amount = 6 / WitnessesAmount;

                struct input_type{
                    var x;
                    var y;
                };

                struct result_type{
                    var output;

                    result_type(const logic_and_flag<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            WitnessesAmount> &component, std::uint32_t start_row_index){
                                output = var(component.W(WitnessesAmount-1), start_row_index+component.rows_amount - 1);   
                    }
                };

                template<typename ContainerType>
                logic_and_flag(ContainerType witness) : component_type(witness,std::array<std::uint32_t, 0>(),
                                                                                std::array<std::uint32_t, 0>()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_and_flag(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_and_flag(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount> 
                using plonk_logic_and_flag_component = logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, WitnessesAmount>;


                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>::result_type generate_assignments(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>& component, 
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                        std::size_t row = start_row_index;
    
                        typename BlueprintFieldType::value_type x = var_value(assignment, instance_input.x);
                        typename BlueprintFieldType::value_type y = var_value(assignment, instance_input.y);
                        typename BlueprintFieldType::value_type p = x*y;
                        typename BlueprintFieldType::value_type v = p.is_zero() ? p : p.inversed();
                        typename BlueprintFieldType::value_type f = p*v;
                        
                        assignment.witness(component.W(0), row) = x;
                        assignment.witness(component.W(1), row) = y;
                        
                        assignment.witness(component.W(0), row+1) = p;
                        assignment.witness(component.W(1), row+1) = v;

                        assignment.witness(component.W(0), row+2) = v-p;
                        assignment.witness(component.W(1), row+2) = f;

                        return typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>::result_type generate_assignments(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>& component, 
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                        std::size_t row = start_row_index;

                        typename BlueprintFieldType::value_type x = var_value(assignment, instance_input.x);
                        typename BlueprintFieldType::value_type y = var_value(assignment, instance_input.y);
                        typename BlueprintFieldType::value_type p = x*y;
                        typename BlueprintFieldType::value_type v = p.is_zero() ? p : p.inversed();
                        typename BlueprintFieldType::value_type f = p*v;
                        
                        assignment.witness(component.W(0), row) = x;
                        assignment.witness(component.W(1), row) = y;
                        assignment.witness(component.W(2), row) = p;
                        
                        assignment.witness(component.W(0), row+1) = v;
                        assignment.witness(component.W(1), row+1) = v-p;
                        assignment.witness(component.W(2), row+1) = f;

                        return typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>::result_type generate_assignments(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>& component, 
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                        std::size_t row = start_row_index;
    
                        typename BlueprintFieldType::value_type x = var_value(assignment, instance_input.x);
                        typename BlueprintFieldType::value_type y = var_value(assignment, instance_input.y);
                        typename BlueprintFieldType::value_type p = x*y;
                        typename BlueprintFieldType::value_type v = p.is_zero() ? p : p.inversed();
                        typename BlueprintFieldType::value_type f = p*v;
                        
                        assignment.witness(component.W(0), row) = x;
                        assignment.witness(component.W(1), row) = y;
                        assignment.witness(component.W(2), row) = p;
                        assignment.witness(component.W(3), row) = v;
                        assignment.witness(component.W(4), row) = f;

                        return typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_gates(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>::input_type &instance_input, 
                    const std::uint32_t first_selector_index
                ){
                    
                    using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 2>::var;
                    
                    auto constraint_1 = bp.add_constraint(var(component.W(0), 0) - var(component.W(0), -1) * var(component.W(1),-1));  // p =x*y
                    auto constraint_2 = bp.add_constraint(var(component.W(1), +1)*(var(component.W(1),+1) - 1));                       // f(f-1)=0
                    auto constraint_3 = bp.add_constraint(var(component.W(1), +1) - var(component.W(0), 0)*var(component.W(1),0));   // f = pv
                    auto constraint_4 = bp.add_constraint(var(component.W(0), +1) - (var(component.W(1), 0) - var(component.W(0),0))); // W1[2] = p-v
                    auto constraint_5 = bp.add_constraint(var(component.W(0), +1)*(var(component.W(1),+1) - 1));                       // (p-v)(f-1)=0

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_gates(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>::input_type &instance_input, 
                    const std::uint32_t first_selector_index
                ){
                    
                    using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 3>::var;
                    
                    auto constraint_1 = bp.add_constraint(var(component.W(2), 0) - var(component.W(0), 0) * var(component.W(1),0));  // p =x*y
                    auto constraint_2 = bp.add_constraint(var(component.W(2), +1)*(var(component.W(2),+1) - 1));                       // f(f-1)=0
                    auto constraint_3 = bp.add_constraint(var(component.W(2), +1) - var(component.W(0), +1)*var(component.W(2),0));   // f = pv
                    auto constraint_4 = bp.add_constraint(var(component.W(1), +1) - (var(component.W(0), +1) - var(component.W(2),0))); // W1[2] = v-p
                    auto constraint_5 = bp.add_constraint(var(component.W(1), +1)*(var(component.W(2),+1) - 1));                       // (v-p)(f-1)=0

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_gates(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>::input_type &instance_input, 
                    const std::uint32_t first_selector_index
                ){
                    
                    using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, 5>::var;
                    
                    auto constraint_1 = bp.add_constraint(var(component.W(2), 0) - var(component.W(0), 0) * var(component.W(1),0));  // p =x*y
                    auto constraint_2 = bp.add_constraint(var(component.W(4), 0)*(var(component.W(4),0) - 1));                       // f(f-1)=0
                    auto constraint_3 = bp.add_constraint(var(component.W(4), 0) - var(component.W(2), 0)*var(component.W(3),0));   // f = pv
                    auto constraint_4 = bp.add_constraint((var(component.W(3), 0) - var(component.W(2),0))*(var(component.W(4),0) - 1)); // (v-p)(f-1)=0

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                void generate_copy_constraints(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                    
                    std::size_t row = start_row_index;
                    using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::var;

                    bp.add_copy_constraint({var(component.W(0), row, false), instance_input.x});
                    bp.add_copy_constraint({var(component.W(1), row, false), instance_input.y});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::result_type generate_circuit(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>& component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment, 
                    const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::input_type &instance_input, 
                    const std::uint32_t start_row_index){

                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }
                    
                    assignment.enable_selector(first_selector_index, start_row_index + (WitnessesAmount == 2 ?  1 : 0));
                    
                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                    return typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::result_type(component, start_row_index);
                }
        }
    }
}

#endif CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_logic_AND_FLAG_HPP