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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/boolean_op_component.hpp>

using nil::blueprint::components::detail::boolean_op_component;

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                The following logical operations do NOT perform any checks on the input values.
            */

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_not;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_not<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 2>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           2, 1> {

                constexpr static const std::uint32_t WitnessesAmount = 2;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 2, 1>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 2> &witnesses) const {
                    return 1 - witnesses[0] - witnesses[1];
                }

                virtual value_type result_assignment(const std::array<value_type, 1> &input_values) const {
                    return 1 - input_values[0];
                }

                template<typename ContainerType>
                logic_not(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_not(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_not(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };


            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_and;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_and<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           3, 2> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 3, 2>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - witnesses[0] * witnesses[1];
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                logic_and(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_and(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_and(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };


            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_or;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_or<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>
                            : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           3, 2> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 3, 2>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                logic_or(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_or(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_or(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };


            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_xor;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_xor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           3, 2> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 3, 2>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (witnesses[0] + witnesses[1] - 2 * witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - 2 * input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                logic_xor(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_xor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_xor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };


            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_nand;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_nand<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           3, 2> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 3, 2>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                logic_nand(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nand(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_nand(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_nor;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_nor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>
                             : public boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                           3, 2> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using component_type =
                    boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                         ArithmetizationParams>, 3, 2>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]));
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - (input_values[0] + input_values[1] - input_values[0] * input_values[1]);
                }

                template<typename ContainerType>
                logic_nor(ContainerType witness) : component_type(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_nor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP
