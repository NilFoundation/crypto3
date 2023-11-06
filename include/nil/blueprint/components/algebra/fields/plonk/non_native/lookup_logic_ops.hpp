//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/boolean_lookup_op_component.hpp>

using nil::blueprint::components::detail::boolean_lookup_op_component;

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                The following logical operations perform checks on that input values are boolean.
            */


            template<typename ArithmetizationType>
            class lookup_logic_and;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class lookup_logic_and<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system< BlueprintFieldType, ArithmetizationParams>>
            {
                using lookup_table_definition = typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;

                class binary_and_table_type : public lookup_table_definition{
                public:
                    binary_and_table_type(): lookup_table_definition("binary_and_table"){
                        this->subtables["full"] = {{0,1,2}, 0, 3};
                    }
                    virtual void generate(){
                        this->_table = {
                            {0, 0, 1, 1},
                            {0, 1, 0, 1},
                            {0, 0, 0, 1}
                        };
                    }
                    virtual std::size_t get_columns_number(){ return 3; }
                    virtual std::size_t get_rows_number(){ return 4; }
                };

                using value_type = typename BlueprintFieldType::value_type;

            protected:
                std::shared_ptr<lookup_table_definition> binary_and_table;
            public:
                using component_type =
                    boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return lookup_logic_and::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                virtual crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> op_lookup_constraint(
                    const std::array<var, 2 + 1> &witnesses,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp
                ) const {
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> result;
                    bp.reserve_table("binary_and_table/full");
                    result.table_id = bp.get_reserved_indices().at("binary_and_table/full");
                    result.lookup_input = {witnesses[0], witnesses[1], witnesses[2]};
                    return result;
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] * input_values[1];
                }

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["binary_and_table/full"] = 0; // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename ContainerType>
                explicit lookup_logic_and(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                lookup_logic_and(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                lookup_logic_and(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

/*
            template<typename ArithmetizationType>
            class logic_or;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_or<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            : public boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_or::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_or(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_or(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_or(std::initializer_list<typename component_type::witness_container_type::value_type>
                               witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                               constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                               public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };
*/

            template<typename ArithmetizationType>
            class lookup_logic_xor;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class lookup_logic_xor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                             : public boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return lookup_logic_xor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                virtual crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> op_lookup_constraint(
                    const std::array<var, 2 + 1> &witnesses,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp
                ) const {
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> result;
                    bp.reserve_table("binary_xor_table/full");
                    result.table_id = bp.get_reserved_indices().at("binary_xor_table/full");
                    result.lookup_input = {witnesses[0], witnesses[1], witnesses[2]};
                    return result;
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return input_values[0] + input_values[1] - 2 * input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit lookup_logic_xor(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                lookup_logic_xor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                lookup_logic_xor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["binary_xor_table/full"] = 0; // REQUIRED_TABLE
                    return lookup_tables;
                }
            };

/*
            template<typename ArithmetizationType>
            class logic_nand;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_nand<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                             : public boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>> {

                constexpr static const std::uint32_t WitnessesAmount = 3;

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_nand::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - witnesses[0] * witnesses[1]);
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - input_values[0] * input_values[1];
                }

                template<typename ContainerType>
                explicit logic_nand(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nand(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_nand(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                           std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                           std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename ArithmetizationType>
            class logic_nor;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_nor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                             : public boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>> {

                using value_type = typename BlueprintFieldType::value_type;

            public:
                using component_type =
                    boolean_lookup_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams>>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return logic_nor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount);
                }

                virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, 3> &witnesses) const {
                    return witnesses[2] - (1 - (witnesses[0] + witnesses[1] - witnesses[0] * witnesses[1]));
                }

                virtual value_type result_assignment(const std::array<value_type, 2> &input_values) const {
                    return 1 - (input_values[0] + input_values[1] - input_values[0] * input_values[1]);
                }

                template<typename ContainerType>
                explicit logic_nor(ContainerType witness) : component_type(witness, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_nor(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_nor(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };*/
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_logic_OPS_HPP
