//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp> // also included by is_zero.hpp below
#include <nil/blueprint/bbf/is_zero.hpp>
#include <nil/blueprint/bbf/choice_function.hpp>
#include <nil/blueprint/bbf/carry_on_addition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class bbf_wrapper;

            template<typename BlueprintFieldType>
            class bbf_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return bbf_wrapper::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), // TODO: this has nothing to do with reality,
                        false                                                                // to be dropped eventually
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 3;
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 3;
                }

                constexpr static const std::size_t gates_amount = 5; // TODO: this is very unoptimized!
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "wrapper of BBF-components";

                struct input_type {
                    var x, q, cx[3], cy[3];

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, q, cx[0], cx[1], cx[2], cy[0], cy[1], cy[2]};
                    }
                };

                struct result_type {
                    result_type(const bbf_wrapper &component, std::size_t start_row_index) { }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit bbf_wrapper(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bbf_wrapper(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                bbf_wrapper(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_bbf_wrapper = bbf_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_bbf_wrapper<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_bbf_wrapper<BlueprintFieldType>  &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                    const typename plonk_bbf_wrapper<BlueprintFieldType>::input_type  instance_input,
                    const std::uint32_t  start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using Is_Zero = typename nil::blueprint::bbf::is_zero<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using Choice_Function = typename nil::blueprint::bbf::choice_function<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT,3>;
                using Carry_On_Addition = typename nil::blueprint::bbf::carry_on_addition<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT,3,16>;
                //using TYPE = typename Is_Zero::TYPE;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment, 8, start_row_index); // max_rows = 8

                Is_Zero c1 = Is_Zero(ct, var_value(assignment, instance_input.x));

                std::array<TYPE,3> input_x = {var_value(assignment,instance_input.cx[0]),
                                              var_value(assignment,instance_input.cx[1]),
                                              var_value(assignment,instance_input.cx[2])};
                std::array<TYPE,3> input_y = {var_value(assignment,instance_input.cy[0]),
                                              var_value(assignment,instance_input.cy[1]),
                                              var_value(assignment,instance_input.cy[2])};

                // ct.print_witness_allocation_log();

                std::vector<std::size_t> ct2_area = {2,3,4,5};
                context_type ct2 = ct.subcontext(ct2_area,0,4);
                Choice_Function c2 = Choice_Function(ct2, var_value(assignment,instance_input.q), input_x, input_y);

                // ct.print_witness_allocation_log();

                std::vector<std::size_t> ct3_area = {7,8,9,10,11};
                context_type ct3 = ct.subcontext(ct3_area,0,4);
                Carry_On_Addition c3 = Carry_On_Addition(ct3, input_x, input_y);

                // ct.print_witness_allocation_log();

                return typename plonk_bbf_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_bbf_wrapper<BlueprintFieldType>::result_type generate_circuit(
                const plonk_bbf_wrapper<BlueprintFieldType>  &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                const typename plonk_bbf_wrapper<BlueprintFieldType>::input_type  &instance_input,
                const std::size_t start_row_index) {

                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CIRCUIT>;
                using Is_Zero = typename nil::blueprint::bbf::is_zero<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CIRCUIT>;
                using Choice_Function = typename nil::blueprint::bbf::choice_function<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CIRCUIT,3>;
                using Carry_On_Addition = typename nil::blueprint::bbf::carry_on_addition<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CIRCUIT,3,16>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment,8,start_row_index); // max_rows = 8
                Is_Zero c1 = Is_Zero(ct, instance_input.x);

                std::array<TYPE,3> input_x = {instance_input.cx[0],instance_input.cx[1],instance_input.cx[2]};
                std::array<TYPE,3> input_y = {instance_input.cy[0],instance_input.cy[1],instance_input.cy[2]};

                std::vector<std::size_t> ct2_area = {2,3,4,5};
                context_type ct2 = ct.subcontext(ct2_area,0,4);
                Choice_Function c2 = Choice_Function(ct2, instance_input.q, input_x, input_y);

                std::vector<std::size_t> ct3_area = {7,8,9,10,11};
                context_type ct3 = ct.subcontext(ct3_area,0,4);
                Carry_On_Addition c3 = Carry_On_Addition(ct3, input_x, input_y);

                ct.optimize_gates();

                // compatibility layer: constraint list => gates & selectors
                std::vector<std::pair<std::vector<constraint_type>, std::set<std::size_t>>> constraint_list = ct.get_constraints();

                for(const auto& [constraints, row_list] : constraint_list) {
                    /*
                    std::cout << "GATE:\n";
                    for(const auto& c : constraints) {
                        std::cout << c << "\n";
                    }
                    std::cout << "Rows: ";
                    */
                    std::size_t selector_index = bp.add_gate(constraints);
                    for(std::size_t row_index : row_list) {
                        // std::cout << row_index << " ";
                        assignment.enable_selector(selector_index, row_index);
                    }
                    //std::cout << "\n";
                }

                // compatibility layer: copy constraint list
                std::vector<plonk_copy_constraint> copy_constraints = ct.get_copy_constraints();
                for(const auto& cc : copy_constraints) {
                    bp.add_copy_constraint(cc);
                }

                // compatibility layer: lookup constraint list
                std::vector<std::pair<std::vector<std::pair<std::string,std::vector<constraint_type>>>, std::set<std::size_t>>>
                lookup_constraints = ct.get_lookup_constraints();
                std::set<std::string> lookup_tables;
                for(const auto& [lookup_list, row_list] : lookup_constraints) {
                    std::vector<lookup_constraint_type> lookup_gate;
                    for(const auto& single_lookup_constraint : lookup_list) {
                        std::string table_name = single_lookup_constraint.first;
                        if (lookup_tables.find(table_name) == lookup_tables.end()) {
                            bp.reserve_table(table_name);
                            lookup_tables.insert(table_name);
                        }
                        std::size_t table_index = bp.get_reserved_indices().at(table_name);
                        lookup_gate.push_back({table_index,single_lookup_constraint.second});
                    }
                    std::size_t selector_index = bp.add_lookup_gate(lookup_gate);
                    for(std::size_t row_index : row_list) {
                        assignment.enable_selector(selector_index, row_index);
                    }
                }

                return typename plonk_bbf_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
