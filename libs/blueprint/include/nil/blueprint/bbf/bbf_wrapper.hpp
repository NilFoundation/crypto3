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
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), // TODO
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 3;
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 3;
                }

                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "wrapper of BBF-components";

                struct input_type {
                    var x = var(0, 0, false); // TODO
                    var y = var(0, 0, false); // TODO

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, y};
                    }
                };

                struct result_type {
                    // TODO: probably no result at all
                    // var output = var(0, 0, false);

                    result_type(const bbf_wrapper &component, std::size_t start_row_index) {
                        // output = var(component.W(2), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        // return {output};
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
                using TYPE = typename Is_Zero::TYPE;

                context_type ct = context_type(assignment, 8, start_row_index); // max_rows = 8
                Is_Zero gc = Is_Zero(ct, var_value(assignment, instance_input.x));

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
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;

                context_type ct = context_type(assignment,8,start_row_index); // max_rows = 8
                Is_Zero gc = Is_Zero(ct, instance_input.x);

                gc.optimize_gates();

                // compatibility layer: constraint list => gates & selectors
                std::vector<std::pair<std::vector<constraint_type>, std::set<std::size_t>>> constraint_list = gc.poly_constraints();

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
                std::vector<plonk_copy_constraint> copy_constraints = gc.copy_constraints();
                for(const auto& cc : copy_constraints) {
                    bp.add_copy_constraint(cc);
                }

                return typename plonk_bbf_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
