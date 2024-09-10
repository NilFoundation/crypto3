//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_TABLE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_TABLE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/blueprint/components/hashes/keccak/util.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class keccak_table;

            template<typename BlueprintFieldType>
            class keccak_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_blocks;

                struct keccak_table_map {
                    var is_last;
                    var hash_hi;
                    var hash_lo;
                    var RLC;

                    keccak_table_map(const keccak_table &component){
                        is_last = var(component.W(0), 0);
                        RLC = var(component.W(1), 0);
                        hash_hi = var(component.W(2), 0);
                        hash_lo = var(component.W(3), 0);
                    }
                };

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_blocks) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(4)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_blocks) {
                    return max_blocks;
                }

                constexpr static const std::size_t gates_amount = 0;
                constexpr static const std::size_t lookup_gates_amount = 0;
                std::size_t rows_amount = max_blocks;

                struct input_type {
                    var rlc_challenge;
                    std::vector<std::tuple<
                        std::vector<std::uint8_t>,
                        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
                    >> input;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        res.push_back(rlc_challenge);
                        return res;
                    }
                };

                struct result_type {
                    result_type(const keccak_table &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit keccak_table(ContainerType witness, std::size_t _max_blocks) :
                    component_type(witness, {}, {}, get_manifest()), max_blocks(_max_blocks)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_table(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _max_blocks
                ) : component_type(witness, constant, public_input, get_manifest()), max_blocks(_max_blocks) {};

                keccak_table(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _max_blocks
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_blocks(_max_blocks){};
            };

            template<typename BlueprintFieldType>
            using plonk_keccak_table =
                keccak_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_keccak_table<BlueprintFieldType>::result_type generate_assignments(
                const plonk_keccak_table<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_keccak_table<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                value_type theta = var_value(assignment, instance_input.rlc_challenge);
                std::size_t input_idx = 0;
                std::size_t block_counter = 0;
                std::vector<std::uint8_t> msg;
                std::pair<value_type, value_type> hash;
                typename component_type::keccak_table_map t(component);
                std::cout << "Keccak table generate assignments" << std::endl;
                while( block_counter < component.max_blocks ) {
                    if( input_idx < instance_input.input.size() ){
                        msg = std::get<0>(instance_input.input[input_idx]);
                        hash = std::get<1>(instance_input.input[input_idx]);
                        input_idx++;
                    } else {
                        msg = {0};
                        hash = {0xbc36789e7a1e281436464229828f817d_cppui_modular254, 0x6612f7b477d66591ff96a9e064bcc98a_cppui_modular254};
                    }
                    value_type RLC = calculateRLC<BlueprintFieldType>(msg, theta);
                    for( std::size_t block = 0; block < std::ceil(float(msg.size() + 1)/136); block++){
                        if( block != std::ceil(float(msg.size() + 1)/136) - 1){
                            std::cout << "0 ";
                            assignment.witness(t.is_last.index, start_row_index + block_counter) = 0;
                        } else {
                            std::cout << "1 ";
                            assignment.witness(t.is_last.index, start_row_index + block_counter) = 1;
                        }
                        std::cout << std::hex << RLC << " " << hash.first << " " << hash.second << std::dec << std::endl;
                        assignment.witness(t.RLC.index, start_row_index + block_counter) = RLC;
                        assignment.witness(t.hash_hi.index, start_row_index + block_counter) = hash.first;
                        assignment.witness(t.hash_lo.index, start_row_index + block_counter) = hash.second;
                        block_counter++;
                    }
                }
                std::cout << "Keccak table assignments generated" << std::endl;
                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            typename plonk_keccak_table<BlueprintFieldType>::result_type generate_circuit(
                const plonk_keccak_table<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_keccak_table<BlueprintFieldType>;
                using var = typename component_type::var;

                bp.register_dynamic_table("keccak_table");
                std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                assignment.enable_selector(selector_index, start_row_index, start_row_index + component.rows_amount - 1);

                crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> keccak_table;
                typename component_type::keccak_table_map t(component);

                keccak_table.tag_index = selector_index;
                keccak_table.columns_number =  4;//
                keccak_table.lookup_options = {{
                    t.is_last,
                    t.RLC,
                    t.hash_hi,
                    t.hash_lo
                }};
                bp.define_dynamic_table("keccak_table", keccak_table);

                return typename component_type::result_type(component, start_row_index);
            }
        }
    }
}
#endif