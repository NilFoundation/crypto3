
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, typename FieldType>
            class zkevm_copy;

            template<typename BlueprintFieldType>
            class zkevm_copy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                // Named witness columns
                // Named witness columns indices
                constexpr static std::size_t IS_FIRST = 0;
                constexpr static std::size_t ID_LO = 1;
                constexpr static std::size_t ID_HI = 2;
                constexpr static std::size_t ADDR = 3;
                constexpr static std::size_t SRC_ADDR_END = 4;
                constexpr static std::size_t BYTE_LEFT = 5;
                constexpr static std::size_t RLC_ACC = 6; // For keccak. Not sure it is necessary
                constexpr static std::size_t RW_COUNTER = 7;
                constexpr static std::size_t RWC_INC_LEFT = 8;
                constexpr static std::size_t TAG = 9;

                // Advice columns
                // Selectors for row types. Just for lookup constraint degree decreasing
                constexpr static std::size_t IS_MEMORY = 10;
                constexpr static std::size_t IS_BYTECODE = 11;
                constexpr static std::size_t IS_TX_CALLDATA = 12;
                constexpr static std::size_t IS_TX_LOG = 13;
                constexpr static std::size_t IS_KECCAK = 14;
                constexpr static std::size_t IS_PADDING = 15;

                constexpr static std::size_t IS_LAST = 16;
                constexpr static std::size_t Q_STEP = 17; // Maybe throw it to static selectors
                constexpr static std::size_t RW_DIFF = 18;
                constexpr static std::size_t VALUE = 19; // Byte value

                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_copy_size; // TODO: Estimate default value. It should have reasonable default value

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return zkevm_copy::gates_amount + zkevm_copy::lookup_gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_copy_size= 3000) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(11)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_copy_size= 3000) {
                    return max_copy_size;
                }

                constexpr static const std::size_t gates_amount = 1;
                constexpr static const std::size_t lookup_gates_amount = 0; // Change when dynamic lookups will be implemented
                std::size_t rows_amount = get_rows_amount(max_copy_size);

                struct input_type {
                    const std::vector<copy_event> &copy_events;

                    input_type(
                        const std::vector<copy_event> &_copy_events
                    ) : copy_events(_copy_events) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                struct result_type {
                    result_type(const zkevm_copy &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit zkevm_copy(ContainerType witness, std::size_t _max_copy_size =1000) :
                    component_type(witness, {}, {}, get_manifest()), max_copy_size(_max_copy_size)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                zkevm_copy(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _max_copy_size =1000
                ) : component_type(witness, constant, public_input, get_manifest()), max_copy_size(_max_copy_size) {};

                zkevm_copy(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _max_copy_size =1000
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_copy_size(_max_copy_size){};


                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_zkevm_copy =
                zkevm_copy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_copy<BlueprintFieldType>::result_type generate_assignments(
                const plonk_zkevm_copy<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_copy<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_zkevm_copy<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                std::cout << "Generate assignments" << std::endl;
                std::cout << "Start row index: " << start_row_index << std::endl;

                std::size_t cur = start_row_index;

                for( std::size_t id = 0; id < instance_input.copy_events.size(); id++){
                    auto &copy_event = instance_input.copy_events[id];
                    std::size_t rw_counter_src = 0;
                    std::size_t rw_counter_dst = 0;
                    std::size_t rw_diff_src = 0;
                    std::size_t rw_diff_dst = 0;
                    if( copy_event.source_type == MEMORY_COPY  || copy_event.source_type == TX_LOG_COPY ){
                        rw_diff_src = 1;
                        rw_counter_src = copy_event.initial_rw_counter;
                        if( copy_event.destination_type == MEMORY_COPY  || copy_event.destination_type == TX_LOG_COPY ) {
                            rw_counter_dst = copy_event.initial_rw_counter + copy_event.length;
                            rw_diff_dst = 1;
                        }
                    } else if ( copy_event.destination_type == MEMORY_COPY  || copy_event.destination_type == TX_LOG_COPY ){
                        rw_counter_dst = copy_event.initial_rw_counter;
                        rw_diff_dst = 1;
                    }
                    for( std::size_t i = 0; i < copy_event.bytes.size(); i++, cur+=2 ){
                        assignment.witness(component.W(component_type::IS_FIRST), cur) = ((i == 0) ? 1: 0 );
                        assignment.witness(component.W(component_type::IS_FIRST), cur+1) = 0;
                        assignment.witness(component.W(component_type::IS_LAST), cur) = 0;
                        assignment.witness(component.W(component_type::IS_LAST), cur+1) = ((i == (copy_event.bytes.size() - 1)) ? 1: 0 );
                        assignment.witness(component.W(component_type::Q_STEP), cur) = 0;
                        assignment.witness(component.W(component_type::Q_STEP), cur+1) = 1;
                        assignment.witness(component.W(component_type::TAG), cur) = copy_event.source_type;
                        assignment.witness(component.W(component_type::TAG), cur+1) = copy_event.destination_type;
                        assignment.witness(component.W(component_type::IS_MEMORY), cur) = (copy_event.source_type == MEMORY_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_MEMORY), cur+1) = (copy_event.destination_type == MEMORY_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_BYTECODE), cur) = (copy_event.source_type == BYTECODE_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_BYTECODE), cur+1) = (copy_event.destination_type == BYTECODE_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_TX_CALLDATA), cur) = (copy_event.source_type == TX_CALLDATA_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_TX_CALLDATA), cur+1) = (copy_event.destination_type == TX_CALLDATA_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_TX_LOG), cur) = (copy_event.source_type == TX_LOG_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_TX_LOG), cur+1) = (copy_event.destination_type == TX_LOG_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_KECCAK), cur) = (copy_event.source_type == KECCAK_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::IS_KECCAK), cur+1) = (copy_event.destination_type == KECCAK_COPY ? 1 : 0);
                        assignment.witness(component.W(component_type::VALUE), cur) = assignment.witness(component.W(component_type::VALUE), cur + 1) = copy_event.bytes[i];
/*                      if(copy_event.source_type == MEMORY_COPY && copy_event.destination_type == MEMORY_COPY){
                            std::cout << "MCOPY implementation" << std::endl;
                            exit(2);
                        } else if (copy_event.source_type == MEMORY_COPY)
                            assignment.witness(component.W(component_type::RW_COUNTER), cur) = copy_event.initial_rw_counter + i;
                        else if(copy_event.destination_type == MEMORY_COPY)
                            assignment.witness(component.W(component_type::RW_COUNTER), cur) = copy_event.initial_rw_counter + i;*/
                        assignment.witness(component.W(component_type::BYTE_LEFT), cur) = assignment.witness(component.W(component_type::BYTE_LEFT), cur + 1) = copy_event.length - i;
                        assignment.witness(component.W(component_type::RW_DIFF), cur) = rw_diff_src;
                        assignment.witness(component.W(component_type::RW_DIFF), cur + 1) = rw_diff_dst;
                        assignment.witness(component.W(component_type::RW_COUNTER), cur) = rw_counter_src + i * rw_diff_src;
                        assignment.witness(component.W(component_type::RW_COUNTER), cur + 1) = rw_counter_dst + i * rw_diff_dst;
                        assignment.witness(component.W(component_type::ID_HI), cur) = w_hi<BlueprintFieldType>(copy_event.source_id);
                        assignment.witness(component.W(component_type::ID_LO), cur) = w_lo<BlueprintFieldType>(copy_event.source_id);
                        assignment.witness(component.W(component_type::ID_HI), cur + 1) = w_hi<BlueprintFieldType>(copy_event.destination_id);
                        assignment.witness(component.W(component_type::ID_LO), cur + 1) = w_lo<BlueprintFieldType>(copy_event.destination_id);
                    }
                    std::cout << std::endl;
                }

                //padding
                for (; cur < start_row_index + component.rows_amount; cur += 2 ){
                    assignment.witness(component.W(component_type::Q_STEP), cur) = 0;
                    assignment.witness(component.W(component_type::Q_STEP), cur+1) = 1;
                    assignment.witness(component.W(component_type::TAG), cur) = PADDING_COPY;
                    assignment.witness(component.W(component_type::TAG), cur+1) = PADDING_COPY;
                    assignment.witness(component.W(component_type::IS_PADDING), cur) = 1;
                    assignment.witness(component.W(component_type::IS_PADDING), cur+1) = 1;
                }

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_zkevm_copy<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_copy<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
            ) {
                using component_type = plonk_zkevm_copy<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                std::vector<constraint_type> constraints;
                std::vector<constraint_type> constraints2;
                std::vector<lookup_constraint_type> lookup_constraints;

                var is_first = var(component.W(component_type::IS_FIRST), 0, true);
                var is_first_prev = var(component.W(component_type::IS_FIRST), -1, true);
                var is_last = var(component.W(component_type::IS_LAST), 0, true);
                var is_last_prev = var(component.W(component_type::IS_LAST), -1, true);
                var is_last_next = var(component.W(component_type::IS_LAST), 1, true);
                var q_step = var(component.W(component_type::Q_STEP), 0, true);
                var q_step_prev = var(component.W(component_type::Q_STEP), -1, true);
                var tag = var(component.W(component_type::TAG), 0, true);
                var tag_prev = var(component.W(component_type::TAG), -1, true);
                var tag_next = var(component.W(component_type::TAG), +1, true);
                var value = var(component.W(component_type::VALUE), 0, true);
                var value_prev = var(component.W(component_type::VALUE), -1, true);
                var rw_counter = var(component.W(component_type::RW_COUNTER), 0, true);
                var rw_counter_prev = var(component.W(component_type::RW_COUNTER), -1, true);
                var rw_counter_next = var(component.W(component_type::RW_COUNTER), +1, true);
                var byte_left = var(component.W(component_type::BYTE_LEFT), 0, true);
                var byte_left_prev = var(component.W(component_type::BYTE_LEFT), -1, true);
                var rw_diff = var(component.W(component_type::RW_DIFF), 0, true);
                var rw_diff_prev = var(component.W(component_type::RW_DIFF), -1, true);
                var id_hi = var(component.W(component_type::ID_HI), 0, true);
                var id_lo = var(component.W(component_type::ID_LO), 0, true);
                var id_hi_prev = var(component.W(component_type::ID_HI), -1, true);
                var id_lo_prev = var(component.W(component_type::ID_LO), -1, true);
                var id_hi_next = var(component.W(component_type::ID_HI), 1, true);
                var id_lo_next = var(component.W(component_type::ID_LO), 1, true);
                var is_memory = var(component.W(component_type::IS_MEMORY), 0, true);
                var is_bytecode = var(component.W(component_type::IS_BYTECODE), 0, true);
                var is_tx_calldata = var(component.W(component_type::IS_TX_CALLDATA), 0, true);
                var is_tx_log = var(component.W(component_type::IS_TX_LOG), 0, true);
                var is_keccak = var(component.W(component_type::IS_KECCAK), 0, true);
                var is_padding = var(component.W(component_type::IS_PADDING), 0, true);
                var is_padding_prev = var(component.W(component_type::IS_PADDING), -1, true);

                // is_first and is_last are dynamic selectors
                constraints.push_back(is_first* (1 - is_first));
                constraints.push_back(is_last* (1 - is_last));

                // q_step is 0 -- for "source" rows, 1 for "destination" rows
                constraints.push_back(q_step* (1 - q_step));
                constraints.push_back(is_first * q_step);
                constraints.push_back(is_last * (1 - q_step));
                constraints.push_back((tag - PADDING_COPY) * (1 - is_first) * (q_step + q_step_prev - 1));

                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * (tag - PADDING_COPY));
                constraints.push_back((1 - is_memory) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * (tag - PADDING_COPY));
                constraints.push_back((tag - MEMORY_COPY) * (1 - is_bytecode) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * (tag - PADDING_COPY));
                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (1 - is_tx_calldata) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * (tag - PADDING_COPY));
                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (1 - is_tx_log) * (tag - KECCAK_COPY) * (tag - PADDING_COPY));
                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (1 - is_keccak) * (tag - PADDING_COPY));
                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * (1 - is_padding));
                constraints.push_back((tag - MEMORY_COPY) * is_memory);
                constraints.push_back((tag - BYTECODE_COPY) * is_bytecode);
                constraints.push_back((tag - TX_CALLDATA_COPY) * is_tx_calldata);
                constraints.push_back((tag - TX_LOG_COPY) * is_tx_log);
                constraints.push_back((tag - KECCAK_COPY) * is_keccak);
                constraints.push_back((tag - PADDING_COPY) * is_padding);

                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * is_first);
                constraints.push_back((tag - MEMORY_COPY) * (tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - TX_LOG_COPY) * (tag - KECCAK_COPY) * is_last);
                constraints.push_back(q_step * (value - value_prev));
                constraints.push_back(q_step * (byte_left_prev - byte_left));
                constraints.push_back((1 - is_first) * (1 - q_step) * (tag - PADDING_COPY) * (byte_left_prev - byte_left - 1));
                constraints.push_back(is_last * (byte_left - 1));
                constraints.push_back((tag - MEMORY_COPY) * (tag - TX_LOG_COPY) * rw_diff);
                constraints.push_back((tag - BYTECODE_COPY) * (tag - TX_CALLDATA_COPY) * (tag - KECCAK_COPY) * (tag - PADDING_COPY) * (1 - rw_diff));
                constraints.push_back((tag - PADDING_COPY) * (1 - is_first) * (1 - is_last) * (rw_counter_next - rw_counter_prev - rw_diff_prev));
                constraints.push_back((1 - is_first) * (1 - is_last) * (id_hi_next - id_hi_prev) * (1 - is_padding));
                constraints.push_back((1 - is_first) * (1 - is_last) * (id_lo_next - id_lo_prev) * (1 - is_padding));
                constraints.push_back(is_first * is_padding * (1 - is_padding_prev) * (1 - is_last_prev));


                std::size_t selector_id = bp.add_gate(constraints);
                return selector_id;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_zkevm_copy<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_copy<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                // TODO: add copy constraints
            }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_copy<BlueprintFieldType>::result_type generate_circuit(
                const plonk_zkevm_copy<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_copy<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                std::cout << "Generate circuit" << std::endl;

                using component_type = plonk_zkevm_copy<BlueprintFieldType>;

                std::size_t selector = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());

                assignment.enable_selector(selector, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }
    }
}