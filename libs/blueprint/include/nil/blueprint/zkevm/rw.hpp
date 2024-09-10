
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

#include <nil/blueprint/zkevm/memory.hpp>
#include <nil/blueprint/zkevm/util/bit_tags.hpp>
#include <nil/blueprint/zkevm/util/chunks16.hpp>
#include <nil/blueprint/zkevm/util/lexicographic.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, typename FieldType>
            class zkevm_rw;

            template<typename BlueprintFieldType>
            class zkevm_rw<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                // Named witness columns
                // Named witness columns indices
                static constexpr std::size_t OP = 0;
                static constexpr std::size_t ID = 1;
                static constexpr std::size_t ADDRESS = 2;
                static constexpr std::size_t STORAGE_KEY_HI = 3;
                static constexpr std::size_t STORAGE_KEY_LO = 4;
                static constexpr std::size_t FIELD_TYPE = 5; // NOT USED FOR STACK, MEMORY and ACCOUNT STORAGE, but used by txComponent.
                static constexpr std::size_t RW_ID = 6;
                static constexpr std::size_t IS_WRITE = 7;
                static constexpr std::size_t VALUE_HI = 8;
                static constexpr std::size_t VALUE_LO = 9;

                // Advice columns
                static constexpr std::size_t OP_SELECTORS_AMOUNT = 4; // index \in {0..31}
                static constexpr std::array<std::size_t, OP_SELECTORS_AMOUNT> OP_SELECTORS = {10, 11, 12, 13};

                static constexpr std::size_t INDICES_AMOUNT = 5; // index \in {0..31}
                static constexpr std::array<std::size_t, INDICES_AMOUNT> INDICES = {14, 15, 16, 17, 18};

                static constexpr std::size_t IS_FIRST = 19;

                static constexpr std::size_t CHUNKS_AMOUNT = 30;
                static constexpr std::array< std::size_t, CHUNKS_AMOUNT> CHUNKS = {
                        20, 21, 22, 23, 24, 25, 26,
                    27, 28, 29, 30, 31, 32, 33, 34,
                    35, 36, 37, 38, 39, 40, 41, 42,
                    43, 44, 45, 46, 47, 48, 49
                };

                static constexpr std::size_t DIFFERENCE = 50;
                static constexpr std::size_t INV_DIFFERENCE = 51;
                static constexpr std::size_t VALUE_BEFORE_HI = 52;          // Check, where do we need it.
                static constexpr std::size_t VALUE_BEFORE_LO = 53;          // Check, where do we need it.
                static constexpr std::size_t STATE_ROOT_HI = 54;            // Check, where do we need it.
                static constexpr std::size_t STATE_ROOT_LO = 55;            // Check, where do we need it.
                static constexpr std::size_t STATE_ROOT_BEFORE_HI = 56;            // Check, where do we need it.
                static constexpr std::size_t STATE_ROOT_BEFORE_LO = 57;            // Check, where do we need it.
                static constexpr std::size_t IS_LAST = 58;

                static constexpr std::size_t SORTED_COLUMNS_AMOUNT = 32;

                static constexpr std::size_t total_witness_amount = 60;

                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_rw_size; // TODO: Estimate default value. It should have reasonable default value

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return zkevm_rw::gates_amount + zkevm_rw::lookup_gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_rw_size= 10000) {
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

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_rw_size= 10000) {
                    return max_rw_size;
                }

                constexpr static const std::size_t gates_amount = 2;
                constexpr static const std::size_t lookup_gates_amount = 1;
                std::size_t rows_amount = get_rows_amount(max_rw_size);

                struct input_type {
                    const rw_trace<BlueprintFieldType> &rws;

                    input_type(
                        const rw_trace<BlueprintFieldType> &_rws
                    ) : rws(_rws) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                struct result_type {
                    result_type(const zkevm_rw &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit zkevm_rw(ContainerType witness, std::size_t _max_rw_size =5000) :
                    component_type(witness, {}, {}, get_manifest()), max_rw_size(_max_rw_size)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                zkevm_rw(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _max_rw_size =5000
                ) : component_type(witness, constant, public_input, get_manifest()), max_rw_size(_max_rw_size) {};

                zkevm_rw(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _max_rw_size =5000
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_rw_size(_max_rw_size){};


                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["chunk_16_bits/full"] = 0; // REQUIRED_TABLE -- used for memory operations
                    lookup_tables["chunk_16_bits/8bits"] = 0; // REQUIRED_TABLE -- used for memory operations
                    lookup_tables["chunk_16_bits/10bits"] = 0; // REQUIRED_TABLE -- used for memory operations

                    return lookup_tables;
                }
            };

            template <typename ComponentType>
            std::vector<std::size_t> sorting_columns(const ComponentType &component){
                std::vector<std::size_t> sorting;

                sorting.resize(ComponentType::SORTED_COLUMNS_AMOUNT);
                sorting[0] = component.W(ComponentType::OP);
                // ID
                sorting[1] = component.W(ComponentType::CHUNKS[0]);
                sorting[2] = component.W(ComponentType::CHUNKS[1]);
                // address
                sorting[3] = component.W(ComponentType::CHUNKS[2]);
                sorting[4] = component.W(ComponentType::CHUNKS[3]);
                sorting[5] = component.W(ComponentType::CHUNKS[4]);
                sorting[6] = component.W(ComponentType::CHUNKS[5]);
                sorting[7] = component.W(ComponentType::CHUNKS[6]);
                sorting[8] = component.W(ComponentType::CHUNKS[7]);
                sorting[9] = component.W(ComponentType::CHUNKS[8]);
                sorting[10] = component.W(ComponentType::CHUNKS[9]);
                sorting[11] = component.W(ComponentType::CHUNKS[10]);
                sorting[12] = component.W(ComponentType::CHUNKS[11]);
                // field
                sorting[13] = component.W(ComponentType::FIELD_TYPE);
                // storage_key
                sorting[14] = component.W(ComponentType::CHUNKS[12]);
                sorting[15] = component.W(ComponentType::CHUNKS[13]);
                sorting[16] = component.W(ComponentType::CHUNKS[14]);
                sorting[17] = component.W(ComponentType::CHUNKS[15]);
                sorting[18] = component.W(ComponentType::CHUNKS[16]);
                sorting[19] = component.W(ComponentType::CHUNKS[17]);
                sorting[20] = component.W(ComponentType::CHUNKS[18]);
                sorting[21] = component.W(ComponentType::CHUNKS[19]);
                sorting[22] = component.W(ComponentType::CHUNKS[20]);
                sorting[23] = component.W(ComponentType::CHUNKS[21]);
                sorting[24] = component.W(ComponentType::CHUNKS[22]);
                sorting[25] = component.W(ComponentType::CHUNKS[23]);
                sorting[26] = component.W(ComponentType::CHUNKS[24]);
                sorting[27] = component.W(ComponentType::CHUNKS[25]);
                sorting[28] = component.W(ComponentType::CHUNKS[26]);
                sorting[29] = component.W(ComponentType::CHUNKS[27]);
                // rw_id
                sorting[30] = component.W(ComponentType::CHUNKS[28]);
                sorting[31] = component.W(ComponentType::CHUNKS[29]);

                return sorting;
            }

            template<typename BlueprintFieldType>
            using plonk_zkevm_rw =
                zkevm_rw<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_rw<BlueprintFieldType>::result_type generate_assignments(
                const plonk_zkevm_rw<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_rw<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {
                using component_type = plonk_zkevm_rw<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using integral_type =  boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                std::cout << "Generate assignments" << std::endl;
                std::cout << "Start row index: " << start_row_index << std::endl;

                auto sorting = sorting_columns<component_type>(component);
                auto rw_trace = instance_input.rws.get_rw_ops();
                for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                    if( rw_trace[i].op != PADDING_OP ) std::cout << i << "." << rw_trace[i] << " ";
                    // Lookup columns
                    assignment.witness(component.W(component_type::OP), start_row_index + i) = rw_trace[i].op;
                    assignment.witness(component.W(component_type::ID), start_row_index + i) = rw_trace[i].id;
                    assignment.witness(component.W(component_type::ADDRESS), start_row_index + i) = integral_type(rw_trace[i].address);
                    assignment.witness(component.W(component_type::STORAGE_KEY_HI), start_row_index + i) = w_hi<BlueprintFieldType>(rw_trace[i].storage_key);
                    assignment.witness(component.W(component_type::STORAGE_KEY_LO), start_row_index + i) = w_lo<BlueprintFieldType>(rw_trace[i].storage_key);
                    assignment.witness(component.W(component_type::RW_ID), start_row_index + i) = rw_trace[i].rw_id;
                    assignment.witness(component.W(component_type::IS_WRITE), start_row_index + i) = rw_trace[i].is_write;
                    assignment.witness(component.W(component_type::VALUE_HI), start_row_index + i) = w_hi<BlueprintFieldType>(rw_trace[i].value);
                    assignment.witness(component.W(component_type::VALUE_LO), start_row_index + i) = w_lo<BlueprintFieldType>(rw_trace[i].value);

                    // Op selectors
                    typename BlueprintFieldType::integral_type mask = (1 << component_type::OP_SELECTORS_AMOUNT);
                    for( std::size_t j = 0; j < component_type::OP_SELECTORS_AMOUNT; j++){
                        mask >>= 1;
                        assignment.witness(component.W(component_type::OP_SELECTORS[j]), start_row_index + i) = (((rw_trace[i].op & mask) == 0) ? 0 : 1);
                    }

                    // Fill chunks.
                    // id
                    mask = 0xffff;
                    mask <<= 16;
                    assignment.witness(component.W(component_type::CHUNKS[0]), start_row_index + i) = (mask & integral_type(rw_trace[i].id)) >> 16;
                    mask >>= 16;
                    assignment.witness(component.W(component_type::CHUNKS[1]), start_row_index + i) = (mask & integral_type(rw_trace[i].id));

                    // address
                    mask = 0xffff;
                    mask <<= (16 * 9);
                    for( std::size_t j = 0; j < 10; j++){
                        assignment.witness(component.W(component_type::CHUNKS[2+j]), start_row_index + i) = (((mask & integral_type(rw_trace[i].address)) >> (16 * (9-j))));
                        mask >>= 16;
                    }

                    // storage key
                    mask = 0xffff;
                    mask <<= (16 * 15);
                    for( std::size_t j = 0; j < 16; j++){
                        assignment.witness(component.W(component_type::CHUNKS[12+j]), start_row_index + i) = (((mask & integral_type(rw_trace[i].storage_key)) >> (16 * (15-j))));
                        mask >>= 16;
                    }

                    // rw_key
                    mask = 0xffff;
                    mask <<= 16;
                    assignment.witness(component.W(component_type::CHUNKS[28]), start_row_index + i) = (mask & rw_trace[i].rw_id) >> 16;
                    mask >>= 16;
                    assignment.witness(component.W(component_type::CHUNKS[29]), start_row_index + i) = (mask & rw_trace[i].rw_id);

                    // fill sorting indices and advices
                    if( i == 0 ) continue;
                    bool neq = true;
                    std::size_t diff_ind = 0;
                    for(; diff_ind < sorting.size(); diff_ind++){
                        if(
                            assignment.witness(component.W(sorting[diff_ind]), start_row_index+i) !=
                            assignment.witness(component.W(sorting[diff_ind]), start_row_index+i - 1)
                        ) break;
                    }
                    if( diff_ind < 30 ){
                        assignment.witness(component.W(component_type::VALUE_BEFORE_HI), start_row_index + i) = w_hi<BlueprintFieldType>(rw_trace[i].value_prev);
                        assignment.witness(component.W(component_type::VALUE_BEFORE_LO), start_row_index + i) = w_lo<BlueprintFieldType>(rw_trace[i].value_prev);
                    } else {
                        assignment.witness(component.W(component_type::VALUE_BEFORE_HI), start_row_index + i) = assignment.witness(component.W(component_type::VALUE_BEFORE_HI), start_row_index + i - 1);
                        assignment.witness(component.W(component_type::VALUE_BEFORE_LO), start_row_index + i) = assignment.witness(component.W(component_type::VALUE_BEFORE_LO), start_row_index + i - 1);
                    }

                    mask = (1 << component_type::INDICES_AMOUNT);
                    for(std::size_t j = 0; j < component_type::INDICES_AMOUNT; j++){
                        mask >>= 1;
                        assignment.witness(component.W(component_type::INDICES[j]), start_row_index + i) = ((mask & diff_ind) == 0? 0: 1);
                    }
                    if( rw_trace[i].op != START_OP && diff_ind < 30){
                        assignment.witness(component.W(component_type::IS_LAST), start_row_index + i - 1) = 1;
                    }
                    if( rw_trace[i].op != START_OP && rw_trace[i].op != PADDING_OP && diff_ind < 30){
                        assignment.witness(component.W(component_type::IS_FIRST), start_row_index + i) = 1;
                    }

                    assignment.witness(component.W(component_type::DIFFERENCE), start_row_index + i) =
                        assignment.witness(component.W(sorting[diff_ind]), start_row_index+i) -
                        assignment.witness(component.W(sorting[diff_ind]), start_row_index+i - 1);
                    if( rw_trace[i].op != PADDING_OP ) std::cout << "Diff index = " << diff_ind <<
                        " is_first = " << assignment.witness(component.W(component_type::IS_FIRST), start_row_index + i) <<
                        " is_last = " << assignment.witness(component.W(component_type::IS_LAST), start_row_index + i) <<
                        std::endl;

                    if( assignment.witness(component.W(component_type::DIFFERENCE), start_row_index + i) == 0)
                        assignment.witness(component.W(component_type::INV_DIFFERENCE), start_row_index + i) = 0;
                    else
                        assignment.witness(component.W(component_type::INV_DIFFERENCE), start_row_index + i) = BlueprintFieldType::value_type::one() / assignment.witness(component_type::DIFFERENCE, start_row_index+i);
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::array<std::size_t, 2> generate_gates(
                const plonk_zkevm_rw<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_rw<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
            ) {
                using component_type = plonk_zkevm_rw<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                std::vector<constraint_type> constraints;
                std::vector<lookup_constraint_type> lookup_constraints;

                var op = var(component.W(component_type::OP), 0, true);
                var op_prev = var(component.W(component_type::OP), -1, true);
                var op_next = var(component.W(component_type::OP), 1, true);
                var is_write = var(component.W(component_type::IS_WRITE), 0, true);
                var address = var(component.W(component_type::ADDRESS), 0, true);
                var storage_key_hi = var(component.W(component_type::STORAGE_KEY_HI), 0, true);
                var storage_key_lo = var(component.W(component_type::STORAGE_KEY_LO), 0, true);
                var id = var(component.W(component_type::ID), 0, true);
                var field = var(component.W(component_type::FIELD_TYPE), 0, true);
                var address_prev = var(component.W(component_type::ADDRESS), -1, true);
                var rw_id = var(component.W(component_type::RW_ID), 0, true);
                var value_hi = var(component.W(component_type::VALUE_HI), 0, true);
                var value_lo = var(component.W(component_type::VALUE_LO), 0, true);
                var value_hi_prev = var(component.W(component_type::VALUE_HI), -1, true);
                var value_lo_prev = var(component.W(component_type::VALUE_LO), -1, true);
                var diff = var(component.W(component_type::DIFFERENCE), 0, true);
                var inv_diff = var(component.W(component_type::INV_DIFFERENCE), 0, true);
                var is_first = var(component.W(component_type::IS_FIRST), 0, true);
                var is_first_prev = var(component.W(component_type::IS_FIRST), -1, true);
                var is_last = var(component.W(component_type::IS_LAST), 0, true);
                var value_before_hi = var(component.W(component_type::VALUE_BEFORE_HI), 0, true);
                var value_before_lo = var(component.W(component_type::VALUE_BEFORE_LO), 0, true);
                var value_before_hi_prev = var(component.W(component_type::VALUE_BEFORE_HI), -1, true);
                var value_before_lo_prev = var(component.W(component_type::VALUE_BEFORE_LO), -1, true);
                var state_root_hi = var(component.W(component_type::STATE_ROOT_HI), 0, true);
                var state_root_lo = var(component.W(component_type::STATE_ROOT_LO), 0, true);
                var state_root_before_hi = var(component.W(component_type::STATE_ROOT_HI), 0, true);
                var state_root_before_lo = var(component.W(component_type::STATE_ROOT_LO), 0, true);

                // op bit decomposition
                std::vector<var> op_bits;
                for(std::size_t i = 0; i < component_type::OP_SELECTORS_AMOUNT; i++){
                    op_bits.push_back(var(component.W(component_type::OP_SELECTORS[i]),0, true));
                }

                auto op_bits_constraints = bit_tag_constraints<BlueprintFieldType>(op_bits, rw_options_amount-1); // Here is maximum possible value
                constraints.insert(constraints.end(), op_bits_constraints.begin(), op_bits_constraints.end());
                constraints.push_back(bit_tag_composition<BlueprintFieldType>(op_bits, op));

                // ordering bit decomposition
                std::vector<var> ind_bits;
                std::vector<var> ind_bits_next;
                for(std::size_t i = 0; i < component_type::INDICES_AMOUNT; i++){
                    ind_bits.push_back(var(component.W(component_type::INDICES[i]),0, true));
                    ind_bits_next.push_back(var(component.W(component_type::INDICES[i]),1, true));
                }

                auto sorting_ids = sorting_columns<component_type>(component);
                auto ind_bits_constraints = bit_tag_constraints<BlueprintFieldType>(ind_bits, sorting_ids.size() - 1);
                constraints.insert(constraints.end(), ind_bits_constraints.begin(), ind_bits_constraints.end());

                std::vector<var> sorted;
                for(std::size_t i = 0; i < sorting_ids.size(); i++){
                    sorted.push_back(var(component.W(sorting_ids[i]),0, true));
                }

                std::vector<var> chunks;
                for(std::size_t i = 0; i < component_type::CHUNKS_AMOUNT; i++){
                    chunks.push_back(var(component.W(component_type::CHUNKS[i]),0, true));
                }

                auto sorting_constraints = lexicographic_constraints<BlueprintFieldType>(
                    sorted, ind_bits,
                    var(component.W(component_type::DIFFERENCE), 0, true)
                );
                constraints.push_back(is_first * (is_first - 1));
                constraints.push_back(is_last * (is_last - 1));
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (1 - is_first) * (1 - ind_bits[0]));
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (1 - is_first) * (1 - ind_bits[1]));
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (1 - is_first) * (1 - ind_bits[2]));
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (1 - is_first) * (1 - ind_bits[3]));
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * is_last * ind_bits_next[0] * ind_bits_next[1] * ind_bits_next[2] * ind_bits_next[3]);

                constraints.push_back(chunk16_composition<BlueprintFieldType>({chunks[0], chunks[1]}, id));
                constraints.push_back(chunk16_composition<BlueprintFieldType>({
                    chunks[2], chunks[3], chunks[4], chunks[5], chunks[6],
                    chunks[7], chunks[8], chunks[9], chunks[10], chunks[11],
                }, address));
                constraints.push_back(chunk16_composition<BlueprintFieldType>({
                    chunks[12], chunks[13], chunks[14], chunks[15],
                    chunks[16], chunks[17], chunks[18], chunks[19]
                }, storage_key_hi));
                constraints.push_back(chunk16_composition<BlueprintFieldType>({
                    chunks[20], chunks[21], chunks[22], chunks[23],
                    chunks[24], chunks[25], chunks[26], chunks[27]
                }, storage_key_lo));
                constraints.push_back(chunk16_composition<BlueprintFieldType>({
                    chunks[28], chunks[29]
                }, rw_id));

                // All chunks are 16 bits
                for( std::size_t i = 0; i < component_type::CHUNKS_AMOUNT; i++){
                    lookup_constraints.push_back({lookup_tables_indices.at("chunk_16_bits/full"), {chunks[i]}});
                }
                // Define possible OP column values

                // Universal constraints for all rw operations
                auto start_selector = bit_tag_selector<BlueprintFieldType>(op_bits, START_OP);
                auto stack_selector = bit_tag_selector<BlueprintFieldType>(op_bits, STACK_OP);
                auto memory_selector = bit_tag_selector<BlueprintFieldType>(op_bits, MEMORY_OP);
                auto storage_selector = bit_tag_selector<BlueprintFieldType>(op_bits, STORAGE_OP);
                auto transient_storage_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TRANSIENT_STORAGE_OP);
                auto call_context_selector = bit_tag_selector<BlueprintFieldType>(op_bits, CALL_CONTEXT_OP);
                auto account_selector = bit_tag_selector<BlueprintFieldType>(op_bits, ACCOUNT_OP);
                auto tx_refund_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TX_REFUND_OP);
                auto tx_access_list_account_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TX_ACCESS_LIST_ACCOUNT_OP);
                auto tx_access_list_account_storage_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TX_ACCESS_LIST_ACCOUNT_STORAGE_OP);
                auto tx_log_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TX_LOG_OP);
                auto tx_receipt_selector = bit_tag_selector<BlueprintFieldType>(op_bits, TX_RECEIPT_OP);
                auto padding_selector = bit_tag_selector<BlueprintFieldType>(op_bits, START_OP);

                constraints.push_back(is_write * (is_write - 1));                                                                                //2. is_write is either 0 or 1
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (is_first - 1) * (is_write - 1) * (value_hi - value_hi_prev));       // 4. for read operations value is equal to previous value
                constraints.push_back((op - START_OP) * (op - PADDING_OP) * (is_first - 1) * (is_write - 1) * (value_lo - value_lo_prev));       // 4. for read operations value is equal to previous value

                // Specific constraints for START
                constraints.push_back(start_selector * address);
                constraints.push_back(start_selector * storage_key_hi);
                constraints.push_back(start_selector * storage_key_lo);
                constraints.push_back(start_selector * id);
                constraints.push_back(start_selector * address);
                constraints.push_back(start_selector * field);
                constraints.push_back(start_selector * rw_id);
                constraints.push_back(start_selector * value_before_hi);
                constraints.push_back(start_selector * value_before_lo);
                constraints.push_back(start_selector * state_root_hi);
                constraints.push_back(start_selector * state_root_lo);
                constraints.push_back(start_selector * state_root_before_hi);
                constraints.push_back(start_selector * state_root_before_lo);

                // Specific constraints for STACK
                constraints.push_back(stack_selector * field);

                constraints.push_back(stack_selector * is_first * (1 - is_write));  // 4. First stack operation is obviously write
                constraints.push_back(stack_selector * (address - address_prev) * (is_write - 1));    // 5. First operation is always write
                constraints.push_back(stack_selector * (address - address_prev) * (address - address_prev - 1)); // 6. Stack pointer always grows and only by one
                constraints.push_back(stack_selector * field);
                constraints.push_back(stack_selector * storage_key_hi);
                constraints.push_back(stack_selector * storage_key_lo);
                constraints.push_back(stack_selector * value_before_hi);
                constraints.push_back(stack_selector * value_before_lo);
                constraints.push_back(stack_selector * (1 - is_first) * (state_root_hi - state_root_before_hi));
                constraints.push_back(stack_selector * (1 - is_first) * (state_root_lo - state_root_before_lo));
                lookup_constraints.push_back({lookup_tables_indices.at("chunk_16_bits/10bits"), {stack_selector * address}});

                // Specific constraints for MEMORY
                // address is 32 bit
                constraints.push_back(memory_selector * field);

                constraints.push_back(memory_selector * (is_first - 1) * (is_write - 1) * (value_lo - value_lo_prev));       // 4. for read operations value is equal to previous value
                constraints.push_back(memory_selector * value_hi);
                constraints.push_back(memory_selector * is_first * (is_write - 1) * value_lo);
                constraints.push_back(memory_selector * field);
                constraints.push_back(memory_selector * storage_key_hi);
                constraints.push_back(memory_selector * storage_key_lo);
                constraints.push_back(memory_selector * value_before_hi);
                constraints.push_back(memory_selector * value_before_lo);
                constraints.push_back(memory_selector * (1 - is_first) * (state_root_hi - state_root_before_hi));
                constraints.push_back(memory_selector * (1 - is_first) * (state_root_lo - state_root_before_lo));
                lookup_constraints.push_back({lookup_tables_indices.at("chunk_16_bits/8bits"), {memory_selector * value_lo}});

                // Specific constraints for STORAGE
                // lookup to MPT circuit
                // field is 0
                constraints.push_back(storage_selector * field);
                constraints.push_back(storage_selector * (1 - is_first) * (value_before_hi_prev - value_before_hi));
                constraints.push_back(storage_selector * (1 - is_first) * (value_before_lo_prev - value_before_lo));
                //lookup_constraints.push_back({"MPT table", {
                //    storage_selector * addr,
                //    storage_selector * field,
                //    storage_selector * storage_key_hi,
                //    storage_selector * storage_key_lo,
                //    storage_selector * value_before_hi,
                //    storage_selector * value_before_lo,
                //    storage_selector * value_hi,
                //    storage_selector * value_lo,
                //    storage_selector * state_root_hi,
                //    storage_selector * state_root_lo
                //}});

                // Specific constraints for TRANSIENT_STORAGE
                // field is 0
                constraints.push_back(transient_storage_selector * field);

                // Specific constraints for CALL_CONTEXT
                // address, storage_key, initial_value, value_prev are 0
                // state_root = state_root_prev
                // range_check for field_flag
                constraints.push_back(call_context_selector * address);
                constraints.push_back(call_context_selector * storage_key_hi);
                constraints.push_back(call_context_selector * storage_key_lo);
                constraints.push_back(call_context_selector * (1 - is_first) * (state_root_hi - state_root_before_hi));
                constraints.push_back(call_context_selector * (1 - is_first) * (state_root_lo - state_root_before_lo));
                constraints.push_back(call_context_selector * value_before_hi);
                constraints.push_back(call_context_selector * value_before_lo);

                // Specific constraints for ACCOUNT_OP
                // id, storage_key 0
                // field_tag -- Range
                // MPT lookup for last access
                // value and value_prev consistency
                constraints.push_back(account_selector * id);
                constraints.push_back(account_selector * storage_key_hi);
                constraints.push_back(account_selector * storage_key_lo);
                constraints.push_back(account_selector * (1 - is_first) * (value_before_hi_prev - value_before_hi));
                constraints.push_back(account_selector * (1 - is_first) * (value_before_lo_prev - value_before_lo));
                //lookup_constraints.push_back({"MPT table", {
                //    storage_selector * is_last * addr,
                //    storage_selector * is_last * field,
                //    storage_selector * is_last * storage_key_hi,
                //    storage_selector * is_last * storage_key_lo,
                //    storage_selector * is_last * value_before_hi,
                //    storage_selector * is_last * value_before_lo,
                //    storage_selector * is_last * value_hi,
                //    storage_selector * is_last * value_lo,
                //    storage_selector * is_last * state_root_hi,
                //    storage_selector * is_last * state_root_lo,
                //    storage_selector * is_last * state_root_before_hi,
                //    storage_selector * is_last * state_root_before_lo
                //}});

                // Specific constraints for TX_REFUND_OP
                // address, field_tag and storage_key are 0
                // state_root eqauls state_root_prev
                // initial_value is 0
                // if first access is Read then value = 0
                constraints.push_back(tx_refund_selector * address);
                constraints.push_back(tx_refund_selector * field);
                constraints.push_back(tx_refund_selector * storage_key_hi);
                constraints.push_back(tx_refund_selector * storage_key_lo);
                constraints.push_back(tx_refund_selector * is_first * (1-is_write) * value_hi);
                constraints.push_back(tx_refund_selector * is_first * (1-is_write) * value_lo);
                constraints.push_back(tx_refund_selector * (state_root_hi - state_root_before_hi));
                constraints.push_back(tx_refund_selector * (state_root_lo - state_root_before_lo));

                // Specific constraints for TX_ACCESS_LIST_ACCOUNT_OP
                // field_tag and storage_key are 0
                // value is boolean
                // initial_value is 0
                // state_root eqauls state_root_prev
                // value column at previous rotation equals value_prev at current rotation
                constraints.push_back(tx_access_list_account_selector * field);
                constraints.push_back(tx_access_list_account_selector * storage_key_hi);
                constraints.push_back(tx_access_list_account_selector * storage_key_lo);
                constraints.push_back(tx_access_list_account_selector * value_hi);
                constraints.push_back(tx_access_list_account_selector * value_lo * (1 - value_lo));
                constraints.push_back(tx_access_list_account_selector * (state_root_hi - state_root_before_hi));
                constraints.push_back(tx_access_list_account_selector * (state_root_lo - state_root_before_lo));
                constraints.push_back(tx_access_list_account_selector * (1 - is_first) * (value_hi_prev - value_before_hi));
                constraints.push_back(tx_access_list_account_selector * (1 - is_first) * (value_lo_prev - value_before_lo));

                // Specific constraints for TX_ACCESS_LIST_ACCOUNT_STORAGE_OP
                //    field_tag is 0
                //    value is boolean
                //    initial_value is 0
                //    state_root eqauls state_root_prev
                //    value column at previous rotation equals value_prev at current rotation
                constraints.push_back(tx_access_list_account_selector * field);
                constraints.push_back(tx_access_list_account_selector * value_hi);
                constraints.push_back(tx_access_list_account_selector * value_lo * (1 - value_lo));
                constraints.push_back(tx_access_list_account_selector * (state_root_hi - state_root_before_hi));
                constraints.push_back(tx_access_list_account_selector * (state_root_lo - state_root_before_lo));
                constraints.push_back(tx_access_list_account_selector * (1 - is_first) * (value_hi_prev - value_before_hi));
                constraints.push_back(tx_access_list_account_selector * (1 - is_first) * (value_lo_prev - value_before_lo));

                // Specific constraints for TX_LOG_OP
                //  is_write is true
                //  initial_value is 0
                //  state_root eqauls state_root_prev
                //  value_prev equals initial_value
                //  address 64 bits
                constraints.push_back(tx_log_selector * (1 - is_write));
                constraints.push_back(tx_log_selector * (state_root_hi - state_root_before_hi));
                constraints.push_back(tx_log_selector * (state_root_lo - state_root_before_lo));
                constraints.push_back(tx_log_selector * value_before_hi);
                constraints.push_back(tx_log_selector * value_before_lo);

                // Specific constraints for TX_RECEIPT_OP
                // address and storage_key are 0
                //  field_tag is boolean (according to EIP-658)
                //  tx_id increases by 1 and value increases as well if tx_id changes
                //  tx_id is 1 if it's the first row and tx_id is in 11 bits range
                //  state root is the same
                //  value_prev is 0 and initial_value is 0
                constraints.push_back(tx_receipt_selector * address);
                constraints.push_back(tx_receipt_selector * storage_key_hi);
                constraints.push_back(tx_receipt_selector * storage_key_lo);

                // Specific constraints for PADDING
                constraints.push_back(padding_selector * address);
                constraints.push_back(padding_selector * storage_key_hi);
                constraints.push_back(padding_selector * storage_key_lo);
                constraints.push_back(padding_selector * id);
                constraints.push_back(padding_selector * address);
                constraints.push_back(padding_selector * field);
                constraints.push_back(padding_selector * rw_id);
                constraints.push_back(padding_selector * state_root_hi);
                constraints.push_back(padding_selector * state_root_lo);
                constraints.push_back(padding_selector * state_root_before_hi);
                constraints.push_back(padding_selector * state_root_before_lo);
                constraints.push_back(padding_selector * value_hi);
                constraints.push_back(padding_selector * value_lo);
                constraints.push_back(padding_selector * value_before_hi);
                constraints.push_back(padding_selector * value_before_lo);

                constraints.push_back((op-START_OP) * (op-PADDING_OP) * (diff * inv_diff - 1));
                lookup_constraints.push_back({lookup_tables_indices.at("chunk_16_bits/full"), {diff}});

                //TODO: range check stack pointer with 1024
                //TODO: range check value_hi with 128 bits
                //TODO: range check value_lo with 128 bits

                std::size_t selector_id = bp.add_gate(constraints);
                bp.add_lookup_gate(selector_id, lookup_constraints);

                std::size_t not_first_selector_id = bp.add_gate(sorting_constraints);
                std::array<std::size_t, 2> selectors = {selector_id, not_first_selector_id};

                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_zkevm_rw<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_rw<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                // TODO: add copy constraints
            }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_rw<BlueprintFieldType>::result_type generate_circuit(
                const plonk_zkevm_rw<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_rw<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                std::cout << "Generate circuit" << std::endl;

                using component_type = plonk_zkevm_rw<BlueprintFieldType>;

                std::array<std::size_t, 2> selectors = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                std::size_t selector = selectors[0];
                std::size_t not_first_selector = selectors[1];

                assignment.enable_selector(
                    selector, start_row_index, start_row_index + component.rows_amount - 1);
                assignment.enable_selector(
                    not_first_selector, start_row_index, start_row_index + component.rows_amount - 1
                );
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
