
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
            class zkevm_bytecode;

            template<typename BlueprintFieldType>
            class zkevm_bytecode<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                // Named witness columns
                static constexpr std::size_t TAG = 0;
                static constexpr std::size_t INDEX = 1;
                static constexpr std::size_t VALUE = 2;
                static constexpr std::size_t IS_OPCODE = 3;
                static constexpr std::size_t PUSH_SIZE = 4;
                static constexpr std::size_t LENGTH_LEFT = 5;
                static constexpr std::size_t HASH_HI = 6;
                static constexpr std::size_t HASH_LO = 7;
                static constexpr std::size_t VALUE_RLC = 8;
                static constexpr std::size_t RLC_CHALLENGE = 9;

                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_bytecode_size;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return zkevm_bytecode::gates_amount + zkevm_bytecode::lookup_gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_bytecode_size) {
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

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_bytecode_size) {
                    return max_bytecode_size;
                }

                constexpr static const std::size_t gates_amount = 1;
                constexpr static const std::size_t lookup_gates_amount = 1;
                std::size_t rows_amount = max_bytecode_size;

                struct input_type {
	                std::vector<std::vector<var>> bytecodes; // EVM contracts bytecodes
                    std::vector<std::pair<var, var>> bytecode_hashes; // hi, lo parts for keccak. It'll be only one value if we'll use poseidon
                    var rlc_challenge;
                    std::size_t full_size;

                    input_type(
                        const std::vector<std::vector<var>> &_bytecodes,
                        const std::vector<std::pair<var, var>> &_bytecode_hashes,
                        const var& _rlc_challenge
                    ) : bytecodes(_bytecodes), bytecode_hashes(_bytecode_hashes), rlc_challenge(_rlc_challenge), full_size(0) {
                        BOOST_ASSERT(_bytecodes.size() == _bytecode_hashes.size());
                        for( std::size_t i = 0; i < bytecodes.size(); i++ ){
                            full_size += bytecodes[i].size();
                        }
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        for( std::size_t i = 0; i < bytecodes.size(); i++ ){
                            for( std::size_t j = 0; j < bytecodes[i].size(); j++ ){
                                result.push_back(bytecodes[i][j]);
                            }
                        }
                        return result;
                    }
                };

                struct result_type {
                    result_type(const zkevm_bytecode &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit zkevm_bytecode(ContainerType witness, std::size_t _max_bytecode_size) :
                    component_type(witness, {}, {}, get_manifest()), max_bytecode_size(_max_bytecode_size)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                zkevm_bytecode(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _max_bytecode_size
                ) : component_type(witness, constant, public_input, get_manifest()), max_bytecode_size(_max_bytecode_size) {};

                zkevm_bytecode(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _max_bytecode_size
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_bytecode_size(_max_bytecode_size){};


                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["byte_range_table/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["zkevm_opcodes/full"] = 1; // REQUIRED_TABLE

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_zkevm_bytecode =
                zkevm_bytecode<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode<BlueprintFieldType>::result_type generate_assignments(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {
                std::cout << "Generate assignments" << std::endl;
                std::cout << "Start row index: " << start_row_index << std::endl;

                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                static constexpr std::size_t TAG = component_type::TAG;
                static constexpr std::size_t INDEX = component_type::INDEX;
                static constexpr std::size_t VALUE = component_type::VALUE;
                static constexpr std::size_t IS_OPCODE = component_type::IS_OPCODE;
                static constexpr std::size_t PUSH_SIZE = component_type::PUSH_SIZE;
                static constexpr std::size_t LENGTH_LEFT = component_type::LENGTH_LEFT;
                static constexpr std::size_t HASH_HI = component_type::HASH_HI;
                static constexpr std::size_t HASH_LO = component_type::HASH_LO;
                static constexpr std::size_t VALUE_RLC = component_type::VALUE_RLC;
                static constexpr std::size_t RLC_CHALLENGE = component_type::RLC_CHALLENGE;

                value_type rlc_challenge = var_value(assignment, instance_input.rlc_challenge);

                std::size_t cur = 0;
                for(std::size_t i = 0; i < instance_input.bytecodes.size(); i++){
                    value_type hash_hi = var_value(assignment, instance_input.bytecode_hashes[i].first);
                    value_type hash_lo = var_value(assignment, instance_input.bytecode_hashes[i].second);
                    value_type push_size = 0;
                    for(std::size_t j = 0; j < instance_input.bytecodes[i].size(); j++, cur++){
                        auto byte = var_value(assignment, instance_input.bytecodes[i][j]);
                        assignment.witness(component.W(VALUE), start_row_index + cur) = byte;
                        assignment.witness(component.W(HASH_HI), start_row_index + cur) = hash_hi;
                        assignment.witness(component.W(HASH_LO), start_row_index + cur) = hash_lo;
                        assignment.witness(component.W(RLC_CHALLENGE), start_row_index + cur) = rlc_challenge;
                        if( j == 0){
                            // HEADER
                            assignment.witness(component.W(TAG), start_row_index + cur) = 0;
                            assignment.witness(component.W(INDEX), start_row_index + cur) = 0;
                            assignment.witness(component.W(IS_OPCODE), start_row_index + cur) = 0;
                            assignment.witness(component.W(PUSH_SIZE), start_row_index + cur) = 0;
                            assignment.witness(component.W(LENGTH_LEFT), start_row_index + cur ) = var_value(assignment, instance_input.bytecodes[i][j]);
                            assignment.witness(component.W(VALUE_RLC), start_row_index + cur) = 0;
                            push_size = 0;
                        } else {
                            // BYTE
                            assignment.witness(component.W(TAG), start_row_index + cur) = 1;
                            assignment.witness(component.W(INDEX), start_row_index + cur) = j-1;
                            assignment.witness(component.W(LENGTH_LEFT), start_row_index + cur ) = assignment.witness(component.W(LENGTH_LEFT), start_row_index + cur - 1) - 1;
                            if(push_size == 0){
                                assignment.witness(component.W(IS_OPCODE), start_row_index + cur) = 1;
                                if(byte > 0x5f && byte < 0x80) push_size = byte - 0x5f;
                            } else {
                                assignment.witness(component.W(IS_OPCODE), start_row_index + cur) = 0;
                                push_size--;
                            }
                            assignment.witness(component.W(PUSH_SIZE), start_row_index + cur) = push_size;
                            assignment.witness(component.W(VALUE_RLC), start_row_index + cur) = assignment.witness(component.W(VALUE_RLC), start_row_index + cur - 1) * rlc_challenge + assignment.witness(component.W(VALUE), start_row_index + cur);
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
            ) {
                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                // Named witness columns
                static constexpr std::size_t TAG = component_type::TAG;
                static constexpr std::size_t INDEX = component_type::INDEX;
                static constexpr std::size_t VALUE = component_type::VALUE;
                static constexpr std::size_t IS_OPCODE = component_type::IS_OPCODE;
                static constexpr std::size_t PUSH_SIZE = component_type::PUSH_SIZE;
                static constexpr std::size_t LENGTH_LEFT = component_type::LENGTH_LEFT;
                static constexpr std::size_t HASH_HI = component_type::HASH_HI;
                static constexpr std::size_t HASH_LO = component_type::HASH_LO;
                static constexpr std::size_t VALUE_RLC = component_type::VALUE_RLC;
                static constexpr std::size_t RLC_CHALLENGE = component_type::RLC_CHALLENGE;

                var tag = var(component.W(TAG), 0, true);
                var tag_prev = var(component.W(TAG), -1, true);
                var tag_next = var(component.W(TAG), 1, true);
                var index = var(component.W(INDEX), 0, true);
                var index_next = var(component.W(INDEX), 1, true);
                var value = var(component.W(VALUE), 0, true);
                var length_left = var(component.W(LENGTH_LEFT), 0, true);
                var length_left_next = var(component.W(LENGTH_LEFT), 1, true);
                var is_opcode = var(component.W(IS_OPCODE), 0, true);
                var is_opcode_next = var(component.W(IS_OPCODE), 1, true);
                var push_size = var(component.W(PUSH_SIZE), 0, true);
                var push_size_next = var(component.W(PUSH_SIZE), 1, true);
                var hash_hi = var(component.W(HASH_HI), 0, true);
                var hash_hi_next = var(component.W(HASH_HI), 1, true);
                var hash_lo = var(component.W(HASH_LO), 0, true);
                var hash_lo_next = var(component.W(HASH_LO), 1, true);
                var value_rlc = var(component.W(VALUE_RLC), 0, true);
                var value_rlc_prev = var(component.W(VALUE_RLC), -1, true);
                var rlc_challenge = var(component.W(RLC_CHALLENGE), 0, true);
                var rlc_challenge_prev = var(component.W(RLC_CHALLENGE), -1, true);

                std::vector<constraint_type> constraints;
                constraints.push_back(tag * (tag - 1));    // 0. TAG is zeroes or ones -- maybe there will be third value for non-used rows
                constraints.push_back((tag - 1) * (index ));     // 1. INDEX for HEADER and unused bytes is zero
                constraints.push_back((tag - 1) * (index_next)); // 2. INDEX for first contract byte is zero
                constraints.push_back(tag * tag_next * (index_next - index - 1)); // 3. INDEX is incremented for any bytes
                constraints.push_back((tag - 1) * (length_left - value)); // 4. In contract header length_left == contract length
                constraints.push_back(tag_next * (length_left - length_left_next - 1)); // 5. In contract bytes each row decrement length_left
                constraints.push_back(tag * (tag_next - 1) * length_left); // 6. Length_left is zero for last byte in the contract
                constraints.push_back(is_opcode * (is_opcode - 1)); // 7. is_opcode is zeroes or ones
                constraints.push_back((tag - 1) * is_opcode); // 8. is_opcode on HEADER are zeroes
                constraints.push_back((tag - 1) * tag_next * (is_opcode_next - 1)); // 9. Fist is_opcode on BYTE after HEADER is 1
                constraints.push_back(is_opcode_next * push_size); // 11. before opcode push_size is always zero
                constraints.push_back(tag_next * (is_opcode_next - 1) * (push_size - push_size_next - 1)); // 10. PUSH_SIZE decreases for non-opcodes
                constraints.push_back(tag_next * (hash_hi - hash_hi_next)); //12. for all bytes hash is similar to previous
                constraints.push_back(tag_next * (hash_lo - hash_lo_next)); //13. for all bytes hash is similar to previous
                constraints.push_back((tag - 1) * value_rlc); // 14. value_rlc for HEADERS == 0;
                constraints.push_back(tag * (value_rlc - value_rlc_prev * rlc_challenge - value)); // 15. for all bytes RLC is correct
                constraints.push_back(tag * (rlc_challenge - rlc_challenge_prev)); //16. for each BYTEs rlc_challenge are similar
                constraints.push_back((tag-1) * tag_prev * tag_next * (rlc_challenge - rlc_challenge_prev)); //17. rlc doesn't change during contract

                std::vector<lookup_constraint_type> lookup_constraints;
                lookup_constraint_type bytecode_range_check = {lookup_tables_indices.at("byte_range_table/full"), {tag * value}};

                lookup_constraint_type opcode_constraint = {
                    lookup_tables_indices.at("zkevm_opcodes/full"),
                    {value * is_opcode, push_size * is_opcode , is_opcode}
                };

//              lookup_constraint_type hash_table_constraint = {
//                 lookup_tables_indices.at("zkevm_dynamic/hash_table"),
//                 {tag * (1 - tag_next) * value_rlc, tag * (1 - tag_next) * value_rlc * index + 1, tag * (1 - tag_next ) * hash_hi, tag * (1 - tag_next) * hash_lo}
//              }

                lookup_constraints.push_back(bytecode_range_check);
                lookup_constraints.push_back(opcode_constraint);

                std::size_t selector_id = bp.add_gate(constraints);
                bp.add_lookup_gate(selector_id, lookup_constraints);
                return selector_id;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                // TODO: add copy constraints
            }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode<BlueprintFieldType>::result_type generate_circuit(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                std::cout << "Generate circuit" << std::endl;

                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
