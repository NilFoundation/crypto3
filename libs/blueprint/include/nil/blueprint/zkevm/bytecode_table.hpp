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

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_table.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            class bytecode_input_type {
            public:
                using data_type = std::vector<std::pair<std::vector<std::uint8_t>, zkevm_word_type>>;

                bytecode_input_type() {}

                void fill_bytecodes(const data_type &_bytecodes ){
                    BOOST_ASSERT(bytecodes == nullptr);
                    bytecodes = std::make_shared<data_type>();
                    *bytecodes = _bytecodes;
                }

                const data_type &get_bytecodes() const{
                    BOOST_ASSERT(bytecodes != nullptr);
                    return *bytecodes;
                }

                // For real usage. Bytecodes order doesn't matter
                std::size_t new_bytecode(std::pair<std::vector<std::uint8_t>, zkevm_word_type> hashed_pair){
                    if( bytecodes == nullptr ) bytecodes = std::make_shared<data_type>();
                    bytecodes->push_back(hashed_pair);
                    return bytecodes->size() - 1;
                }

                // TODO two versions -- with keccak and poseidon.
                // Keccak is more universal because we have poseidon implementation only for pallas curve
                std::size_t new_bytecode(std::vector<std::uint8_t> code = {}){
                    if( bytecodes == nullptr ) bytecodes = std::make_shared<data_type>();
                    zkevm_word_type hash = zkevm_keccak_hash(code);
                    bytecodes->push_back({code, hash});
                    return bytecodes->size() - 1;
                }

                // For small tests where we define opcode sequences manually
                void push_byte(std::size_t code_id, std::uint8_t b){
                    BOOST_ASSERT(bytecodes != nullptr && code_id < bytecodes->size());
                    (*bytecodes)[code_id].first.push_back(b);
                    (*bytecodes)[code_id].second = zkevm_keccak_hash((*bytecodes)[code_id].first);
                }
            private:
                std::shared_ptr<data_type> bytecodes; // EVM contracts bytecodes
            };

            // Component for bytecode table
            template<typename ArithmetizationType, typename FieldType>
            class zkevm_bytecode_table;

            template<typename BlueprintFieldType>
            class zkevm_bytecode_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using state_var = state_var<BlueprintFieldType>;
                using manifest_type = plonk_component_manifest;
                using value_type = typename BlueprintFieldType::value_type;

                struct bytecode_table_map{
                    bytecode_table_map(std::vector<std::uint32_t> witnesses):
                        tag(witnesses[0]), index(witnesses[1]), value(witnesses[2]),
                        is_opcode(witnesses[3]), hash_hi(witnesses[4]), hash_lo(witnesses[5]
                    )  {}

                    state_var tag;
                    state_var index;
                    state_var value;
                    state_var is_opcode;
                    state_var hash_hi;
                    state_var hash_lo;
                };

                std::size_t max_bytecode_size;
                std::size_t max_keccak_blocks;
                static const std::size_t witness_amount = 6; // It is the only supported value

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest() {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(zkevm_bytecode_table::witness_amount)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_bytecode_size) {
                    return max_bytecode_size;
                }

                std::size_t rows_amount = max_bytecode_size;

                class input_type:public bytecode_input_type{
                public:
                    input_type(): bytecode_input_type() {}
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                struct result_type {
                    result_type() {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                zkevm_bytecode_table(
                    const typename component_type::witness_container_type  &witnesses,
                    const typename component_type::constant_container_type &constants,
                    const typename component_type::public_input_container_type &public_inputs,
                    std::size_t _max_bytecode_size
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_bytecode_size(_max_bytecode_size),
                    m(witnesses){};

                bytecode_table_map m;
            };

            template<typename BlueprintFieldType>
            using plonk_zkevm_bytecode_table =
                zkevm_bytecode_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode_table<BlueprintFieldType>::result_type generate_assignments(
                const plonk_zkevm_bytecode_table<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_zkevm_bytecode_table<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                auto bytecodes = instance_input.get_bytecodes();
                const auto &m = component.m;

                std::size_t cur = start_row_index;
                for(std::size_t i = 0; i < bytecodes.size(); i++){
                    value_type hash_hi = w_hi<BlueprintFieldType>(bytecodes[i].second);
                    value_type hash_lo = w_lo<BlueprintFieldType>(bytecodes[i].second);
                    value_type push_size = 0;
                    const auto &buffer = bytecodes[i].first;
                    for(std::size_t j = 0; j < buffer.size(); j++, cur++){
                        std::uint8_t byte = buffer[j];
                        assignment.witness(m.hash_hi.index, cur) = hash_hi;
                        assignment.witness(m.hash_lo.index, cur) = hash_lo;
                        if( j == 0){
                            // HEADER
                            assignment.witness(m.value.index, cur) = buffer.size();
                            assignment.witness(m.tag.index, cur) = 0;
                            assignment.witness(m.index.index, cur) = 0;
                            assignment.witness(m.is_opcode.index, cur) = 0;
                            push_size = 0;
                            cur++;
                        }
                        // BYTE
                        assignment.witness(m.value.index, cur) = byte;
                        assignment.witness(m.hash_hi.index, cur) = hash_hi;
                        assignment.witness(m.hash_lo.index, cur) = hash_lo;
                        assignment.witness(m.tag.index, cur) = 1;
                        assignment.witness(m.index.index, cur) = j;
                        if(push_size == 0){
                            assignment.witness(m.is_opcode.index, cur) = 1;
                            if(byte > 0x5f && byte < 0x80) push_size = byte - 0x5f;
                        } else {
                            assignment.witness(m.is_opcode.index, cur) = 0;
                            push_size--;
                        }
                    }
                }
                return typename component_type::result_type();
	        }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode_table<BlueprintFieldType>::result_type generate_circuit(
                const plonk_zkevm_bytecode_table<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_zkevm_bytecode_table<BlueprintFieldType>;

                bp.register_dynamic_table("zkevm_bytecode");
               const auto &m = component.m;

                std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                assignment.enable_selector(selector_index, start_row_index, start_row_index + component.rows_amount - 1);

                crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> bytecode_table;
                bytecode_table.tag_index = selector_index;
                bytecode_table.columns_number =  6;// tag, index, value, length, hash_hi, hash_lo
                bytecode_table.lookup_options = {{
                    m.tag(), m.index(), m.value(), m.is_opcode(), m.hash_hi(), m.hash_lo()
                }};
                bp.define_dynamic_table("zkevm_bytecode", bytecode_table);
                return typename component_type::result_type();
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
