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
#include <nil/blueprint/zkevm/bytecode_table.hpp>

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
                using bytecode_table_component_type = plonk_zkevm_bytecode_table<BlueprintFieldType>;
                using keccak_table_component_type = plonk_keccak_table<BlueprintFieldType>;
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using state_var = state_var<BlueprintFieldType>;
                using manifest_type = plonk_component_manifest;
                using value_type = typename BlueprintFieldType::value_type;

                // Named witness columns
                /*static constexpr std::size_t PUSH_SIZE = 6;
                static constexpr std::size_t VALUE_RLC = 7;
                static constexpr std::size_t LENGTH_LEFT = 8;
                static constexpr std::size_t RLC_CHALLENGE = 9;*/

                struct bytecode_map{
                    bytecode_map(std::vector<std::uint32_t> witnesses):
                        tag(witnesses[0]),
                        index(witnesses[1]),
                        value(witnesses[2]),
                        is_opcode(witnesses[3]),
                        hash_hi(witnesses[4]),
                        hash_lo(witnesses[5]),
                        push_size(witnesses[6]),
                        value_rlc(witnesses[7]),
                        length_left(witnesses[8]),
                        rlc_challenge(witnesses[9]),
                        keccak_map(witnesses) { }

                    const std::vector<std::uint32_t> bytecode_table_witnesses() const{
                        return {
                            std::uint32_t(tag.index),
                            std::uint32_t(index.index),
                            std::uint32_t(value.index),
                            std::uint32_t(is_opcode.index),
                            std::uint32_t(hash_hi.index),
                            std::uint32_t(hash_lo.index)
                        };
                    }
                    typename keccak_table_component_type::keccak_table_map keccak_map;
                    state_var tag;
                    state_var index;
                    state_var value;
                    state_var is_opcode;
                    state_var hash_hi;
                    state_var hash_lo;
                    state_var push_size;
                    state_var value_rlc;
                    state_var length_left;
                    state_var rlc_challenge;
                };

                std::size_t max_bytecode_size;
                std::size_t max_keccak_blocks;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return zkevm_bytecode::gates_amount + zkevm_bytecode::lookup_gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(10)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_bytecode_size, std::size_t max_keccak_blocks) {
                    return max_bytecode_size + max_keccak_blocks + 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                constexpr static const std::size_t lookup_gates_amount = 1;
                std::size_t rows_amount = max_bytecode_size;

                class input_type:public bytecode_input_type {
                    using keccak_input_type = typename keccak_table_component_type::input_type;
                public:
                    var rlc_challenge;
                    input_type(var _rlc_challenge ) :rlc_challenge(_rlc_challenge) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {rlc_challenge};
                    }

                    const keccak_input_type& get_keccak_input() const{
                        BOOST_ASSERT(keccak_input != nullptr);
                        return *keccak_input;
                    }

                    void fill_dynamic_table_inputs(const keccak_input_type&_keccak_input){
                        BOOST_ASSERT(keccak_input == nullptr);
                        keccak_input = std::make_shared<keccak_input_type>();
                        *keccak_input = _keccak_input;
                    }
                private:
                    std::shared_ptr<keccak_input_type> keccak_input;
                };

                struct result_type {
                    result_type() {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                std::map<std::string, std::size_t> component_lookup_tables() const{
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["byte_range_table/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["zkevm_opcodes/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["keccak_table"] = 1; // Dynamic table;
                    return lookup_tables;
                }

                zkevm_bytecode(
                    typename component_type::witness_container_type witnesses,
                    typename component_type::constant_container_type constants,
                    typename component_type::public_input_container_type public_inputs,
                    std::size_t _max_bytecode_size,
                    std::size_t _max_keccak_blocks
                ) : component_type(witnesses, constants, public_inputs, get_manifest()),
                    max_bytecode_size(_max_bytecode_size),
                    max_keccak_blocks(_max_keccak_blocks),
                    m(witnesses),
                    bytecode_table(m.bytecode_table_witnesses(), constants, public_inputs, _max_bytecode_size),
                    keccak_table(m.keccak_map.witnesses(), constants, public_inputs, _max_keccak_blocks)
                {};

                bytecode_map m;
                bytecode_table_component_type bytecode_table;
                keccak_table_component_type keccak_table;
            };

            template<typename BlueprintFieldType>
            using plonk_zkevm_bytecode =
                zkevm_bytecode<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode<BlueprintFieldType>::result_type generate_basic_assignments(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;
                using bytecode_table_component_type = typename component_type::bytecode_table_component_type;
                using value_type = typename BlueprintFieldType::value_type;

                const typename component_type::bytecode_map &m = component.m;
                const bytecode_table_component_type &bytecode_table = component.bytecode_table;

                typename bytecode_table_component_type::input_type table_input;
                table_input.fill_bytecodes(instance_input.get_bytecodes());

                generate_assignments(bytecode_table, assignment, table_input, start_row_index);

                value_type rlc_challenge = var_value(assignment, instance_input.rlc_challenge);

                std::size_t cur = start_row_index;
                const auto &bytecodes = instance_input.get_bytecodes();
                for(std::size_t i = 0; i < bytecodes.size(); i++){
                    value_type push_size = 0;
                    auto buffer = bytecodes[i].first;
                    value_type length_left = buffer.size();
                    for(std::size_t j = 0; j < bytecodes[i].first.size(); j++, cur++){
                        auto byte = buffer[j];
                        assignment.witness(m.rlc_challenge.index, cur) = rlc_challenge;
                        if( j == 0){
                            // HEADER
                            assignment.witness(m.push_size.index, cur) = 0;
                            assignment.witness(m.length_left.index, cur ) = length_left;
                            assignment.witness(m.value_rlc.index, cur) = length_left;
                            push_size = 0;
                            length_left--;
                            cur++;
                        }
                        // BYTE
                        assignment.witness(m.rlc_challenge.index, cur) = rlc_challenge;
                        assignment.witness(m.length_left.index, cur) = length_left;
                        if(push_size == 0){
                            if(byte > 0x5f && byte < 0x80) push_size = byte - 0x5f;
                        } else {
                            push_size--;
                        }
                        assignment.witness(m.push_size.index, cur) = push_size;
                        assignment.witness(m.value_rlc.index, cur) = assignment.witness(m.value_rlc.index, cur - 1) * rlc_challenge + byte;
                        length_left--;
                    }
                }

                return typename component_type::result_type();
	        }

            template<typename BlueprintFieldType>
            void generate_dynamic_tables_assignments(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index
            ) {
                generate_assignments(
                    component.keccak_table,
                    assignment,
                    instance_input.get_keccak_input(),
                    start_row_index + component.bytecode_table.rows_amount + 1
                );
	        }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode<BlueprintFieldType>::result_type generate_assignments(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>   &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index
            ) {
                auto result_type = generate_basic_assignments<BlueprintFieldType>(component, assignment, instance_input, start_row_index);
                generate_dynamic_tables_assignments<BlueprintFieldType>(component, assignment, instance_input, start_row_index);
                return result_type;
            }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_zkevm_bytecode<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_zkevm_bytecode<BlueprintFieldType>::input_type
                    &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices,
                std::size_t start_row_index
            ) {
                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;
                using bytecode_table_component_type = typename component_type::bytecode_table_component_type;
                using keccak_table_component_type = typename component_type::keccak_table_component_type;
                using value_type = typename BlueprintFieldType::value_type;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const typename component_type::bytecode_map &m = component.m;
                const bytecode_table_component_type &bytecode_table = component.bytecode_table;

                bp.add_copy_constraint({instance_input.rlc_challenge, m.rlc_challenge.abs(start_row_index)});

                typename bytecode_table_component_type::input_type table_input;
                generate_circuit(bytecode_table, bp, assignment, table_input, start_row_index);

                typename keccak_table_component_type::input_type keccak_input(instance_input.rlc_challenge);
                generate_circuit(component.keccak_table, bp, assignment, keccak_input, start_row_index + component.bytecode_table.rows_amount + 1);

                std::vector<constraint_type> constraints;
                constraints.push_back(m.tag() * (m.tag() - 1));    // 0. TAG is zeroes or ones -- maybe there will be third value for non-used rows
                constraints.push_back((m.tag() - 1) * (m.index()));     // 1. INDEX for HEADER and unused bytes is zero
                constraints.push_back((m.tag() - 1) * (m.index.next())); // 2. INDEX for first contract byte is zero
                constraints.push_back(m.tag() * m.tag.next() * (m.index.next() - m.index() - 1)); // 3. INDEX is incremented for all bytes
                constraints.push_back((m.tag() - 1) * (m.length_left() - m.value())); // 4. In contract header length_left == contract length
                constraints.push_back(m.tag.next() * (m.length_left() - m.length_left.next() - 1)); // 5. In contract bytes each row decrement length_left
                constraints.push_back(m.tag() * (m.tag.next() - 1) * m.length_left()); // 6. Length_left is zero for last byte in the contract
                constraints.push_back(m.is_opcode() * (m.is_opcode() - 1)); // 7. is_opcode is zeroes or ones
                constraints.push_back((m.tag() - 1) * m.is_opcode()); // 8. is_opcode on HEADER are zeroes
                constraints.push_back((m.tag() - 1) * m.tag.next() * (m.is_opcode.next() - 1)); // 9. Fist is_opcode on BYTE after HEADER is 1
                constraints.push_back(m.is_opcode.next() * m.push_size()); // 11. before opcode push_size is always zero
                constraints.push_back(m.tag.next() * (m.is_opcode.next() - 1) * (m.push_size() - m.push_size.next() - 1)); // 10. PUSH_SIZE decreases for non-opcodes
                constraints.push_back(m.tag.next() * (m.hash_hi() - m.hash_hi.next())); //12. for all bytes hash is similar to previous
                constraints.push_back(m.tag.next() * (m.hash_lo() - m.hash_lo.next())); //13. for all bytes hash is similar to previous
                constraints.push_back((m.tag() - 1) * (m.value_rlc() - m.length_left())); // 14. value_rlc for HEADERS == 0;
                constraints.push_back(m.tag() * (m.value_rlc() - m.value_rlc.prev() * m.rlc_challenge() - m.value())); // 15. for all bytes RLC is correct
                constraints.push_back(m.tag() * (m.rlc_challenge() - m.rlc_challenge.prev())); //16. for each BYTEs rlc_challenge are similar
                constraints.push_back((m.tag() - 1) * m.tag.prev() * m.tag.next() * (m.rlc_challenge() - m.rlc_challenge.prev())); //17. rlc doesn't change during contract

                std::vector<lookup_constraint_type> lookup_constraints;
                lookup_constraint_type bytecode_range_check = {lookup_tables_indices.at("byte_range_table/full"), {m.tag() * m.value()}};

                lookup_constraint_type opcode_constraint = {
                    lookup_tables_indices.at("zkevm_opcodes/full"),
                    {m.value() * m.is_opcode(), m.push_size() * m.is_opcode() , m.is_opcode()}
                };
                std::size_t selector_id = bp.get_dynamic_table_definition("zkevm_bytecode")->lookup_table.tag_index;

                lookup_constraint_type hash_table_constraint = {
                    lookup_tables_indices.at("keccak_table"),
                    {
                        m.tag() * (1 - m.tag.next()),
                        m.tag() * (1 - m.tag.next()) * m.value_rlc() + (1 - m.tag() * (1 - m.tag.next())) *  0x109057df9cba2ae4cc6f2c8c33de834267af65e2b2ea38088d571b0c4e5fcb5c_cppui_modular257,
                        m.tag() * (1 - m.tag.next()) * m.hash_hi() + (1 - m.tag() * (1 - m.tag.next())) *  0x97cea80fc2260ca27ded02e6d09f19a3_cppui_modular257,
                        m.tag() * (1 - m.tag.next()) * m.hash_lo() + (1 - m.tag() * (1 - m.tag.next())) *  0x9853f3bc764790709249eb48cc9375fd_cppui_modular257
                    }
                };

                lookup_constraints.push_back(bytecode_range_check);
                lookup_constraints.push_back(opcode_constraint);
                lookup_constraints.push_back(hash_table_constraint);

                bp.add_gate(selector_id, constraints);
                bp.add_lookup_gate(selector_id, lookup_constraints);

                return selector_id;
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
                using component_type = plonk_zkevm_bytecode<BlueprintFieldType>;
                using var = typename component_type::var;

                auto lookup_tables = component.component_lookup_tables();
                    for(auto &[k,v]:lookup_tables){
                    if( v == 1 )
                        bp.reserve_dynamic_table(k);
                    else
                        bp.reserve_table(k);
                }
                // Selector id is already enabled by subcomponent
                generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices(), start_row_index);

                return typename component_type::result_type();
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
