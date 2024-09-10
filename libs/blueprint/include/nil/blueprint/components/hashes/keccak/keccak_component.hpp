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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_COMPONENT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/blueprint/components/hashes/keccak/util.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_table.hpp>
#include <nil/blueprint/components/hashes/keccak/keccak_dynamic.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Easiest configuration with single keccak_table component and single keccak_dynamic
            template<typename ArithmetizationType>
            class keccak_component;

            template<typename BlueprintFieldType>
            class keccak_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                using table_component_type = plonk_keccak_table<BlueprintFieldType>;
                using dynamic_component_type = keccak_dynamic_component<BlueprintFieldType>;

                table_component_type     table_component;
                dynamic_component_type   dynamic_component;
                std::size_t max_blocks;
                std::size_t limit_permutation_columns;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 41;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_blocks, std::size_t limit_permutation_columns) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_blocks, std::size_t limit_permutation_column) {
                    std::cout << "Whole component rows amount = " << max_blocks + dynamic_component_type::get_rows_amount(witness_amount, max_blocks, limit_permutation_column) << std::endl;
                    return max_blocks + dynamic_component_type::get_rows_amount(witness_amount, max_blocks, limit_permutation_column);
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/extended"] = 0;              // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/extended_swap"] = 0;         // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check"] = 0;           // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_135"] = 0;       // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_16bit"] = 0;     // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/sparse_16bit"] = 0;          // REQUIRED_TABLE
                    lookup_tables["keccak_sign_bit_table/full"] = 0;              // REQUIRED_TABLE
                    lookup_tables["keccak_normalize3_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize4_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize6_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_chi_table/full"] = 0;                   // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_sparse"] = 0;    // REQUIRED_TABLE
                    lookup_tables["keccak_table"] = 1;                            // DYNAMIC_TABLE
                    lookup_tables["sparsed_keccak_table"] = 1;                    // DYNAMIC_TABLE
                    return lookup_tables;
                }

                constexpr static const std::size_t gates_amount = 0;
                constexpr static const std::size_t lookup_gates_amount = 2;
                std::size_t rows_amount = get_rows_amount(this->witness_amount(), max_blocks, limit_permutation_columns);

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
                    result_type(const keccak_component &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;

                        return result;
                    }
                };

                template<typename ContainerType>
                explicit keccak_component(ContainerType witness, std::size_t _max_blocks) :
                    component_type(witness, {}, {}, get_manifest()), max_blocks(_max_blocks)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_component(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _max_blocks,
                    std::size_t _limit_permuted_columns
                ) : component_type(witness, constant, public_input, get_manifest()), max_blocks(_max_blocks),
                    limit_permutation_columns(_limit_permuted_columns),
                    table_component(witness, constant, public_input, _max_blocks),
                    dynamic_component(witness, constant, public_input, _max_blocks, _limit_permuted_columns)
                {};

                keccak_component(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _max_blocks,
                    std::size_t _limit_permuted_columns
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), max_blocks(_max_blocks),
                limit_permutation_columns(_limit_permuted_columns),
                table_component(witnesses, constants, public_inputs, max_blocks),
                dynamic_component(witnesses, constants, public_inputs, max_blocks, _limit_permuted_columns)
                {};
            };

            template<typename BlueprintFieldType>
            using plonk_keccak_component =
                keccak_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_keccak_component<BlueprintFieldType>::result_type generate_assignments(
                const plonk_keccak_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_component<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_keccak_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                typename component_type::table_component_type::input_type table_input;
                table_input.input = instance_input.input;
                table_input.rlc_challenge = instance_input.rlc_challenge;
                generate_assignments(component.table_component, assignment, table_input, start_row_index);

                typename component_type::dynamic_component_type::input_type dynamic_input;
                dynamic_input.input = instance_input.input;
                dynamic_input.rlc_challenge = instance_input.rlc_challenge;
                generate_assignments(component.dynamic_component, assignment, dynamic_input, start_row_index + component.table_component.rows_amount);
                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            typename plonk_keccak_component<BlueprintFieldType>::result_type generate_circuit(
                const plonk_keccak_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_component<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_keccak_component<BlueprintFieldType>;
                using var = typename component_type::var;

                typename component_type::table_component_type::input_type table_input;
                table_input.input = instance_input.input;
                table_input.rlc_challenge = instance_input.rlc_challenge;
                generate_circuit(component.table_component, bp, assignment, table_input, start_row_index);

                typename component_type::dynamic_component_type::input_type dynamic_input;
                dynamic_input.input = instance_input.input;
                dynamic_input.rlc_challenge = instance_input.rlc_challenge;
                generate_circuit(component.dynamic_component, bp, assignment, dynamic_input, start_row_index + component.table_component.rows_amount);

                std::size_t selector_id = bp.get_dynamic_lookup_table_selector();
                typename component_type::dynamic_component_type::keccak_map m(component.dynamic_component);

                bp.register_dynamic_table("sparsed_keccak_table");
                crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> sparsed_table;
                sparsed_table.tag_index = selector_id;
                sparsed_table.columns_number =  4;//
                sparsed_table.lookup_options = {{
                    m.h.is_last,
                    m.h.RLC,
                    m.h.hash_hi,
                    m.h.hash_lo
                }};
                bp.define_dynamic_table("sparsed_keccak_table", sparsed_table);

                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                auto lookup_tables_indices = bp.get_reserved_indices();

                lookup_constraint_type check = {lookup_tables_indices.at("keccak_table"),{m.h.is_last, m.h.RLC, m.h.hash_hi, m.h.hash_lo}};
                bp.add_lookup_gate(selector_id, {check});
                for( std::size_t i = 0; i < component.max_blocks; i++){
                    assignment.enable_selector(
                        selector_id,
                        start_row_index + component.table_component.rows_amount + i * component.dynamic_component.block_rows_amount
                    );
                }

                typename component_type::table_component_type::keccak_table_map t(component.table_component);
                lookup_constraint_type tcheck = {lookup_tables_indices.at("sparsed_keccak_table"),{t.is_last, t.RLC, t.hash_hi, t.hash_lo}};
                std::size_t tselector_id = bp.add_lookup_gate({tcheck});
                for( std::size_t i = 0; i < component.max_blocks; i++){
                    assignment.enable_selector(
                        tselector_id,
                        start_row_index + i
                    );
                }

                return typename component_type::result_type(component, start_row_index);
            }
        }
    }
}
#endif