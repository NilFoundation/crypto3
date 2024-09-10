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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_STATIC_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_STATIC_HPP

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
            class keccak_dynamic;

            template<typename BlueprintFieldType>
            class keccak_dynamic<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                using round_component_type =
                    keccak_round<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                using manifest_type = nil::blueprint::plonk_component_manifest;
                class gate_manifest_type : public component_gate_manifest {
                public:
                    static const constexpr std::size_t clamp = 15; //What is it?
                    std::size_t witness_amount;
                    std::size_t max_blocks;
                    std::size_t limit_permutation_column;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t max_blocks_,
                                       std::size_t limit_permutation_column_) :
                        witness_amount(std::min(witness_amount_, clamp)),
                        max_blocks(max_blocks_),
                        limit_permutation_column(limit_permutation_column_) {
                    }

                    std::uint32_t gates_amount() const override {
                        return get_gates_amount(witness_amount, max_blocks, limit_permutation_column);
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount,
                    std::size_t max_blocks,
                    std::size_t limit_permutation_column
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(
                        witness_amount, max_blocks, limit_permutation_column));

                    //manifest.merge_with(
                    //    round_component_type::get_gate_manifest(witness_amount, true, true, limit_permutation_column));
                    // Why we don't use it?
                    // manifest.merge_with(round_component_type::get_gate_manifest(
                    //     witness_amount, lookup_column_amount, true, false, limit_permutation_column));
                    // manifest.merge_with(round_component_type::get_gate_manifest(
                    //     witness_amount, lookup_column_amount, false, false, limit_permutation_column));

                    return manifest;
                }

                static manifest_type get_manifest(std::size_t max_blocks, std::size_t lpc = 7) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(15, 15)), false)
                            .merge_with(round_component_type::get_manifest(true, true, lpc));
                    return manifest;
                }

                const std::size_t lookup_rows = 65536;
                const std::size_t witnesses = this->witness_amount();

                const std::size_t max_blocks;
                const std::size_t limit_permutation_column;
                const std::size_t bytes_per_block = 136;    // 17*8

                round_component_type round_tt;
                round_component_type round_tf;
                round_component_type round_ff;

                const std::size_t header_rows_amount = get_header_rows_amount(this->witness_amount());
                const std::size_t state_rows_amount = get_state_rows_amount(this->witness_amount());
                const std::size_t chunks_rows_amount = get_chunks_rows_amount(this->witness_amount());
                const std::size_t rounds_rows_amount = get_rounds_rows_amount(this->witness_amount(), this->limit_permutation_column);
                const std::size_t unsparser_rows_amount = get_unsparser_rows_amount(this->witness_amount());
                const std::size_t block_rows_amount = get_block_rows_amount(this->witness_amount(), this->limit_permutation_column);

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), max_blocks, limit_permutation_column);
                const std::size_t gates_amount = get_gates_amount(this->witness_amount(), max_blocks, limit_permutation_column);

                const std::size_t round_constant[24] = {1,
                                                        0x8082,
                                                        0x800000000000808a,
                                                        0x8000000080008000,
                                                        0x808b,
                                                        0x80000001,
                                                        0x8000000080008081,
                                                        0x8000000000008009,
                                                        0x8a,
                                                        0x88,
                                                        0x80008009,
                                                        0x8000000a,
                                                        0x8000808b,
                                                        0x800000000000008b,
                                                        0x8000000000008089,
                                                        0x8000000000008003,
                                                        0x8000000000008002,
                                                        0x8000000000000080,
                                                        0x800a,
                                                        0x800000008000000a,
                                                        0x8000000080008081,
                                                        0x8000000000008080,
                                                        0x80000001,
                                                        0x8000000080008008};

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
                    result_type() {
                    }
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                struct header_map{
                    var hash_hi;
                    var hash_lo;
                    var RLC;
                    var is_first;
                    var is_last;
                    var L;
                    var l;
                    var hash_cur_hi;
                    var hash_cur_lo;
                    var rlc_before;
                    var rlc_after;

                    var hash_hi_prev;
                    var hash_lo_prev;
                    var RLC_prev;
                    var L_prev;
                    var l_prev;
                    var is_first_prev;
                    var is_last_prev;
                    var hash_cur_hi_prev;
                    var hash_cur_lo_prev;
                    var rlc_before_prev;
                    var rlc_after_prev;
                };

                struct state_map{
                    var is_first;
                    var s0;
                    var s1;
                    var s2;
                    var s3;
                    var s4;
                    var S0;
                    var S1;
                    var S2;
                    var S3;
                    var S4;
                    var rng;
                    var XOR;
                    var ch;
                    var out;

                    var is_first_prev;
                    var XOR_prev;
                    var ch_prev;

                    var rng_next;
                    var XOR_next;
                };

                struct chunks_map{
                    var b0;
                    var b1;
                    var b2;
                    var b3;
                    var sp0;
                    var sp1;
                    var chunk;
                    var l;
                    var l_before;
                    var rlc;
                    var rlc_before;
                    var r2;
                    var r4;
                    var first_in_block;
                    // First row is length before -- controlled by copy constraints -- other rows 0

                    var sp0_prev;
                    var sp1_prev;
                    var l_prev;
                    var l_before_prev;
                    var diff_prev;
                    var rlc_prev;
                    var rlc_before_prev;
                };

                struct unsparser_map{
                    var SP;         // sparsed 64 bit round output
                    var sp0;
                    var sp1;
                    var sp2;
                    var sp3;        // 16-bit chunks for SP
                    var ch0;
                    var ch1;
                    var ch2;
                    var ch3;        // unpacked 16-bit chunks
                    var hash_chunk; // 64 bit final chunk -- used only in last block but we compute it for all blocks

                    var ch0_prev;
                    var ch1_prev;
                    var ch2_prev;
                    var ch3_prev;
                };

                struct keccak_map{
                    header_map h;
                    state_map  s;
                    chunks_map c;
                    unsparser_map u;
                    var r; // rlc_challenge
                    var r_prev;

                    keccak_map(const keccak_dynamic &component){
                        std::size_t witness_amount = component.witness_amount();
                        assert(witness_amount == 15);
                        r = var(component.W(14), 0);
                        r_prev = var(component.W(14), -1);

                        h.L = var(component.W(0), 0);
                        h.RLC = var(component.W(1), 0);
                        h.hash_hi = var(component.W(2), 0);
                        h.hash_lo = var(component.W(3), 0);
                        h.rlc_before = var(component.W(4), 0);
                        h.rlc_after = var(component.W(5), 0);
                        h.l = var(component.W(6), 0);
                        h.hash_cur_hi = var(component.W(7), 0);
                        h.hash_cur_lo = var(component.W(8), 0);
                        h.is_last = var(component.W(9), 0);
                        h.is_first = var(component.W(10), 0);

                        h.L_prev = var(component.W(0), -1);
                        h.RLC_prev = var(component.W(1), -1);
                        h.hash_hi_prev = var(component.W(2), -1);
                        h.hash_lo_prev = var(component.W(3), -1);
                        h.rlc_before_prev = var(component.W(4), -1);
                        h.l_prev = var(component.W(6), -1);
                        h.hash_cur_hi_prev = var(component.W(7), -1);
                        h.hash_cur_lo_prev = var(component.W(8), -1);
                        h.is_last_prev = var(component.W(9), -1);
                        h.is_first_prev = var(component.W(10), -1);

                        s.s0 = var(component.W(0), 0);
                        s.s1 = var(component.W(1), 0);
                        s.s2 = var(component.W(2), 0);
                        s.s3 = var(component.W(3), 0);
                        s.s4 = var(component.W(4), 0);
                        s.S0 = var(component.W(5), 0);
                        s.S1 = var(component.W(6), 0);
                        s.S2 = var(component.W(7), 0);
                        s.S3 = var(component.W(8), 0);
                        s.S4 = var(component.W(9), 0);
                        // Connected with header by polynomial constraints
                        // Use copy constraints to remove this dependency
                        s.is_first = var(component.W(10), 0);
                        s.rng = var(component.W(11), 0);
                        s.XOR = var(component.W(12), 0);
                        s.ch = var(component.W(13), 0);
                        s.out = var(component.W(14), 0);

                        s.is_first_prev = var(component.W(10), -1);
                        s.XOR_prev = var(component.W(12), -1);
                        s.ch_prev = var(component.W(13), -1);

                        s.rng_next = var(component.W(11), 1);
                        s.XOR_next = var(component.W(12), 1);

                        c.b0 = var(component.W(0), 0);
                        c.b1 = var(component.W(1), 0);
                        c.b2 = var(component.W(2), 0);
                        c.b3 = var(component.W(3), 0);
                        c.sp0 = var(component.W(4), 0);
                        c.sp1 = var(component.W(5), 0);
                        c.chunk = var(component.W(6), 0);
                        c.l = var(component.W(7), 0);
                        c.l_before = var(component.W(8), 0);
                        c.rlc = var(component.W(9), 0);
                        c.rlc_before = var(component.W(10),0);
                        c.r2 = var(component.W(11),0);
                        c.r4 = var(component.W(12),0);
                        c.first_in_block = var(component.W(13),0);

                        c.sp0_prev = var(component.W(4), -1);
                        c.sp1_prev = var(component.W(5), -1);
                        c.l_prev = var(component.W(7), -1);
                        c.l_before_prev = var(component.W(8), -1);
                        c.rlc_prev = var(component.W(9), -1);
                        c.rlc_before_prev = var(component.W(10), -1);

                        u.SP = var(component.W(0), 0);
                        u.sp0 = var(component.W(1), 0);
                        u.sp1 = var(component.W(2), 0);
                        u.sp2 = var(component.W(3), 0);
                        u.sp3 = var(component.W(4), 0);
                        u.ch0 = var(component.W(5), 0);
                        u.ch1 = var(component.W(6), 0);
                        u.ch2 = var(component.W(7), 0);
                        u.ch3 = var(component.W(8), 0);
                        u.hash_chunk = var(component.W(9), 0);

                        u.ch0_prev = var(component.W(5), -1);
                        u.ch1_prev = var(component.W(6), -1);
                        u.ch2_prev = var(component.W(7), -1);
                        u.ch3_prev = var(component.W(8), -1);
                    }
                };

                static std::size_t get_header_rows_amount(std::size_t witness_amount){
                    return 1;
                }

                static std::size_t get_state_rows_amount(std::size_t witness_amount){
                    return 5;
                }

                static std::size_t get_chunks_rows_amount(std::size_t witness_amount){
                    return 34;
                }

                static std::size_t get_rounds_rows_amount(std::size_t witness_amount, std::size_t limit_permutation_column){
                    return
                        round_component_type::get_rows_amount( witness_amount, true, false, limit_permutation_column ) +
                        23 * round_component_type::get_rows_amount( witness_amount, false, false, limit_permutation_column);
                }

                static std::size_t get_unsparser_rows_amount(std::size_t witness_amount){
                    return 4;
                }

                static std::size_t get_footer_rows_amount(std::size_t witness_amount){
                    return 1;
                }

                static std::size_t get_block_rows_amount(std::size_t witness_amount, std::size_t limit_permutation_column){
                    return
                        get_header_rows_amount (witness_amount) +
                        get_state_rows_amount (witness_amount) +
                        get_chunks_rows_amount (witness_amount) +
                        get_rounds_rows_amount (witness_amount, limit_permutation_column) +
                        get_unsparser_rows_amount (witness_amount) +
                        get_footer_rows_amount (witness_amount);
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_blocks, std::size_t limit_permutation_column) {
                    return get_block_rows_amount(witness_amount, limit_permutation_column) * max_blocks;
                }

                static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t max_blocks,
                                                    std::size_t limit_permutation_column) {
                    return 39; // + round_component_type::get_gates_amount(witness_amount, );
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["keccak_pack_table/extended"] = 0;                // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/extended_swap"] = 0;                // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check"] = 0;             // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_135"] = 0;         // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_16bit"] = 0;         // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/sparse_16bit"] = 0;         // REQUIRED_TABLE
                    lookup_tables["keccak_sign_bit_table/full"] = 0;              // REQUIRED_TABLE
                    lookup_tables["keccak_normalize3_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize4_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_normalize6_table/full"] = 0;            // REQUIRED_TABLE
                    lookup_tables["keccak_chi_table/full"] = 0;                   // REQUIRED_TABLE
                    lookup_tables["keccak_pack_table/range_check_sparse"] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_dynamic(WitnessContainerType witness, ConstantContainerType constant,
                       PublicInputContainerType public_input, std::size_t max_blocks_,
                       std::size_t lpc_ = 7) :
                    component_type(witness, constant, public_input,
                                   get_manifest(max_blocks_, lpc_)),
                    max_blocks(max_blocks_),
                    limit_permutation_column(lpc_),
                    round_tt(witness, constant, public_input, true, true, lpc_),
                    round_tf(witness, constant, public_input, true, false, lpc_),
                    round_ff(witness, constant, public_input, false, false, lpc_) {};

                keccak_dynamic(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                       std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                       std::initializer_list<typename component_type::public_input_container_type::value_type>
                           public_inputs,
                       std::size_t max_blocks_, std::size_t lpc_ = 7) :
                    component_type(witnesses, constants, public_inputs),
                    max_blocks(max_blocks_),
                    limit_permutation_column(lpc_),
                    round_tt(witnesses, constants, public_inputs, true, true, lpc_),
                    round_tf(witnesses, constants, public_inputs, true, false, lpc_),
                    round_ff(witnesses, constants, public_inputs, false, false, lpc_) {};
            };

            template<typename BlueprintFieldType>
            using keccak_dynamic_component = keccak_dynamic<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const keccak_dynamic_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_dynamic_component<BlueprintFieldType>::input_type &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices) {
                std::cout << "Keccak component::generate gates" << std::endl;

                using component_type = keccak_dynamic_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using lookup_constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;
                using value_type = typename BlueprintFieldType::value_type;

                typename component_type::keccak_map m(component);

                std::vector<std::size_t> selector_indices;
                std::vector<constraint_type> header_constraints;
                std::vector<lookup_constraint_type> header_lookup_constraints;
                // Is_first and is_last definition
                header_constraints.push_back(m.h.is_first * (m.h.is_first - 1));                                                            // HF1
                header_constraints.push_back(m.h.is_last * (m.h.is_last - 1));                                                              // HF2
                header_constraints.push_back(m.h.is_first * (m.h.L - m.h.l));                                                               // HF3
                header_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check_135"),{m.h.is_last * m.h.l}}); // HF4

                // Hash computation correctness
                header_constraints.push_back(m.h.is_last * (m.h.hash_hi - m.h.hash_cur_hi));    // HF5
                header_constraints.push_back(m.h.is_last * (m.h.hash_lo - m.h.hash_cur_lo));    // HF6

                // RLC computation correctness
                header_constraints.push_back(m.h.is_first * (m.h.rlc_before - m.h.L));  // HF7
                header_constraints.push_back(m.h.is_last * (m.h.rlc_after - m.h.RLC));  // HF8

                // Transition between blocks
                header_constraints.push_back(( 1 - m.h.is_first ) * (m.h.L - m.h.L_prev));      // BT4
                header_constraints.push_back(( 1 - m.h.is_first ) * (m.h.RLC - m.h.RLC_prev));  // BT5
                header_constraints.push_back(( 1 - m.h.is_first ) * (m.h.hash_hi - m.h.hash_hi_prev));  // BT6
                header_constraints.push_back(( 1 - m.h.is_first ) * (m.h.hash_lo - m.h.hash_lo_prev));  // BT7
                header_constraints.push_back(( 1 - m.h.is_first ) * (m.h.rlc_before_prev - m.h.rlc_before)); // BT8
                header_constraints.push_back(( 1 - m.h.is_first ) * (1 - m.h.is_last) * (m.h.l_prev - m.h.l - 136)); // BT9

                header_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check_16bit"),{m.h.L}});
                header_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check_16bit"),{m.h.l}});
                selector_indices.push_back(bp.add_gate(header_constraints));
                bp.add_lookup_gate(selector_indices.back(), header_lookup_constraints);

                std::vector<constraint_type> first_header_constraints;
                first_header_constraints.push_back(1 - m.h.is_first); // BT1
                selector_indices.push_back(bp.add_gate(first_header_constraints));

                std::vector<constraint_type> non_first_header_constraints;
                non_first_header_constraints.push_back(m.h.is_first * (1 - m.h.is_last_prev)); //BT2
                selector_indices.push_back(bp.add_gate(non_first_header_constraints));

                // State constraints.
                //      m.s.s -- previous block output defined by copy_constraints.
                //      m.s.S -- zerofied for first block and copied for other blocks.
                std::vector<constraint_type> state_constraints;
                std::vector<lookup_constraint_type> state_lookup_constraints;
                state_constraints.push_back(m.s.is_first_prev - m.s.is_first);      // ST1
                state_constraints.push_back(m.s.S0 - (1 - m.s.is_first) * m.s.s0);  // ST3
                state_constraints.push_back(m.s.S1 - (1 - m.s.is_first) * m.s.s1);  // ST4
                state_constraints.push_back(m.s.S2 - (1 - m.s.is_first) * m.s.s2);  // ST5
                state_constraints.push_back(m.s.S3 - (1 - m.s.is_first) * m.s.s3);  // ST6
                state_constraints.push_back(m.s.S4 - (1 - m.s.is_first) * m.s.s4);  // ST7
                state_constraints.push_back(m.s.out
                    - m.s.XOR_prev * (integral_type(1) << (48 * 3))
                    - m.s.ch_prev * (integral_type(1) << (48 * 2))
                    - m.s.XOR * (integral_type(1) << 48)
                    - m.s.ch
                );    // ST9
                state_lookup_constraints.push_back(
                    {lookup_tables_indices.at("keccak_pack_table/sparse_16bit"),{m.s.rng}}
                );    // ST8
                selector_indices.push_back(bp.add_gate(state_constraints));
                bp.add_lookup_gate(selector_indices.back(), state_lookup_constraints);

                std::vector<constraint_type> xor_constraints;
                const integral_type sparse_x80 = component.round_tf.sparse_x80 >> 144;
                const integral_type sparse_x7f = component.round_tf.sparse_x7f >> 144;
                xor_constraints.push_back((m.s.rng_next - sparse_x80 - m.s.rng) * (m.s.rng_next - sparse_x7f + m.s.rng )); // XOR1
                //xor_constraints.push_back((m.s.ch * (m.s.ch - 1))); -- not necessary, controlled by copy constraints
                xor_constraints.push_back((m.s.rng_next - sparse_x7f + m.s.rng ) * (m.s.XOR - m.s.rng_next + sparse_x80)); // XOR2
                xor_constraints.push_back((m.s.rng_next - sparse_x80 - m.s.rng ) * (m.s.XOR - m.s.rng_next - sparse_x80)); // XOR3
                // XOR_next - is_last * XOR - (1-is_last) * rng_next
                xor_constraints.push_back((m.s.XOR_next - m.s.ch * m.s.XOR - (1 - m.s.ch) * m.s.rng_next)); // XOR4
                selector_indices.push_back(bp.add_gate(xor_constraints));

                value_type chunk_factor = value_type(integral_type(1) << 48);
                std::vector<constraint_type> chunks_constraints;
                std::vector<lookup_constraint_type> chunks_lookup_constraints;
                chunks_constraints.push_back(
                    m.c.chunk - m.c.sp1 * chunk_factor * chunk_factor * chunk_factor -
                    m.c.sp0 * chunk_factor * chunk_factor - m.c.sp1_prev * chunk_factor - m.c.sp0_prev
                );  // CH7

                auto diff = m.c.l_before - m.c.l;
                auto diff_prev = m.c.l_before_prev - m.c.l_prev;

                //chunks_constraints.push_back(m.c.first_in_block * (1 - m.c.first_in_block)); // Not necessary, controlled by copy constraints.
                chunks_constraints.push_back((1 - m.c.first_in_block) * (m.c.l_before - m.c.l_prev)); // LC3
                chunks_constraints.push_back(diff * (diff - 1) * (diff - 2) * (diff - 3) * (diff - 4)); // LC4
                chunks_constraints.push_back((1 - m.c.first_in_block) * diff * (diff_prev - 4)); // LC5

                chunks_constraints.push_back(diff * (diff - 1) * (diff-2) * (diff-4) * (m.c.b3 - 1));  // PC1
                chunks_constraints.push_back(diff * (diff - 1) * (diff-3) * (diff-4) * (m.c.b2 - 1));  // PC2
                chunks_constraints.push_back(diff * (diff - 1) * (diff-3) * (diff-4) * m.c.b3);        // PC3
                chunks_constraints.push_back(diff * (diff - 2) * (diff-3) * (diff-4) * (m.c.b1 - 1));  // PC4
                chunks_constraints.push_back(diff * (diff - 2) * (diff-3) * (diff-4) * m.c.b2);        // PC5
                chunks_constraints.push_back(diff * (diff - 2) * (diff-3) * (diff-4) * m.c.b3);        // PC6
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - diff) * (diff_prev - diff - 1) * (diff_prev - diff - 2) * (diff_prev - diff - 3)  * (m.c.b0 - 1)); //PC7
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - diff) * (diff_prev - diff - 1) * (diff_prev - diff - 2) * (diff_prev - diff - 3)  * m.c.b1);       //PC8
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - diff) * (diff_prev - diff - 1) * (diff_prev - diff - 2) * (diff_prev - diff - 3)  * m.c.b2);       //PC9
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - diff) * (diff_prev - diff - 1) * (diff_prev - diff - 2) * (diff_prev - diff - 3)  * m.c.b3);       //PC10
                chunks_constraints.push_back(m.c.first_in_block * (diff - 1) * (diff - 2) * (diff-3) * (diff - 4)  * (m.c.b0 - 1)); //PC11
                chunks_constraints.push_back(m.c.first_in_block * (diff - 1) * (diff - 2) * (diff-3) * (diff - 4)  * m.c.b1);       //PC12
                chunks_constraints.push_back(m.c.first_in_block * (diff - 1) * (diff - 2) * (diff-3) * (diff - 4)  * m.c.b2);       //PC13
                chunks_constraints.push_back(m.c.first_in_block * (diff - 1) * (diff - 2) * (diff-3) * (diff - 4)  * m.c.b3);       //PC14
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - 4) * (diff - 1) * (diff - 2) * (diff - 3)  * (diff - 4) * m.c.b0); //PC15
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - 4) * (diff - 1) * (diff - 2) * (diff - 3)  * (diff - 4) * m.c.b1); //PC16
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - 4) * (diff - 1) * (diff - 2) * (diff - 3)  * (diff - 4) * m.c.b2); //PC17
                chunks_constraints.push_back((1 - m.c.first_in_block) * (diff_prev - 4) * (diff - 1) * (diff - 2) * (diff - 3)  * (diff - 4) * m.c.b3); //PC18

                chunks_constraints.push_back(m.c.r2 - m.r * m.r);               //RLC4
                chunks_constraints.push_back(m.c.r4 - m.c.r2 * m.c.r2);         //RLC5
                chunks_constraints.push_back((1 - m.c.first_in_block) * (m.c.rlc_before - m.c.rlc_prev));   //RLC6
                //RLC7
                chunks_constraints.push_back(
                    diff * (diff - 1) * (diff - 2) * (diff - 3) *
                    (m.c.rlc - m.c.r4 * m.c.rlc_before - m.c.r2 * m.r *  m.c.b0 - m.c.r2 * m.c.b1 - m.r  * m.c.b2 - m.c.b3)
                );
                //RLC8
                chunks_constraints.push_back(
                    diff * (diff - 1) * (diff - 2) * (diff - 4) *
                    (m.c.rlc - m.c.r2 * m.r * m.c.rlc_before - m.c.r2 *  m.c.b0 - m.r * m.c.b1 - m.c.b2)
                );
                //RLC9
                chunks_constraints.push_back(
                    diff * (diff - 1) * (diff - 3) * (diff - 4) *
                    (m.c.rlc - m.c.r2 * m.c.rlc_before - m.r *  m.c.b0 - m.c.b1)
                );
                //RLC10
                chunks_constraints.push_back(
                    diff * (diff - 2) * (diff - 3) * (diff - 4) *
                    (m.c.rlc - m.r * m.c.rlc_before - m.c.b0)
                );
                //RLC11
                chunks_constraints.push_back(
                    (diff - 1) * (diff - 2) * (diff - 3) * (diff - 4) *
                    (m.c.rlc - m.c.rlc_before)
                );

                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),{m.c.b0}});  // CH1
                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),{m.c.b1}});  // CH2
                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),{m.c.b2}});  // CH3
                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/range_check"),{m.c.b3}});  // CH4
                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended"), {m.c.b1 * 256 + m.c.b0, m.c.sp0}});  // CH5
                chunks_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended"), {m.c.b3 * 256 + m.c.b2, m.c.sp1}});  // CH6

                selector_indices.push_back(bp.add_gate(chunks_constraints));
                bp.add_lookup_gate(selector_indices.back(), chunks_lookup_constraints);

                std::vector<constraint_type> unsparser_constraints;
                std::vector<lookup_constraint_type> unsparser_lookup_constraints;
                integral_type sparsed_factor( integral_type(1) << 48 );
                integral_type ufactor( integral_type(1) << 16);
                //UN2
                unsparser_constraints.push_back(m.u.SP - m.u.sp0 * (sparsed_factor << 96) - m.u.sp1 * (sparsed_factor << 48) - m.u.sp2 * sparsed_factor - m.u.sp3);
                //UN7
                unsparser_constraints.push_back( m.u.hash_chunk -
                    m.u.ch3_prev * (ufactor  << (16 * 6)) -
                    m.u.ch2_prev * (ufactor  << (16 * 5)) -
                    m.u.ch1_prev * (ufactor  << (16 * 4)) -
                    m.u.ch0_prev * (ufactor  << (16 * 3)) -
                    m.u.ch3 * (ufactor  << (16 * 2)) -
                    m.u.ch2 * (ufactor  << (16)) -
                    m.u.ch1 * ufactor -
                    m.u.ch0);
                selector_indices.push_back(bp.add_gate(unsparser_constraints));
                unsparser_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended_swap"),{m.u.ch0, m.u.sp0}}); //UN3
                unsparser_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended_swap"),{m.u.ch1, m.u.sp1}}); //UN4
                unsparser_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended_swap"),{m.u.ch2, m.u.sp2}}); //UN5
                unsparser_lookup_constraints.push_back({lookup_tables_indices.at("keccak_pack_table/extended_swap"),{m.u.ch3, m.u.sp3}}); //UN6
                bp.add_lookup_gate(selector_indices.back(), unsparser_lookup_constraints);

                return selector_indices;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const keccak_dynamic_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_dynamic_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = keccak_dynamic_component<BlueprintFieldType>;
                using round_type = typename component_type::round_component_type;
                using var = typename component_type::var;

                typename component_type::keccak_map m (component);

                std::size_t header_row = start_row_index;
                std::size_t footer_row = header_row + component.block_rows_amount - 1;
                for( std::size_t i = 0; i < component.max_blocks; i++ ){
                    std::size_t state_row = header_row + component.header_rows_amount;
                    std::size_t chunks_row = state_row + component.state_rows_amount;
                    std::size_t unsparser_row = footer_row - component.unsparser_rows_amount;

                    bp.add_copy_constraint( { instance_input.rlc_challenge, var(m.r.index, header_row, false)  } ); // HF9

                    // BT3
                    bp.add_copy_constraint( { var(m.r.index, header_row, false), var(m.r.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.hash_hi.index, header_row, false), var(m.h.hash_hi.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.hash_lo.index, header_row, false), var(m.h.hash_lo.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.L.index, header_row, false), var(m.h.L.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.l.index, header_row, false), var(m.h.l.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.RLC.index, header_row, false), var(m.h.RLC.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.is_first.index, header_row, false), var(m.h.is_first.index, footer_row, false) } );
                    bp.add_copy_constraint( { var(m.h.is_last.index, header_row, false), var(m.h.is_last.index, footer_row, false) } );

                    bp.add_copy_constraint( {var(m.s.S1.index, state_row + 3, false), var(m.s.out.index, state_row + 4, false)} );  //ST11
                    bp.add_copy_constraint( {var(m.h.is_last.index, header_row, false), var(m.s.ch.index, state_row, false)} );     //ST8

                    // ST12
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 2, false), var(m.s.ch.index, state_row + 1, false)} );
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 3, false), var(m.s.XOR.index, state_row + 2, false)} );
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 4, false), var(m.s.ch.index, state_row + 2, false)} );

                    // ST10
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 1, false), var(m.s.XOR.index, state_row + 3, false)} );
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 2, false), var(m.s.ch.index, state_row + 3, false)} );
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 3, false), var(m.s.XOR.index, state_row + 4, false)} );
                    bp.add_copy_constraint( {var(m.s.rng.index, state_row + 4, false), var(m.s.ch.index, state_row + 4, false)} );

                    for( std::size_t j = 0; j < component.chunks_rows_amount; j++ ){
                        // LC1
                        if(j == 0)
                            bp.add_copy_constraint({var(m.c.first_in_block.index,  chunks_row + j, false), var(component.C(0), start_row_index + 1, false, var::column_type::constant)});
                        else
                            bp.add_copy_constraint({var(m.c.first_in_block.index,  chunks_row + j, false), var(component.C(0), start_row_index, false, var::column_type::constant)});
                        bp.add_copy_constraint({  instance_input.rlc_challenge, var(m.r.index, chunks_row + j, false)  } ); // RLC3
                    }
                    bp.add_copy_constraint( {var(m.h.l.index, header_row, false), var(m.c.l_before.index, chunks_row, false)} ); // LC2

                    bp.add_copy_constraint( {var(m.h.rlc_before.index, header_row, false), var(m.c.rlc_before.index, chunks_row, false)} ); // RLC1
                    bp.add_copy_constraint( {var(m.h.rlc_after.index, header_row, false), var(m.c.rlc.index, chunks_row + component.chunks_rows_amount - 1, false)} ); // RLC2

                    bp.add_copy_constraint( {var(m.h.hash_cur_hi.index, header_row, false), var(m.u.hash_chunk.index, unsparser_row + 1, false)}); //UN8
                    bp.add_copy_constraint( {var(m.h.hash_cur_lo.index, header_row, false), var(m.u.hash_chunk.index, unsparser_row + 3, false)}); //UN8

                    header_row += component.block_rows_amount;
                    footer_row += component.block_rows_amount;
                }
            }

            template<typename BlueprintFieldType>
            typename keccak_dynamic_component<BlueprintFieldType>::result_type generate_circuit(
                const keccak_dynamic_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_dynamic_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {
                std::cout << "Keccak dynamic component generate_circuit rows_amount = "
                    << component.rows_amount << " gates_amount = " << component.gates_amount
                    << " start_row_index = " << start_row_index
                    << " block rows amount = " << component.block_rows_amount << std::endl;

//                BOOST_ASSERT(instance_input.message.size() == component.num_blocks);

                using component_type = keccak_dynamic_component<BlueprintFieldType>;
                using round_type = typename component_type::round_component_type;
                using var = typename component_type::var;

                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);
                std::size_t row = start_row_index;

                auto selector_indices =
                    generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());
                std::size_t header_selector = selector_indices[0];
                std::size_t first_header_selector = selector_indices[1];
                std::size_t non_first_header_selector = selector_indices[2];
                std::size_t state_selector = selector_indices[3];
                std::size_t xor_selector = selector_indices[4];
                std::size_t chunks_selector = selector_indices[5];
                std::size_t unsparser_selector = selector_indices[6];

                typename component_type::keccak_map m(component);

                typename round_type::result_type round_result;
                for( std::size_t block = 0; block < component.max_blocks; block++ ){
                    std::size_t header_row = start_row_index + block * component.block_rows_amount;
                    assignment.enable_selector(header_selector, header_row);
                    if( block != 0 )
                        assignment.enable_selector(non_first_header_selector, header_row);
                    else
                        assignment.enable_selector(first_header_selector, header_row);

                    std::size_t state_row = header_row + component.header_rows_amount;
                    for( std::size_t j = 0; j < component.state_rows_amount; j++ ){
                        assignment.enable_selector(state_selector, state_row + j);
                        if( block != 0){
                            // ST2
                            bp.add_copy_constraint( { round_result.inner_state[j * 5], var(m.s.s0.index, state_row + j, false) } );
                            bp.add_copy_constraint( { round_result.inner_state[j * 5 + 1], var(m.s.s1.index, state_row + j, false) } );
                            bp.add_copy_constraint( { round_result.inner_state[j * 5 + 2], var(m.s.s2.index, state_row + j, false) } );
                            bp.add_copy_constraint( { round_result.inner_state[j * 5 + 3], var(m.s.s3.index, state_row + j, false) } );
                            bp.add_copy_constraint( { round_result.inner_state[j * 5 + 4], var(m.s.s4.index, state_row + j, false) } );
                        }
                    }
                    assignment.enable_selector(xor_selector, state_row);

                    std::size_t chunks_row = state_row + component.state_rows_amount;
                    for( std::size_t j = 0; j < component.chunks_rows_amount; j++ )
                        assignment.enable_selector(chunks_selector, chunks_row + j);

                    std::size_t footer_row = header_row + component.block_rows_amount - 1;
                    std::size_t unsparser_row = footer_row - component.unsparser_rows_amount;
                    for( std::size_t j = 0; j < component.unsparser_rows_amount; j++ )
                        assignment.enable_selector(unsparser_selector, unsparser_row + j);

                    std::array<var, 25> inner_state;
                    for (std::size_t i = 0; i < 5; i++) {
                        inner_state[5 * i    ] = var(m.s.S0.index, state_row + i, false);
                        inner_state[5 * i + 1] = var(m.s.S1.index, state_row + i, false);
                        inner_state[5 * i + 2] = var(m.s.S2.index, state_row + i, false);
                        inner_state[5 * i + 3] = var(m.s.S3.index, state_row + i, false);
                        inner_state[5 * i + 4] = var(m.s.S4.index, state_row + i, false);
                    }
                    inner_state[16] = var(m.s.out.index, state_row + 2, false);

                    std::size_t offset = 0;
                    std::array<var, 17> pmc;
                    for (std::size_t i = 0; i < 17; i++ ){
                        pmc[i] = var(m.c.chunk.index, chunks_row + 2 * i + 1, false);
                    }

                    std::size_t rounds_row = chunks_row + component.chunks_rows_amount;
                    for (std::size_t j = 0; j < 24; ++j) {
                        typename round_type::input_type round_input = {
                            inner_state, pmc,
                            var(component.C(0), start_row_index + j + 2, false, var::column_type::constant)
                        };

                        if (j == 0) {
                            round_result = generate_circuit(component.round_tf, bp, assignment, round_input, rounds_row);
                            inner_state = round_result.inner_state;
                            rounds_row += component.round_tf.rows_amount;
                        } else {
                            round_result = generate_circuit(component.round_ff, bp, assignment, round_input, rounds_row);
                            inner_state = round_result.inner_state;
                            rounds_row += component.round_ff.rows_amount;
                        }
                    }
                    //UN1
                    bp.add_copy_constraint( {round_result.inner_state[0], var(m.u.SP.index, unsparser_row, false)});
                    bp.add_copy_constraint( {round_result.inner_state[1], var(m.u.SP.index, unsparser_row + 1, false)});
                    bp.add_copy_constraint( {round_result.inner_state[2], var(m.u.SP.index, unsparser_row + 2, false)});
                    bp.add_copy_constraint( {round_result.inner_state[3], var(m.u.SP.index, unsparser_row + 3, false)});
                }
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type();
            }

            template<typename BlueprintFieldType>
            typename keccak_dynamic_component<BlueprintFieldType>::result_type generate_assignments(
                const keccak_dynamic_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_dynamic_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t cur_row = start_row_index;

                using component_type = keccak_dynamic_component<BlueprintFieldType>;
                using round_type = typename component_type::round_component_type;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                value_type theta = var_value(assignment, instance_input.rlc_challenge);
                std::cout << "RLC challenge = " << theta << std::endl;

                typename component_type::keccak_map m(component);
                assignment.witness(0, start_row_index + component.rows_amount-1) = value_type(0);

                std::size_t block_counter = 0;
                std::size_t header_row = start_row_index;
                std::size_t footer_row = header_row + component.block_rows_amount - 1;
                std::size_t input_idx = 0;
                std::size_t l;
                std::size_t l_before;
                std::size_t first_in_block;
                value_type rlc;
                value_type rlc_before;
                value_type RLC;
                // Valid blocks

                std::array<value_type, 25> state;
                while( block_counter < component.max_blocks ) {
                    std::cout << std::endl << std::endl << "New message" << std::endl;
                    std::vector<uint8_t> msg;
                    std::pair<value_type, value_type> hash;
                    if( input_idx < instance_input.input.size() ){
                        msg = std::get<0>(instance_input.input[input_idx]);
                        hash = std::get<1>(instance_input.input[input_idx]);
                        input_idx++;
                    } else {
                        msg = {0};
                        hash = {0xbc36789e7a1e281436464229828f817d_cppui_modular254, 0x6612f7b477d66591ff96a9e064bcc98a_cppui_modular254};
                    }
                    auto padded_msg = msg;
                    padded_msg.push_back(1);
                    while( padded_msg.size() % 136 != 0 ){
                        padded_msg.push_back(0);
                    }
/*                  std::cout << "Padded message: ";
                    for(std::size_t i = 0; i < 136; i++){
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::size_t(padded_msg[i]) << " ";
                    }
                    std::cout << std::endl;*/
                    RLC = calculateRLC<BlueprintFieldType>(msg, theta);
                    std::cout << "RLC = " << std::hex << RLC << std::dec << std::endl;
                    for( std::size_t block = 0; block < padded_msg.size()/136; block++){
                        l = msg.size() - block * 136;
                        bool is_first = (block == 0? 1: 0);
                        bool is_last = ((block == padded_msg.size()/136 - 1 )? 1: 0);
                        std::cout  << "Is_last = " << is_last << std::endl;
                        if (is_first) rlc = msg.size();

                        assignment.witness(m.h.is_first.index, header_row) = is_first;
                        assignment.witness(m.h.is_last.index, header_row) = is_last;
                        assignment.witness(m.h.L.index, header_row) = msg.size();
                        assignment.witness(m.h.l.index, header_row) = msg.size() - block * 136;
                        assignment.witness(m.h.hash_hi.index, header_row) = hash.first;
                        assignment.witness(m.h.hash_lo.index, header_row) = hash.second;
                        assignment.witness(m.h.RLC.index, header_row) = RLC;
                        assignment.witness(m.r.index, header_row) = theta;
                        assignment.witness(m.h.rlc_before.index, header_row) = rlc;

                        assignment.witness(m.h.is_first.index, footer_row) = (block == 0? 1: 0);
                        assignment.witness(m.h.is_last.index, footer_row) = ((block == padded_msg.size()/136 - 1 )? 1: 0);
                        assignment.witness(m.h.L.index, footer_row) = msg.size();
                        assignment.witness(m.h.l.index, footer_row) = msg.size() - block * 136;
                        assignment.witness(m.h.hash_hi.index, footer_row) = hash.first;
                        assignment.witness(m.h.hash_lo.index, footer_row) = hash.second;
                        assignment.witness(m.h.RLC.index, footer_row) = RLC;
                        assignment.witness(m.r.index, footer_row) = theta;

                        std::size_t state_row = header_row + component.header_rows_amount;
                        for( std::size_t i = 0; i < component.state_rows_amount; i++ ){
                            assignment.witness(m.s.s0.index, state_row + i ) = state[5 * i];
                            assignment.witness(m.s.s1.index, state_row + i ) = state[5 * i + 1];
                            assignment.witness(m.s.s2.index, state_row + i ) = state[5 * i + 2];
                            assignment.witness(m.s.s3.index, state_row + i ) = state[5 * i + 3];
                            assignment.witness(m.s.s4.index, state_row + i ) = state[5 * i + 4];

                            assignment.witness(m.s.is_first.index, state_row + i) = is_first;
                            assignment.witness(m.s.S0.index, state_row + i) = is_first ? 0 : state[5 * i];
                            assignment.witness(m.s.S1.index, state_row + i) = is_first ? 0 : state[5 * i + 1];
                            assignment.witness(m.s.S2.index, state_row + i) = is_first ? 0 : state[5 * i + 2];
                            assignment.witness(m.s.S3.index, state_row + i) = is_first ? 0 : state[5 * i + 3];
                            assignment.witness(m.s.S4.index, state_row + i) = is_first ? 0 : state[5 * i + 4];
                        }
                        const integral_type sparse_x80 = component.round_tf.sparse_x80 >> 144;
                        const integral_type sparse_x7f = component.round_tf.sparse_x7f >> 144;
                        auto s16 = var_value(assignment, var(m.s.S1.index, state_row + 3, false));
                        auto s16_chunks = sparsed_64bits_to_4_chunks<BlueprintFieldType>(s16);
                        value_type mod = integral_type(s16_chunks[0].data) >= sparse_x80 ? s16_chunks[0] - sparse_x80 : sparse_x7f - s16_chunks[0];
                        value_type XOR = integral_type(s16_chunks[0].data) >= sparse_x80 ? s16_chunks[0] - sparse_x80 : s16_chunks[0] + sparse_x80;
/*                      std::cout <<std::hex
                            << "S16 = " << s16 << ":" << state[16] << " => "
                            << s16_chunks[0] << ", "
                            << s16_chunks[1] << ", "
                            << s16_chunks[2] << ", "
                            << s16_chunks[3] << std::dec << std::endl;
                        std::cout << std::hex << "mod = " << mod << std::dec << std::endl;
                        std::cout << std::hex << "XOR = " << XOR << std::dec << std::endl;
                        std::cout << std::hex << "sparse_x80 = " << sparse_x80 << std::dec << std::endl;
                        std::cout << std::hex << "sparse_x7f = " << sparse_x7f << std::dec << std::endl;
                        std::cout << "State row = " << state_row << std::endl;*/

                        assignment.witness(m.s.rng.index, state_row) = mod;
                        assignment.witness(m.s.rng.index, state_row + 1) = s16_chunks[0];
                        assignment.witness(m.s.rng.index, state_row + 2) = s16_chunks[1];
                        assignment.witness(m.s.rng.index, state_row + 3) = s16_chunks[2];
                        assignment.witness(m.s.rng.index, state_row + 4) = s16_chunks[3];

                        assignment.witness(m.s.XOR.index, state_row) = XOR;
                        assignment.witness(m.s.XOR.index, state_row + 1) = is_last? XOR : s16_chunks[0];
                        assignment.witness(m.s.XOR.index, state_row + 2) = s16_chunks[2];
                        assignment.witness(m.s.XOR.index, state_row + 3) = s16_chunks[0];
                        assignment.witness(m.s.XOR.index, state_row + 4) = s16_chunks[2];

                        assignment.witness(m.s.ch.index, state_row) = is_last;
                        assignment.witness(m.s.ch.index, state_row + 1) = s16_chunks[1];
                        assignment.witness(m.s.ch.index, state_row + 2) = s16_chunks[3];
                        assignment.witness(m.s.ch.index, state_row + 3) = s16_chunks[1];
                        assignment.witness(m.s.ch.index, state_row + 4) = s16_chunks[3];

                        for( std::size_t i = 0; i < component.state_rows_amount; i++ ){
                            assignment.witness(m.s.out.index, state_row+ i) =
                                var_value(assignment, var(m.s.XOR.index, state_row + i - 1, false)) * (integral_type(1) << (48 * 3)) +
                                var_value(assignment, var(m.s.ch.index, state_row + i - 1, false)) * (integral_type(1) << (48 * 2)) +
                                var_value(assignment, var(m.s.XOR.index, state_row + i, false)) * (integral_type(1) << 48) +
                                var_value(assignment, var(m.s.ch.index, state_row + i, false)) ;
//                            std::cout << "state.out " << i << " = " << var_value(assignment, var(m.s.out.index, state_row + i, false)) << std::endl;
                        }
/*
                        std::cout << "First expression part " << std::hex << (var_value(assignment, var(m.s.rng.index, state_row + 1, false)) - 5026338869833) + var_value(assignment, var(m.s.rng.index, state_row, false)) << std::endl;
                        std::cout << "Second expression part " << ((var_value(assignment, var(m.s.rng.index, state_row + 1, false)) + 35184372088832) - var_value(assignment, var(m.s.rng.index, state_row, false))) << std::endl;
                        std::cout << "chunk = " << var_value(assignment, var(m.s.rng.index, state_row + 1, false)) << std::endl;
                        std::cout << "mod = " << var_value(assignment, var(m.s.rng.index, state_row, false)) << std::dec << std::endl;
*/
/*                        std::cout << "Sparse_x80 = " << std::hex
                            << component.round_tf.sparse_x80 << "=>"
                            << unpack<BlueprintFieldType>(component.round_tf.sparse_x80)
                            << std::dec << std::endl;
*/
                        std::size_t chunks_row = state_row + component.state_rows_amount;
                        for( std::size_t i = 0; i < component.chunks_rows_amount; i++ ){
                            first_in_block = (i == 0) ? 1 : 0;
                            l_before = l;
                            rlc_before = rlc;
                            if( l > 4 ) l -= 4; else l = 0;

                            std::size_t msg_idx = 136 * block + 4 * i;
                            assignment.witness(m.r.index, chunks_row + i) = theta;
                            assignment.witness(m.c.b0.index, chunks_row + i) = padded_msg[msg_idx];
                            assignment.witness(m.c.b1.index, chunks_row + i) = padded_msg[msg_idx + 1];
                            assignment.witness(m.c.b2.index, chunks_row + i) = padded_msg[msg_idx + 2];
                            assignment.witness(m.c.b3.index, chunks_row + i) = padded_msg[msg_idx + 3];
                            auto sp0 = pack<BlueprintFieldType>(integral_type(padded_msg[msg_idx + 1]) * 256 + integral_type(padded_msg[msg_idx ]));
                            auto sp1 = pack<BlueprintFieldType>(integral_type(padded_msg[msg_idx + 3]) * 256 + integral_type(padded_msg[msg_idx + 2]));
                            value_type sp0_prev = var_value(assignment, var(m.c.sp0.index, chunks_row +i - 1, false));
                            value_type sp1_prev = var_value(assignment, var(m.c.sp1.index, chunks_row +i - 1, false));
                            assignment.witness(m.c.sp0.index, chunks_row +i) = sp0;
                            assignment.witness(m.c.sp1.index, chunks_row +i) = sp1;

                            value_type chunk_factor = value_type(integral_type(1) << 48 );
                            value_type chunk = sp1 * chunk_factor + sp0;
                            chunk = chunk * chunk_factor + sp1_prev;
                            chunk = chunk * chunk_factor + sp0_prev;


                            assignment.witness(m.c.chunk.index, chunks_row + i) = chunk;
//                            if( i%2 == 1 )
//                              std::cout << "Block " << block_counter << ", chunk " << i/2 << ": "  << std::hex
//                                    << sp0_prev << ", " << sp1_prev << ", " << sp0 << ", " << sp1 << " =>"  <<  chunk
//                                << std::dec << std::endl;
                            assignment.witness(m.c.first_in_block.index, chunks_row + i) = first_in_block;
                            assignment.witness(m.c.l.index, chunks_row + i) = l;
                            assignment.witness(m.c.l_before.index, chunks_row + i) = l_before;
                            assignment.witness(m.c.rlc_before.index, chunks_row + i) = rlc_before;
                            assignment.witness(m.c.r2.index, chunks_row + i) = theta * theta;
                            assignment.witness(m.c.r4.index, chunks_row + i) = theta * theta * theta * theta;
                            if (l_before - l == 4)
                                    rlc = rlc_before * theta * theta * theta * theta +
                                    msg[msg_idx] * theta * theta * theta +
                                    msg[msg_idx + 1] * theta * theta +
                                    msg[msg_idx + 2] * theta + msg[msg_idx + 3];
                            else if (l_before - l == 3)
                                rlc = rlc_before * theta * theta * theta +
                                    msg[msg_idx] * theta * theta +
                                    msg[msg_idx + 1] * theta +
                                    msg[msg_idx + 2];
                            else if (l_before - l == 2)
                                rlc = rlc_before * theta * theta +
                                    msg[msg_idx] * theta +
                                    msg[msg_idx + 1];
                            else if (l_before - l == 1)
                                rlc = rlc_before * theta + msg[msg_idx];
                            else
                                rlc = rlc_before;
                            assignment.witness(m.c.rlc.index, chunks_row + i) = rlc;
                            std::cout << std::hex
                                << std::size_t(padded_msg[msg_idx]) << ", " << std::size_t(padded_msg[msg_idx + 1]) << ", "
                                << std::size_t(padded_msg[msg_idx + 2]) << ", " << std::size_t(padded_msg[msg_idx + 3])
                                <<  std::dec <<  "  l="<< l << "  l_before=" << l_before
                                <<  std::hex <<  "  rlc="<< rlc << "  rlc_before=" << rlc_before << std::dec
                                << " first_in_block = " << first_in_block << std::endl;
                        }
                        assignment.witness(m.h.rlc_after.index, header_row) = rlc;
                        assignment.witness(m.h.rlc_before.index, footer_row) = rlc;

                        std::array<var, 25> inner_state;
                        for (std::size_t i = 0; i < 5; i++) {
                            inner_state[5 * i    ] = var(m.s.S0.index, state_row + i, false);
                            inner_state[5 * i + 1] = var(m.s.S1.index, state_row + i, false);
                            inner_state[5 * i + 2] = var(m.s.S2.index, state_row + i, false);
                            inner_state[5 * i + 3] = var(m.s.S3.index, state_row + i, false);
                            inner_state[5 * i + 4] = var(m.s.S4.index, state_row + i, false);
                        }
                        inner_state[16] = var(m.s.out.index, state_row + 2, false);

                        std::size_t offset = 0;
                        std::array<var, 17> pmc;
                        for (std::size_t i = 0; i < 17; i++ ){
                            pmc[i] = var(m.c.chunk.index, chunks_row + 2 * i + 1, false);
                        }

                        std::size_t rounds_row = chunks_row + component.chunks_rows_amount;
                        for (std::size_t j = 0; j < 24; ++j) {
                            typename round_type::input_type round_input = {
                                inner_state, pmc,
                                var(component.C(0), start_row_index + j + 2, false, var::column_type::constant)
                            };

                            if (j == 0) {
                                typename round_type::result_type round_result =
                                    generate_assignments(component.round_tf, assignment, round_input, rounds_row);
                                inner_state = round_result.inner_state;
                                rounds_row += component.round_tf.rows_amount;
                            } else {
                                typename round_type::result_type round_result =
                                    generate_assignments(component.round_ff, assignment, round_input, rounds_row);
                                inner_state = round_result.inner_state;
                                rounds_row += component.round_ff.rows_amount;
                            }
                        }
                        for( std::size_t i = 0; i < 25; i++ ){
                            state[i] = var_value(assignment, inner_state[i]);
                        }

                        std::cout << "Sparse hash chunks : " << std::endl;
                        std::array<value_type, 4> result;
                        for( std::size_t i = 0; i < 4; i++ ){
                            value_type sparse_value = var_value(assignment, inner_state[i]);
                            result[i] = sparse_value;
                            //std::cout << "\t" << std::hex << sparse_value << std::dec << std::endl;
                            value_type regular = unpack<BlueprintFieldType>(sparse_value);
                            std::cout << "\t" << std::hex << regular << std::dec << " ";
                        }
                        std::cout << std::endl;

                        assert(rounds_row == footer_row - component.unsparser_rows_amount);
                        std::size_t unsparser_row = footer_row - component.unsparser_rows_amount;
                        integral_type chunk_factor = integral_type(1) << 16;
                        for( std::size_t i = 0; i < component.unsparser_rows_amount; i++ ){
                            auto chunks = sparsed_64bits_to_4_chunks<BlueprintFieldType>(result[i]);
                            assignment.witness( m.u.SP.index, unsparser_row + i ) = result[i];
                            assignment.witness( m.u.sp0.index, unsparser_row + i) = chunks[0];
                            assignment.witness( m.u.sp1.index, unsparser_row + i) = chunks[1];
                            assignment.witness( m.u.sp2.index, unsparser_row + i) = chunks[2];
                            assignment.witness( m.u.sp3.index, unsparser_row + i) = chunks[3];
                            assignment.witness( m.u.ch0.index, unsparser_row + i) = swap_bytes<BlueprintFieldType>(unpack<BlueprintFieldType>(chunks[0]));
                            assignment.witness( m.u.ch1.index, unsparser_row + i) = swap_bytes<BlueprintFieldType>(unpack<BlueprintFieldType>(chunks[1]));
                            assignment.witness( m.u.ch2.index, unsparser_row + i) = swap_bytes<BlueprintFieldType>(unpack<BlueprintFieldType>(chunks[2]));
                            assignment.witness( m.u.ch3.index, unsparser_row + i) = swap_bytes<BlueprintFieldType>(unpack<BlueprintFieldType>(chunks[3]));
                            assignment.witness( m.u.hash_chunk.index, unsparser_row + i) =
                                var_value(assignment, var(m.u.ch3.index, unsparser_row + i - 1, false)) * (chunk_factor  << (16 * 6)) +
                                var_value(assignment, var(m.u.ch2.index, unsparser_row + i - 1, false)) * (chunk_factor  << (16 * 5)) +
                                var_value(assignment, var(m.u.ch1.index, unsparser_row + i - 1, false)) * (chunk_factor  << (16 * 4)) +
                                var_value(assignment, var(m.u.ch0.index, unsparser_row + i - 1, false)) * (chunk_factor  << (16 * 3)) +
                                var_value(assignment, var(m.u.ch3.index, unsparser_row + i, false)) * (chunk_factor  << (16 * 2)) +
                                var_value(assignment, var(m.u.ch2.index, unsparser_row + i, false)) * (chunk_factor  << (16)) +
                                var_value(assignment, var(m.u.ch1.index, unsparser_row + i, false)) * chunk_factor +
                                var_value(assignment, var(m.u.ch0.index, unsparser_row + i, false));
                        }
                        assignment.witness(m.h.hash_cur_hi.index, header_row) = var_value(assignment, var(m.u.hash_chunk.index, unsparser_row + 1, false));
                        assignment.witness(m.h.hash_cur_lo.index, header_row) = var_value(assignment, var(m.u.hash_chunk.index, unsparser_row + 3, false));

                        if( is_last ){
                            std::cout << "Previous hash: " << std::hex
                                << var_value(assignment, var(m.h.hash_hi.index, header_row, false)) << " "
                                << var_value(assignment, var(m.h.hash_lo.index, header_row, false)) << " " << std::endl;
                            std::cout << "Current hash: " << std::hex
                                << var_value(assignment, var(m.h.hash_cur_hi.index, header_row, false)) << " "
                                << var_value(assignment, var(m.h.hash_cur_lo.index, header_row, false)) << " " << std::endl;
                            std::cout << "Final hash: " << std::hex
                                << var_value(assignment, var(m.u.hash_chunk.index, unsparser_row + 1, false)) << " "
                                << var_value(assignment, var(m.u.hash_chunk.index, unsparser_row + 3, false)) << std::dec << std::endl;
                        }

                        block_counter++;
                        header_row += component.block_rows_amount;
                        footer_row += component.block_rows_amount;
                    }
                }
                return typename component_type::result_type();
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const keccak_dynamic_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename keccak_dynamic_component<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = 0;
                assignment.constant(component.C(0), start_row_index + 1) = 1;
                std::size_t row = start_row_index + 2;
                for (std::size_t i = 0; i < 24; ++i) {
                    assignment.constant(component.C(0), row + i) = pack<BlueprintFieldType>(
                        typename BlueprintFieldType::value_type(component.round_constant[i])
                    );
                }
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_ROUND_HPP