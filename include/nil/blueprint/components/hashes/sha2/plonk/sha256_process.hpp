//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256_PROCESS component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_PROCESS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_PROCESS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: [x_0, x_1, x_2] \in Fp
            // Output: [y_0, y_1, y_2] - SHA256 permutation of [x_0, x_1, x_2]
            template<typename ArithmetizationType>
            class sha256_process;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class sha256_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return sha256_process::gates_amount + sha256_process::lookup_gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<nil::blueprint::manifest_param>(
                            new nil::blueprint::manifest_single_value_param(9)),
                        true
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 762;
                }

                constexpr static const std::size_t rounds_amount = 64;

                constexpr static const std::size_t base4 = 4;
                constexpr static const std::size_t base7 = 7;

                constexpr static const std::array<typename BlueprintFieldType::value_type, rounds_amount>
                    round_constant = {
                        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                constexpr static const std::size_t gates_amount = 11;
                constexpr static const std::size_t lookup_gates_amount = 8;
                struct input_type {
                    std::array<var, 8> input_state;
                    std::array<var, 16> input_words;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(24);
                        result.insert(result.end(), input_state.begin(), input_state.end());
                        result.insert(result.end(), input_words.begin(), input_words.end());
                        return result;
                    }
                };

                struct result_type {
                    std::array<var, 8> output_state;

                    result_type(const sha256_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                ArithmetizationParams>>
                                    &component,
                                std::uint32_t start_row_index) {
                        output_state = {var(component.W(0), start_row_index + component.rows_amount - 7, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 7, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 7, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 7, false),
                                        var(component.W(0), start_row_index + component.rows_amount - 5, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 5, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 5, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 5, false)};
                    }

                    std::vector<var> all_vars() const {
                        std::vector<var> result;
                        result.reserve(8);
                        result.insert(result.end(), output_state.begin(), output_state.end());
                        return result;
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                sha256_process(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                sha256_process(std::initializer_list<typename component_type::witness_container_type::value_type>
                                   witnesses,
                               std::initializer_list<typename component_type::constant_container_type::value_type>
                                   constants,
                               std::initializer_list<typename component_type::public_input_container_type::value_type>
                                   public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};


                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["sha256_sparse_base4/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base4/first_column"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_reverse_sparse_base4/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base7/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base7/first_column"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_reverse_sparse_base7/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_maj/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_ch/full"] = 0; // REQUIRED_TABLE

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_sha256_process =
                sha256_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            namespace detail {

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_assignments_constant(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                    std::size_t row = start_row_index + 242 + 3;
                    for (std::size_t i = 0; i < 64; i++) {
                        assignment.constant(component.C(0), row + i * 8) =
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::round_constant[i];
                    }
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t,2> generate_sigma0_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    std::array<std::size_t, 2> selectors;

                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                    const std::array<var, 4> a_chunks_0 = {
                        var(component.W(1), -1), var(component.W(2), -1),
                        var(component.W(3), -1), var(component.W(4), -1)};
                    const std::array<var, 4> a_chunks_1 = {
                        var(component.W(7), -1), var(component.W(2), 0),
                        var(component.W(3), 0), var(component.W(4), 0)};
                    const std::array<std::array<var, 4>, 2> a_chunks = {a_chunks_0, a_chunks_1};

                    const std::array<var, 4> sigma0_chunks_0 = {
                        var(component.W(1), +1), var(component.W(2), +1),
                        var(component.W(3), +1), var(component.W(4), +1)};
                    const std::array<var, 4> sigma0_chunks_1 = {
                        var(component.W(5), 0), var(component.W(6), 0),
                        var(component.W(7), 0), var(component.W(8), 0)};
                    const std::array<std::array<var, 4>, 2> sigma0_chunks = {sigma0_chunks_0, sigma0_chunks_1};

                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 =
                        var(component.W(0), -1) -
                        (a_chunks[0][0] + a_chunks[0][1] * (one << 3) +
                         a_chunks[0][2] * (one << 7) + a_chunks[0][3] * (one << 18));
                    auto constraint_2 =
                        (a_chunks[0][0] - 7) * (a_chunks[0][0] - 6) * (a_chunks[0][0] - 5) *
                        (a_chunks[0][0] - 4) * (a_chunks[0][0] - 3) * (a_chunks[0][0] - 2) *
                        (a_chunks[0][0] - 1) * a_chunks[0][0];
                    auto constraint_3 =
                        sigma0_chunks[1][0] + sigma0_chunks[1][1] * (1 << 16) +
                        sigma0_chunks[1][2] * (one << 32) + sigma0_chunks[1][3] * (one << 48) -
                        (a_chunks[1][1] * (1 + (one << 56) + (one << 34)) +
                        a_chunks[1][2] * ((one << 8) + 1 + (one << 42)) +
                        a_chunks[1][3] * ((1 << 30) + (1 << 22) + 1) +
                        a_chunks[1][0] * ((one << 50) + (1 << 28)));

                    selectors[0] = bp.add_gate(
                        {constraint_1, constraint_2, constraint_3});

                    lookup_constraint lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][0], a_chunks[1][0]}};
                    lookup_constraint lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_chunks[0][1] * 1024}};
                    lookup_constraint lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][1], a_chunks[1][1]}};
                    lookup_constraint lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_chunks[0][2] * 8}};
                    lookup_constraint lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][2], a_chunks[1][2]}};
                    lookup_constraint lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][3], a_chunks[1][3]}};
                    lookup_constraint lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma0_chunks[0][0], sigma0_chunks[1][0]}};
                    lookup_constraint lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma0_chunks[0][1], sigma0_chunks[1][1]}};
                    lookup_constraint lookup_constraint_9 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma0_chunks[0][2], sigma0_chunks[1][2]}};
                    lookup_constraint lookup_constraint_10 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma0_chunks[0][3], sigma0_chunks[1][3]}};

                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1,
                        lookup_constraint_2,
                        lookup_constraint_3,
                        lookup_constraint_4,
                        lookup_constraint_5,
                        lookup_constraint_6,
                        lookup_constraint_7,
                        lookup_constraint_8,
                        lookup_constraint_9,
                        lookup_constraint_10
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2> generate_sigma1_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    std::array<std::size_t, 2> selectors;
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                    const std::array<var, 4> b_chunks_0 = {
                        var(component.W(1), 0), var(component.W(2), 0),
                        var(component.W(3), 0), var(component.W(4), 0)};
                    const std::array<var, 4> b_chunks_1 = {
                        var(component.W(1), -1), var(component.W(2), -1),
                        var(component.W(3), -1), var(component.W(4), -1)};
                    const std::array<std::array<var, 4>, 2> b_chunks = {b_chunks_0, b_chunks_1};

                    const std::array<var, 4> sigma1_chunks_1 = {
                        var(component.W(5), -1), var(component.W(6), -1),
                        var(component.W(7), -1), var(component.W(8), -1)};
                    const var integral_a2 = var(component.W(8), 0);
                    const std::array<var, 3> integral_a2_chunks = {
                        var(component.W(5), 0), var(component.W(6), 0),
                        var(component.W(7), 0)};

                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 =
                        var(component.W(0), 0) -
                            (b_chunks[0][0] + b_chunks[0][1] * (1 << 10) +
                             b_chunks[0][2] * (1 << 17) + b_chunks[0][3] * (1 << 19));
                    auto constraint_2 =
                        (b_chunks[0][2] - 3) * (b_chunks[0][2] - 2) *
                        (b_chunks[0][2] - 1) * b_chunks[0][2];
                    auto constraint_3 =
                        sigma1_chunks_1[0] + sigma1_chunks_1[1] * (one << 16) +
                        sigma1_chunks_1[2] * (one << 32) + sigma1_chunks_1[3] * (one << 48) -
                        (b_chunks[1][1] * (1 + (one << 50) + (one << 46)) +
                         b_chunks[1][2] * ((one << 14) + 1 + (one << 60)) +
                         b_chunks[1][3] * ((one << 18) + (one << 4) + 1) +
                         b_chunks[1][0] * ((one << 30) + (1 << 26)));

                    auto constraint_4 = -integral_a2 +
                        integral_a2_chunks[0] + integral_a2_chunks[1] * (1 << 14) + integral_a2_chunks[2] * (1 << 28);

                    selectors[0] = bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4});

                    lookup_constraint lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {b_chunks[0][0] * 16}};
                    lookup_constraint lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {b_chunks[0][0], b_chunks[1][0]}};
                    lookup_constraint lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {b_chunks[0][1] * 128}};
                    lookup_constraint lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {b_chunks[0][1], b_chunks[1][1]}};
                    lookup_constraint lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {b_chunks[0][3] * 2}};
                    lookup_constraint lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {b_chunks[0][2], b_chunks[1][2]}};
                    lookup_constraint lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {b_chunks[0][3], b_chunks[1][3]}};

                    lookup_constraint lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[0]}};
                    lookup_constraint lookup_constraint_9 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[1]}};
                    lookup_constraint lookup_constraint_10 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[2]}};
                    lookup_constraint lookup_constraint_11 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[2] * (1 << 10)}};
                    lookup_constraint lookup_constraint_12 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(0), -1)}};
                    lookup_constraint lookup_constraint_13 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(0), -1) * (1 << 10)}};

                    selectors[1] =  bp.add_lookup_gate({
                        lookup_constraint_1,
                        lookup_constraint_2,
                        lookup_constraint_3,
                        lookup_constraint_4,
                        lookup_constraint_5,
                        lookup_constraint_6,
                        lookup_constraint_7,
                        lookup_constraint_8,
                        lookup_constraint_9,
                        lookup_constraint_10,
                        lookup_constraint_11,
                        lookup_constraint_12,
                        lookup_constraint_13
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 6> generate_message_scheduling_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {

                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                    std::array<std::size_t, 2> sigma0_selectors =
                        generate_sigma0_gates(component, bp, assignment, lookup_tables_indices);
                    typename BlueprintFieldType::integral_type one = 1;
                    auto m = typename BlueprintFieldType::value_type(2).pow(32);
                    std::array<var, 4> sigma0_chunks_0 = {
                        var(component.W(1), 0), var(component.W(2), 0),
                        var(component.W(3), 0), var(component.W(4), 0)};
                    std::array<var, 4> sigma1_chunks_0 = {
                        var(component.W(5), 0), var(component.W(6), 0),
                        var(component.W(7), 0), var(component.W(8), 0)};
                    std::array<var, 4> sigma1_chunks_1 = {
                        var(component.W(5), +1), var(component.W(6), +1),
                        var(component.W(7), +1), var(component.W(8), +1)};
                    std::array<std::array<var, 4>, 2> sigma1_chunks = {sigma1_chunks_0, sigma1_chunks_1};
                    auto constraint_1 =
                        var(component.W(0), 0) + m * var(component.W(0), +1) -
                            (var(component.W(0), -1) + var(component.W(1), -1) + sigma0_chunks_0[0] +
                            sigma0_chunks_0[1] * (one << 8) + sigma0_chunks_0[2] * (one << 16) +
                            sigma0_chunks_0[3] * (one << 24) + sigma1_chunks[0][0] +
                            sigma1_chunks[0][1] * (one << 8) + sigma1_chunks[0][2] * (one << 16) +
                            sigma1_chunks[0][3] * (one << 24));
                    auto constraint_2 =
                        (var(component.W(0), +1) - 3) * (var(component.W(0), +1) - 2) *
                        (var(component.W(0), +1) - 1) * var(component.W(0), +1);
                    std::size_t selector_1 = bp.add_gate({constraint_1, constraint_2});
                    lookup_constraint lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma1_chunks[0][0], sigma1_chunks[1][0]}};
                    lookup_constraint lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma1_chunks[0][1], sigma1_chunks[1][1]}};
                    lookup_constraint lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma1_chunks[0][2], sigma1_chunks[1][2]}};
                    lookup_constraint lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {sigma1_chunks[0][3], sigma1_chunks[1][3]}};
                    std::size_t sigma1_check = bp.add_lookup_gate({
                        lookup_constraint_1,
                        lookup_constraint_2,
                        lookup_constraint_3,
                        lookup_constraint_4
                    });
                    std::array<std::size_t, 2> sigma_1_selectors =
                        generate_sigma1_gates(component, bp, assignment, lookup_tables_indices);
                    return {sigma0_selectors[0], sigma0_selectors[1], selector_1,
                            sigma1_check, sigma_1_selectors[0], sigma_1_selectors[1]};
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2> generate_Sigma0_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                    std::array<std::size_t, 2> selectors;
                    typename BlueprintFieldType::integral_type one = 1;

                    var a2 = var(component.W(0), +1);
                    var a_new = var(component.W(2), -1);

                    std::array<var, 4> a_chunks_0 = {
                        var(component.W(2), +1), var(component.W(3), +1),
                        var(component.W(4), +1), var(component.W(5), +1)};
                    std::array<var, 4> a_chunks_1 = {
                        var(component.W(2), 0), var(component.W(3), 0),
                        var(component.W(4), 0), var(component.W(5), 0)};
                    std::array<std::array<var, 4>, 2> a_chunks = {a_chunks_0, a_chunks_1};

                    std::array<var, 4> Sigma0_chunks_0 = {
                        var(component.W(5), -1), var(component.W(6), -1),
                        var(component.W(7), -1), var(component.W(8), -1)};
                    std::array<var, 4> Sigma0_chunks_1 = {
                        var(component.W(0), 0), var(component.W(1), 0),
                        var(component.W(6), 0), var(component.W(7), 0)};
                    std::array<std::array<var, 4>, 2> Sigma0_chunks = {Sigma0_chunks_0, Sigma0_chunks_1};

                    std::array<var, 3> a_new_chunks = {
                        var(component.W(6), +1), var(component.W(7), +1), var(component.W(8), +1)};

                    auto constraint_1 =
                        a2 - (a_chunks[0][0] + a_chunks[0][1] * (1 << 2) +
                              a_chunks[0][2] * (1 << 13) + a_chunks[0][3] * (1 << 22));
                    auto constraint_2 =
                        var(component.W(0), -1) -
                            (a_chunks[1][0] + a_chunks[1][1] * (1 << 4) +
                             a_chunks[1][2] * (1 << 26) + a_chunks[1][3] * (one << 44));
                    auto constraint_3 =
                        (a_chunks[0][0] - 3) * (a_chunks[0][0] - 2) *
                        (a_chunks[0][0] - 1) * a_chunks[0][0];
                    auto constraint_4 =
                        Sigma0_chunks[1][0] + Sigma0_chunks[1][1] * (1 << 16) +
                            Sigma0_chunks[1][2] * (one << 32) + Sigma0_chunks[1][3] * (one << 48) -
                                (a_chunks[1][0] * ((one << 38) + (1 << 20) + (one << 60)) +
                                 a_chunks[1][1] * ((one << 42) + 1 + (1 << 24)) +
                                 a_chunks[1][2] * ((1 << 22) + (one << 46) + 1) +
                                 a_chunks[1][3] * ((one << 40) + (1 << 18) + 1));

                    auto constraint_7 = -a_new +
                        a_new_chunks[0] + a_new_chunks[1] * (1 << 14) + a_new_chunks[2] * (1 << 28);

                    selectors[0] = bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_7});

                    lookup_constraint_type lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_chunks[0][1] * 8}};
                    lookup_constraint_type lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][0], a_chunks[1][0]}};
                    lookup_constraint_type lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_chunks[0][2] * 32}};
                    lookup_constraint_type lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][1], a_chunks[1][1]}};
                    lookup_constraint_type lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_chunks[0][3] * 16}};
                    lookup_constraint_type lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][2], a_chunks[1][2]}};
                    lookup_constraint_type lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_sparse_base4/full"),
                         {a_chunks[0][3], a_chunks[1][3]}};
                    lookup_constraint_type lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {Sigma0_chunks[0][0], Sigma0_chunks[1][0]}};
                    lookup_constraint_type lookup_constraint_9 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {Sigma0_chunks[0][1], Sigma0_chunks[1][1]}};
                    lookup_constraint_type lookup_constraint_10 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {Sigma0_chunks[0][2], Sigma0_chunks[1][2]}};
                    lookup_constraint_type lookup_constraint_11 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base4/full"),
                         {Sigma0_chunks[0][3], Sigma0_chunks[1][3]}};

                    lookup_constraint_type lookup_constraint_12 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_new_chunks[0]}};
                    lookup_constraint_type lookup_constraint_13 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_new_chunks[1]}};
                    lookup_constraint_type lookup_constraint_14 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_new_chunks[2]}};
                    lookup_constraint_type lookup_constraint_15 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {a_new_chunks[2] * (1 << 10)}};
                    lookup_constraint_type lookup_constraint_16 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(3), -1)}};
                    lookup_constraint_type lookup_constraint_17 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(3), -1) * (1 << 8)}};

                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1,
                        lookup_constraint_2,
                        lookup_constraint_3,
                        lookup_constraint_4,
                        lookup_constraint_5,
                        lookup_constraint_6,
                        lookup_constraint_7,
                        lookup_constraint_8,
                        lookup_constraint_9,
                        lookup_constraint_10,
                        lookup_constraint_11,
                        lookup_constraint_12,
                        lookup_constraint_13,
                        lookup_constraint_14,
                        lookup_constraint_15,
                        lookup_constraint_16,
                        lookup_constraint_17
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2> generate_Sigma1_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    std::array<std::size_t, 2> selectors;
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                    typename BlueprintFieldType::integral_type one = 1;
                    typename BlueprintFieldType::value_type base7_value =
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7;
                    std::array<var, 4> e_chunks_0 = {
                        var(component.W(2), -1), var(component.W(3), -1),
                        var(component.W(4), -1), var(component.W(5), -1)};
                    std::array<var, 4> e_chunks_1 = {
                        var(component.W(1), -1), var(component.W(2), 0),
                        var(component.W(3), 0), var(component.W(4), 0)};
                    std::array<std::array<var, 4>, 4> e_chunks = {e_chunks_0, e_chunks_1};
                    std::array<var, 4> Sigma1_chunks_0 = {
                        var(component.W(5), +1), var(component.W(6), +1),
                        var(component.W(7), +1), var(component.W(8), +1)
                    };
                    std::array<var, 4> Sigma1_chunks_1 = {
                        var(component.W(5), 0), var(component.W(6), -1),
                        var(component.W(7), -1), var(component.W(8), -1)
                    };
                    std::array<std::array<var, 4>, 2> Sigma1_chunks = {Sigma1_chunks_0, Sigma1_chunks_1};
                    auto constraint_1 =
                        var(component.W(0), -1) -
                            (e_chunks[0][0] + e_chunks[0][1] * (1 << 6) +
                             e_chunks[0][2] * (1 << 11) + e_chunks[0][3] * (1 << 25));
                    auto constraint_2 =
                        var(component.W(0), 0) -
                            (e_chunks[1][0] + e_chunks[1][1] * base7_value.pow(6) +
                             e_chunks[1][2] * base7_value.pow(11) + e_chunks[1][3] * base7_value.pow(25));
                    auto constraint_3 =
                        Sigma1_chunks[1][0] + Sigma1_chunks[1][1] * base7_value.pow(8) +
                        Sigma1_chunks[1][2] * base7_value.pow(16) + Sigma1_chunks[1][3] * base7_value.pow(24) -
                        (e_chunks[1][1] * (base7_value.pow(27) + base7_value.pow(13) + 1) +
                         e_chunks[1][2] * (base7_value.pow(5) + 1 + base7_value.pow(18)) +
                         e_chunks[1][3] * (base7_value.pow(19) + base7_value.pow(14) + 1) +
                         e_chunks[1][0] * (base7_value.pow(26) + base7_value.pow(21) + base7_value.pow(7)));

                    selectors[0] = bp.add_gate({constraint_1, constraint_2, constraint_3});

                    lookup_constraint lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_sparse_base7/first_column"),
                         {e_chunks[0][1] * 256}};
                    lookup_constraint lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_sparse_base7/full"),
                         {e_chunks[0][0], e_chunks[1][0]}};
                    lookup_constraint lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_sparse_base7/first_column"),
                         {e_chunks[0][1] * 512}};
                    lookup_constraint lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_sparse_base7/full"),
                         {e_chunks[0][1], e_chunks[1][1]}};
                    lookup_constraint lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base7/first_column"),
                         {e_chunks[0][3] * 128}};
                    lookup_constraint lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base7/full"),
                         {e_chunks[0][2], e_chunks[1][2]}};
                    lookup_constraint lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_sparse_base7/full"),
                         {e_chunks[0][3], e_chunks[1][3]}};
                    lookup_constraint lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base7/full"),
                         {Sigma1_chunks[0][0], Sigma1_chunks[1][0]}};
                    lookup_constraint lookup_constraint_9 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base7/full"),
                         {Sigma1_chunks[0][1], Sigma1_chunks[1][1]}};
                    lookup_constraint lookup_constraint_10 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base7/full"),
                         {Sigma1_chunks[0][2], Sigma1_chunks[1][2]}};
                    lookup_constraint lookup_constraint_11 =
                        {lookup_tables_indices.at("sha256_reverse_sparse_base7/full"),
                         {Sigma1_chunks[0][3], Sigma1_chunks[1][3]}};

                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1,
                        lookup_constraint_2,
                        lookup_constraint_3,
                        lookup_constraint_4,
                        lookup_constraint_5,
                        lookup_constraint_6,
                        lookup_constraint_7,
                        lookup_constraint_8,
                        lookup_constraint_9,
                        lookup_constraint_10,
                        lookup_constraint_11
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2> generate_Maj_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices
                ) {
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                    std::array<std::size_t, 2> selectors;

                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 =
                        var(component.W(0), 0) + var(component.W(1), 0) * (1 << 16) +
                        var(component.W(2), 0) * (one << 32) + var(component.W(3), 0) * (one << 48) -
                        (var(component.W(0), +1) + var(component.W(1), +1) + var(component.W(4), +1));
                    selectors[0] = bp.add_gate({constraint_1});

                    lookup_constraint lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_maj/full"), {var(component.W(5), 0), var(component.W(0), 0)}};
                    lookup_constraint lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_maj/full"), {var(component.W(6), 0), var(component.W(1), 0)}};
                    lookup_constraint lookup_constraint_3=
                        {lookup_tables_indices.at("sha256_maj/full"), {var(component.W(7), 0), var(component.W(2), 0)}};
                    lookup_constraint lookup_constraint_4=
                        {lookup_tables_indices.at("sha256_maj/full"), {var(component.W(8), 0), var(component.W(3), 0)}};
                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1, lookup_constraint_2, lookup_constraint_3, lookup_constraint_4
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2> generate_Ch_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;
                    using lookup_constraint = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                    std::array<std::size_t, 2> selectors;

                    typename BlueprintFieldType::value_type base7_value =
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7;
                    var e_new = var(component.W(4), +1);
                    std::array<var, 3> integral_a2_chunks = {
                        var(component.W(6), -1), var(component.W(7), -1), var(component.W(8), -1)};
                    std::array<var, 4> ch_chunks_0 = {
                        var(component.W(5), +1), var(component.W(6), +1),
                        var(component.W(7), +1), var(component.W(8), +1)};
                    std::array<var, 4> ch_chunks_1 = {
                        var(component.W(0), 0), var(component.W(1), 0),
                        var(component.W(2), 0), var(component.W(3), 0)};
                    std::array<std::array<var, 4>, 2> ch_chunks = {ch_chunks_0, ch_chunks_1};

                    auto constraint_1 =
                        ch_chunks[1][0] + ch_chunks[1][1] * base7_value.pow(8) +
                        ch_chunks[1][2] * base7_value.pow(16) + ch_chunks[1][3] * base7_value.pow(24) -
                        (var(component.W(0), -1) + 2 * var(component.W(1), -1) + 3 * var(component.W(0), +1));


                    auto constraint_2 = -1 * e_new +
                        integral_a2_chunks[0] + integral_a2_chunks[1] * (1 << 14) + integral_a2_chunks[2] * (1 << 28);

                    selectors[0] =  bp.add_gate({constraint_1, constraint_2});

                    lookup_constraint lookup_constraint_1 =
                       {lookup_tables_indices.at("sha256_ch/full"),
                        {ch_chunks[0][0], ch_chunks[1][0]}};
                    lookup_constraint lookup_constraint_2 =
                       {lookup_tables_indices.at("sha256_ch/full"),
                        {ch_chunks[0][1], ch_chunks[1][1]}};
                    lookup_constraint lookup_constraint_3 =
                       {lookup_tables_indices.at("sha256_ch/full"),
                        {ch_chunks[0][2], ch_chunks[1][2]}};
                    lookup_constraint lookup_constraint_4 =
                       {lookup_tables_indices.at("sha256_ch/full"),
                        {ch_chunks[0][3], ch_chunks[1][3]}};

                    lookup_constraint lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[0]}};
                    lookup_constraint lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[1]}};
                    lookup_constraint lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {integral_a2_chunks[2]}};
                    lookup_constraint lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(4), 0)}};
                    lookup_constraint lookup_constraint_9 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"),
                         {var(component.W(4), 0) * (1 << 9)}};

                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1, lookup_constraint_2, lookup_constraint_3, lookup_constraint_4,
                        lookup_constraint_5, lookup_constraint_6, lookup_constraint_7, lookup_constraint_8, lookup_constraint_9
                    });
                    return selectors;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 11> generate_compression_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type &lookup_tables_indices
                ) {
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;

                    std::array<std::size_t, 2> sigma_1_selectors = generate_Sigma1_gates(component, bp, assignment, lookup_tables_indices);
                    std::array<std::size_t, 2> ch_selectors = generate_Ch_gates(component, bp, assignment, lookup_tables_indices);
                    auto m = typename BlueprintFieldType::value_type(2).pow(32);
                    auto constraint_1 =
                        var(component.W(4), +1) -
                        (var(component.W(2), 0) + var(component.W(5), -1) + var(component.W(6), -1) * (1 << 8) +
                         var(component.W(7), -1) * (1 << 16) + var(component.W(8), -1) * (1 << 24) +
                         var(component.W(5), 0) + var(component.W(6), 0) * (1 << 8) +
                         var(component.W(7), 0) * (1 << 16) + var(component.W(8), 0) * (1 << 24) +
                         var(component.C(0), 0, true, var::column_type::constant) + var(component.W(3), 0));
                    auto constraint_2 = var(component.W(4), 0) + m * var(component.W(4), -1) -
                                                          (var(component.W(1), 0) + var(component.W(4), +1));
                    auto constraint_3 =
                        (var(component.W(4), -1) - 5) * (var(component.W(4), -1) - 4) * (var(component.W(4), -1) - 3) *
                        (var(component.W(4), -1) - 2) * (var(component.W(4), -1) - 1) * var(component.W(4), -1);
                    std::size_t selector_2 = bp.add_gate({constraint_1, constraint_2, constraint_3});
                    auto constraint_4 =
                        var(component.W(2), +1) + m * var(component.W(3), +1) -
                        (var(component.W(4), 0) + var(component.W(5), +1) + var(component.W(6), +1) * (1 << 8) +
                         var(component.W(7), +1) * (1 << 16) + var(component.W(8), +1) * (1 << 24) +
                         var(component.W(5), 0) + var(component.W(6), 0) * (1 << 8) +
                         var(component.W(7), 0) * (1 << 16) + var(component.W(8), 0) * (1 << 24));
                    auto constraint_5 =
                        (var(component.W(3), +1) - 6) * (var(component.W(3), +1) - 5) * (var(component.W(3), +1) - 4) *
                        (var(component.W(3), +1) - 3) * (var(component.W(3), +1) - 2) * (var(component.W(3), +1) - 1) *
                        var(component.W(3), +1);
                    std::size_t selector_3 = bp.add_gate({constraint_4, constraint_5});
                    std::array<std::size_t,2> maj_selectors = generate_Maj_gates(component, bp, assignment, lookup_tables_indices);
                    std::array<std::size_t,2> sigma_0_selectors = generate_Sigma0_gates(component, bp, assignment, lookup_tables_indices);

                    auto constraint_out_1 = var(component.W(0), +1) + m * var(component.W(4), +1) -
                                                              (var(component.W(0), 0) + var(component.W(4), 0));
                    auto constraint_out_2 = var(component.W(1), +1) + m * var(component.W(5), +1) -
                                                              (var(component.W(1), 0) + var(component.W(5), 0));
                    auto constraint_out_3 = var(component.W(2), +1) + m * var(component.W(6), +1) -
                                                              (var(component.W(2), 0) + var(component.W(6), 0));
                    auto constraint_out_4 = var(component.W(3), +1) + m * var(component.W(7), +1) -
                                                              (var(component.W(3), 0) + var(component.W(7), 0));

                    auto constraint_out_5 = var(component.W(4), +1) * (var(component.W(4), +1) - 1);
                    auto constraint_out_6 = var(component.W(5), +1) * (var(component.W(5), +1) - 1);
                    auto constraint_out_7 = var(component.W(6), +1) * (var(component.W(6), +1) - 1);
                    auto constraint_out_8 = var(component.W(7), +1) * (var(component.W(7), +1) - 1);

                    std::size_t selector_6 =
                        bp.add_gate({constraint_out_1, constraint_out_2, constraint_out_3, constraint_out_4,
                        constraint_out_5, constraint_out_6, constraint_out_7, constraint_out_8});
                    return {
                        sigma_1_selectors[0], sigma_1_selectors[1],
                        sigma_0_selectors[0], sigma_0_selectors[1],
                        selector_2, selector_3,
                        maj_selectors[0], maj_selectors[1],
                        ch_selectors[0], ch_selectors[1],
                        selector_6
                    };
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::array<std::size_t, 2>  generate_output_check_gates(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices
                ) {
                    using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;

                    std::array<std::size_t, 2>  selectors;

                    auto constraint_1 = -1 * var(component.W(3), 0) +
                        var(component.W(0), 0) + var(component.W(1), 0) * (1 << 14) + var(component.W(2), 0) * (1 << 28);
                    auto constraint_2 = -1 * var(component.W(7), 0) +
                        var(component.W(4), 0) + var(component.W(5), 0) * (1 << 14) + var(component.W(6), 0) * (1 << 28);

                    selectors[0] = bp.add_gate({constraint_1, constraint_2});

                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_1 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(0), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_2 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(1), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_3 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(2), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_4 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(2), 0) * (1 << 10)}};

                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_5 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(4), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_6 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(5), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_7 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(6), 0)}};
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType> lookup_constraint_8 =
                        {lookup_tables_indices.at("sha256_sparse_base4/first_column"), {var(component.W(6), 0) * (1 << 10)}};

                    selectors[1] = bp.add_lookup_gate({
                        lookup_constraint_1, lookup_constraint_2, lookup_constraint_3, lookup_constraint_4,
                        lookup_constraint_5, lookup_constraint_6, lookup_constraint_7, lookup_constraint_8
                    });

                    return selectors;
                }

            }    // namespace detail

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::array<std::size_t, 19> generate_gates(
                const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices
            ) {
                auto message_scheduling_selectors =
                    detail::generate_message_scheduling_gates(component, bp, assignment, lookup_tables_indices);
                auto compression_selectors = detail::generate_compression_gates(component, bp, assignment, lookup_tables_indices);
                auto final_selectors = detail::generate_output_check_gates(component, bp, assignment, lookup_tables_indices);

                return {
                    message_scheduling_selectors[0], message_scheduling_selectors[1],
                    message_scheduling_selectors[2], message_scheduling_selectors[3],
                    message_scheduling_selectors[4], message_scheduling_selectors[5],
                    compression_selectors[0], compression_selectors[1], compression_selectors[2],
                    compression_selectors[3], compression_selectors[4], compression_selectors[5],
                    compression_selectors[6], compression_selectors[7], compression_selectors[8],
                    compression_selectors[9], compression_selectors[10],
                    final_selectors[0], final_selectors[1]
                };
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::size_t row = start_row_index + 2;
                using var = typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::var;

                for (std::size_t i = 1; i <= 15; ++i) {
                    bp.add_copy_constraint(
                        {var(component.W(0), row + (i - 1) * 5 + 0, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 9; i <= 15; ++i) {
                    bp.add_copy_constraint(
                        {var(component.W(0), row + (i - 9) * 5 + 1, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 0; i <= 15; ++i) {
                    bp.add_copy_constraint(
                        {var(component.W(1), row + (i - 0) * 5 + 1, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 14; i <= 15; ++i) {
                    bp.add_copy_constraint(
                        {var(component.W(0), row + (i - 14) * 5 + 4, false), instance_input.input_words[i]});
                }

                for (std::size_t round = 0; round < 48; round++) {
                    if (round >= 2) {
                        bp.add_copy_constraint({var(component.W(0), row + round * 5 + 4, false),
                                                var(component.W(0), row + (round - 2) * 5 + 2, false)});
                    }
                    if (round >= 7) {
                        bp.add_copy_constraint({var(component.W(0), row + round * 5 + 1, false),
                                                var(component.W(0), row + (round - 7) * 5 + 2, false)});
                    }
                    if (round >= 15) {
                        bp.add_copy_constraint({var(component.W(0), row + round * 5 + 0, false),
                                                var(component.W(0), row + (round - 15) * 5 + 2, false)});
                    }
                    if (round >= 16) {
                        bp.add_copy_constraint({var(component.W(1), row + round * 5 + 1, false),
                                                var(component.W(0), row + (round - 16) * 5 + 2, false)});
                    }

                    bp.add_copy_constraint({var(component.W(0), row + round * 5 + 2, false),
                                                var(component.W(8), row + round * 5 + 4, false)});
                }
                row = row + 240;

                for (std::size_t round = 1; round < 64; round++) {
                    bp.add_copy_constraint({var(component.W(0), row + round * 8 + 0, false),
                                            var(component.W(4), row + (round - 1) * 8 + 3, false)});    // e = e_new
                    bp.add_copy_constraint({var(component.W(0), row + round * 8 + 7, false),
                                            var(component.W(2), row + (round - 1) * 8 + 5, false)});    // a = a_new

                    bp.add_copy_constraint({var(component.W(1), row + round * 8 + 5, false),
                                            var(component.W(0), row + (round - 1) * 8 + 5,
                                                false)});    // sparse_values[1] = sparse_values[0]
                    bp.add_copy_constraint({var(component.W(4), row + round * 8 + 5, false),
                                            var(component.W(1), row + (round - 1) * 8 + 5,
                                                false)});    // sparse_values[2] = sparse_values[1]
                    bp.add_copy_constraint({var(component.W(1), row + round * 8 + 1, false),
                                            var(component.W(0), row + (round - 1) * 8 + 1,
                                                false)});    // sparse_values[5] = sparse_values[4]
                    bp.add_copy_constraint({var(component.W(0), row + round * 8 + 3, false),
                                            var(component.W(1), row + (round - 1) * 8 + 1,
                                                false)});    // sparse_values[6] = sparse_values[5]
                }

                row = row + 512;

                bp.add_copy_constraint({var(component.W(0), row - 1, false), var(component.W(5), row, false)});
                bp.add_copy_constraint({var(component.W(0), row - 9, false), var(component.W(6), row, false)});
                bp.add_copy_constraint({var(component.W(0), row - 17, false), var(component.W(7), row, false)});

                bp.add_copy_constraint({var(component.W(0), row - 8, false), var(component.W(5), row + 2, false)});
                bp.add_copy_constraint({var(component.W(0), row - 16, false), var(component.W(6), row + 2, false)});
                bp.add_copy_constraint({var(component.W(0), row - 24, false), var(component.W(7), row + 2, false)});

                for (std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({var(component.W(i), row, false), instance_input.input_state[i]});
                    bp.add_copy_constraint({var(component.W(i), row + 2, false), instance_input.input_state[i + 4]});
                }

                bp.add_copy_constraint({var(component.W(4), row, false), var(component.W(3), row + 4, false)});
                bp.add_copy_constraint({var(component.W(5), row, false), var(component.W(7), row + 4, false)});
                bp.add_copy_constraint({var(component.W(6), row, false), var(component.W(3), row + 5, false)});
                bp.add_copy_constraint({var(component.W(7), row, false), var(component.W(7), row + 5, false)});

                bp.add_copy_constraint({var(component.W(4), row + 2, false), var(component.W(3), row + 6, false)});
                bp.add_copy_constraint({var(component.W(5), row + 2, false), var(component.W(7), row + 6, false)});
                bp.add_copy_constraint({var(component.W(6), row + 2, false), var(component.W(3), row + 7, false)});
                bp.add_copy_constraint({var(component.W(7), row + 2, false), var(component.W(7), row + 7, false)});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index
                ) {

                detail::generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);
                std::size_t j = start_row_index;
                j = j + 2;
                auto selector_indices = generate_gates(component, bp, assignment, instance_input, bp.get_reserved_indices());

                // Message selectors
                assignment.enable_selector(selector_indices[0], j + 1, j + 239, 5);//sigma0
                assignment.enable_selector(selector_indices[1], j + 1, j + 239, 5);//sigma0
                assignment.enable_selector(selector_indices[2], j + 2, j + 239, 5);//selector1
                assignment.enable_selector(selector_indices[3], j + 2, j + 239, 5);//sigma1 chunk check
                assignment.enable_selector(selector_indices[4], j + 4, j + 239, 5);//sigma1
                assignment.enable_selector(selector_indices[5], j + 4, j + 239, 5);//sigma1

                // Compression selectors
                j = j + 240;
                assignment.enable_selector(selector_indices[6], j + 1, j + 511, 8); // Sigma1
                assignment.enable_selector(selector_indices[7], j + 1, j + 511, 8); // Sigma1
                assignment.enable_selector(selector_indices[8], j + 6, j + 511, 8); // Sigma0
                assignment.enable_selector(selector_indices[9], j + 6, j + 511, 8); // Sigma0
                assignment.enable_selector(selector_indices[10], j + 3, j + 511, 8); // selector2
                assignment.enable_selector(selector_indices[11], j + 4, j + 511, 8); // selector3
                assignment.enable_selector(selector_indices[12], j + 4, j + 511, 8); // Maj_selector
                assignment.enable_selector(selector_indices[13], j + 4, j + 511, 8); // Maj_selector
                assignment.enable_selector(selector_indices[14], j + 2, j + 511, 8); // Ch_selector
                assignment.enable_selector(selector_indices[15], j + 2, j + 511, 8); // Ch_selector

                j = j + 512;
                assignment.enable_selector(selector_indices[16], j, j + 2, 2); // selector6

                j = j + 4;
                assignment.enable_selector(selector_indices[17], j, j + 3, 1);
                assignment.enable_selector(selector_indices[18], j, j + 3, 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                return typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_sha256_process<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>;

                std::size_t row = start_row_index;
                typename BlueprintFieldType::integral_type one = 1;
                std::array<typename BlueprintFieldType::value_type, 8> input_state = {
                    var_value(assignment, instance_input.input_state[0]),
                    var_value(assignment, instance_input.input_state[1]),
                    var_value(assignment, instance_input.input_state[2]),
                    var_value(assignment, instance_input.input_state[3]),
                    var_value(assignment, instance_input.input_state[4]),
                    var_value(assignment, instance_input.input_state[5]),
                    var_value(assignment, instance_input.input_state[6]),
                    var_value(assignment, instance_input.input_state[7])};
                std::array<typename BlueprintFieldType::value_type, 64> message_scheduling_words;
                for (std::size_t i = 0; i < 16; i++) {
                    message_scheduling_words[i] = var_value(assignment, instance_input.input_words[i]);
                }
                typename BlueprintFieldType::value_type a = input_state[0];
                typename BlueprintFieldType::value_type b = input_state[1];
                typename BlueprintFieldType::value_type c = input_state[2];
                typename BlueprintFieldType::value_type d = input_state[3];
                typename BlueprintFieldType::value_type e = input_state[4];
                typename BlueprintFieldType::value_type f = input_state[5];
                typename BlueprintFieldType::value_type g = input_state[6];
                typename BlueprintFieldType::value_type h = input_state[7];

                std::array<typename BlueprintFieldType::integral_type, 8> sparse_values {};
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(component.W(i), row) = input_state[i];
                    typename BlueprintFieldType::integral_type integral_input_state_sparse =
                        typename BlueprintFieldType::integral_type(input_state[i].data);
                    std::vector<bool> input_state_sparse(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> input_state_sparse_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_input_state_sparse,
                                                                                         status);
                        std::copy(input_state_sparse_all.end() - 32, input_state_sparse_all.end(),
                                  input_state_sparse.begin());
                    }

                    std::vector<std::size_t> input_state_sparse_sizes = {32};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> input_state_sparse_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            input_state_sparse, input_state_sparse_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(i), row + 1) = input_state_sparse_chunks[1][0];
                    sparse_values[i] = input_state_sparse_chunks[1][0];
                }
                for (std::size_t i = 4; i < 8; i++) {
                    assignment.witness(component.W(i), row) = input_state[i];
                    typename BlueprintFieldType::integral_type integral_input_state_sparse =
                        typename BlueprintFieldType::integral_type(input_state[i].data);
                    std::vector<bool> input_state_sparse(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> input_state_sparse_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_input_state_sparse,
                                                                                         status);
                        std::copy(input_state_sparse_all.end() - 32, input_state_sparse_all.end(),
                                  input_state_sparse.begin());
                    }

                    std::vector<std::size_t> input_state_sparse_sizes = {32};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> input_state_sparse_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            input_state_sparse, input_state_sparse_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(i), row + 1) = input_state_sparse_chunks[1][0];
                    sparse_values[i] = input_state_sparse_chunks[1][0];
                }
                row = row + 2;
                std::vector<std::size_t> sigma_sizes = {8, 8, 8, 8};
                std::vector<std::size_t> ch_and_maj_sizes = {8, 8, 8, 8};
                typename BlueprintFieldType::value_type base4_value =
                    plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4;
                typename BlueprintFieldType::value_type base7_value =
                    plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7;
                for (std::size_t i = row; i < row + 236; i = i + 5) {
                    typename BlueprintFieldType::integral_type integral_a =
                        typename BlueprintFieldType::integral_type(message_scheduling_words[(i - row) / 5 + 1].data);
                    assignment.witness(component.W(0), i) = message_scheduling_words[(i - row) / 5 + 1];
                    std::vector<bool> a(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> a_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_a, status);
                        std::copy(a_all.end() - 32, a_all.end(), a.begin());
                    }

                    std::vector<std::size_t> a_sizes = {3, 4, 11, 14};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> a_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            a, a_sizes, plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(1), i) = a_chunks[0][0];
                    assignment.witness(component.W(2), i) = a_chunks[0][1];
                    assignment.witness(component.W(3), i) = a_chunks[0][2];
                    assignment.witness(component.W(4), i) = a_chunks[0][3];
                    assignment.witness(component.W(7), i) = a_chunks[1][0];
                    assignment.witness(component.W(0), i + 1) = message_scheduling_words[(i - row) / 5 + 9];
                    assignment.witness(component.W(1), i + 1) = message_scheduling_words[(i - row) / 5];
                    assignment.witness(component.W(2), i + 1) = a_chunks[1][1];
                    assignment.witness(component.W(3), i + 1) = a_chunks[1][2];
                    assignment.witness(component.W(4), i + 1) = a_chunks[1][3];
                    typename BlueprintFieldType::integral_type sparse_sigma0 =
                        a_chunks[1][1] * (1 + (one << 56) + (one << 34)) +
                        a_chunks[1][2] * ((1 << 8) + 1 + (one << 42)) + a_chunks[1][3] * ((1 << 30) + (1 << 22) + 1) +
                        a_chunks[1][0] * ((one << 50) + (1 << 28));
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> sigma0_chunks =
                        detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_sigma0, sigma_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(5), i + 1) = sigma0_chunks[1][0];
                    assignment.witness(component.W(6), i + 1) = sigma0_chunks[1][1];
                    assignment.witness(component.W(7), i + 1) = sigma0_chunks[1][2];
                    assignment.witness(component.W(8), i + 1) = sigma0_chunks[1][3];

                    assignment.witness(component.W(1), i + 2) = sigma0_chunks[0][0];
                    assignment.witness(component.W(2), i + 2) = sigma0_chunks[0][1];
                    assignment.witness(component.W(3), i + 2) = sigma0_chunks[0][2];
                    assignment.witness(component.W(4), i + 2) = sigma0_chunks[0][3];

                    typename BlueprintFieldType::integral_type integral_b =
                        typename BlueprintFieldType::integral_type(message_scheduling_words[(i - row) / 5 + 14].data);
                    std::vector<bool> b(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> b_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);
                        std::copy(b_all.end() - 32, b_all.end(), b.begin());
                    }

                    std::vector<std::size_t> b_sizes = {10, 7, 2, 13};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> b_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            b, b_sizes, plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(0), i + 4) = message_scheduling_words[(i - row) / 5 + 14];
                    assignment.witness(component.W(1), i + 4) = b_chunks[0][0];
                    assignment.witness(component.W(2), i + 4) = b_chunks[0][1];
                    assignment.witness(component.W(3), i + 4) = b_chunks[0][2];
                    assignment.witness(component.W(4), i + 4) = b_chunks[0][3];

                    assignment.witness(component.W(1), i + 3) = b_chunks[1][0];
                    assignment.witness(component.W(2), i + 3) = b_chunks[1][1];
                    assignment.witness(component.W(3), i + 3) = b_chunks[1][2];
                    assignment.witness(component.W(4), i + 3) = b_chunks[1][3];

                    typename BlueprintFieldType::integral_type sparse_sigma1 =
                        b_chunks[1][1] * (1 + (one << 50) + (one << 46)) +
                        b_chunks[1][2] * ((1 << 14) + 1 + (one << 60)) + b_chunks[1][3] * ((1 << 18) + (1 << 4) + 1) +
                        b_chunks[1][0] * ((1 << 30) + (1 << 26));

                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> sigma1_chunks =
                        detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_sigma1, sigma_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(5), i + 3) = sigma1_chunks[1][0];
                    assignment.witness(component.W(6), i + 3) = sigma1_chunks[1][1];
                    assignment.witness(component.W(7), i + 3) = sigma1_chunks[1][2];
                    assignment.witness(component.W(8), i + 3) = sigma1_chunks[1][3];

                    assignment.witness(component.W(5), i + 2) = sigma1_chunks[0][0];
                    assignment.witness(component.W(6), i + 2) = sigma1_chunks[0][1];
                    assignment.witness(component.W(7), i + 2) = sigma1_chunks[0][2];
                    assignment.witness(component.W(8), i + 2) = sigma1_chunks[0][3];
                    typename BlueprintFieldType::value_type sum =
                        message_scheduling_words[(i - row) / 5 + 9] + message_scheduling_words[(i - row) / 5] +
                        sigma1_chunks[0][0] + sigma0_chunks[0][0] +
                        (one << 8) * (sigma1_chunks[0][1] + sigma0_chunks[0][1]) +
                        (one << 16) * (sigma1_chunks[0][2] + sigma0_chunks[0][2]) +
                        (one << 24) * (sigma1_chunks[0][3] + sigma0_chunks[0][3]);
                    message_scheduling_words[(i - row) / 5 + 16] =
                        typename BlueprintFieldType::integral_type(sum.data) %
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                    assignment.witness(component.W(0), i + 2) = message_scheduling_words[(i - row) / 5 + 16];

                    typename BlueprintFieldType::integral_type integral_a2 =
                        typename BlueprintFieldType::integral_type(message_scheduling_words[(i - row) / 5 + 16].data);
                    assignment.witness(component.W(5), i + 4) = ( ((1 << 14) - 1) & (integral_a2) );
                    assignment.witness(component.W(6), i + 4) = ( ((1 << 14) - 1) & (integral_a2 >> 14) );
                    assignment.witness(component.W(7), i + 4) = ( ((1 << 14) - 1) & (integral_a2 >> 28) );
                    assignment.witness(component.W(8), i + 4) = integral_a2;

                    assignment.witness(component.W(0), i + 3) =
                        (sum - message_scheduling_words[(i - row) / 5 + 16]) /
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                }
                row = row + 240;
                for (std::size_t i = row; i < row + 512; i = i + 8) {
                    assignment.witness(component.W(0), i) = e;
                    typename BlueprintFieldType::integral_type integral_e =
                        typename BlueprintFieldType::integral_type(e.data);
                    std::vector<bool> e_bits(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> e_bits_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_e, status);
                        std::copy(e_bits_all.end() - 32, e_bits_all.end(), e_bits.begin());
                    }

                    std::vector<std::size_t> e_sizes = {6, 5, 14, 7};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> e_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            e_bits, e_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(2), i) = e_chunks[0][0];
                    assignment.witness(component.W(3), i) = e_chunks[0][1];
                    assignment.witness(component.W(4), i) = e_chunks[0][2];
                    assignment.witness(component.W(5), i) = e_chunks[0][3];

                    assignment.witness(component.W(1), i) = e_chunks[1][0];
                    assignment.witness(component.W(2), i + 1) = e_chunks[1][1];
                    assignment.witness(component.W(3), i + 1) = e_chunks[1][2];
                    assignment.witness(component.W(4), i + 1) = e_chunks[1][3];

                    sparse_values[4] = typename BlueprintFieldType::integral_type(
                        (e_chunks[1][0] + e_chunks[1][1] * base7_value.pow(e_sizes[0]) +
                         e_chunks[1][2] * base7_value.pow(e_sizes[0] + e_sizes[1]) +
                         e_chunks[1][3] * base7_value.pow(e_sizes[0] + e_sizes[1] + e_sizes[2]))
                            .data);
                    assignment.witness(component.W(0), i + 1) = sparse_values[4];
                    assignment.witness(component.W(1), i + 1) = sparse_values[5];
                    typename BlueprintFieldType::integral_type sparse_Sigma1 =
                        typename BlueprintFieldType::integral_type(
                            (e_chunks[1][1] * (base7_value.pow(27) + base7_value.pow(13) + 1) +
                             e_chunks[1][2] * (base7_value.pow(5) + base7_value.pow(18) + 1) +
                             e_chunks[1][3] * (base7_value.pow(19) + base7_value.pow(14) + 1) +
                             e_chunks[1][0] * (base7_value.pow(26) + base7_value.pow(21) + base7_value.pow(7)))
                                .data);
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> Sigma1_chunks =
                        detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_Sigma1, sigma_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(5), i + 2) = Sigma1_chunks[0][0];
                    assignment.witness(component.W(6), i + 2) = Sigma1_chunks[0][1];
                    assignment.witness(component.W(7), i + 2) = Sigma1_chunks[0][2];
                    assignment.witness(component.W(8), i + 2) = Sigma1_chunks[0][3];
                    assignment.witness(component.W(5), i + 1) = Sigma1_chunks[1][0];
                    assignment.witness(component.W(6), i + 0) = Sigma1_chunks[1][1];
                    assignment.witness(component.W(7), i + 0) = Sigma1_chunks[1][2];
                    assignment.witness(component.W(8), i + 0) = Sigma1_chunks[1][3];
                    typename BlueprintFieldType::integral_type Sigma1 =
                        Sigma1_chunks[0][0] + Sigma1_chunks[0][1] * (1 << (sigma_sizes[0])) +
                        Sigma1_chunks[0][2] * (1 << (sigma_sizes[0] + sigma_sizes[1])) +
                        Sigma1_chunks[0][3] * (1 << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]));
                    typename BlueprintFieldType::integral_type sparse_ch =
                        sparse_values[4] + 2 * sparse_values[5] + 3 * sparse_values[6];

                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> ch_chunks =
                        detail::reversed_sparse_and_split_ch<BlueprintFieldType>(
                            sparse_ch, ch_and_maj_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(5), i + 3) = ch_chunks[0][0];
                    assignment.witness(component.W(6), i + 3) = ch_chunks[0][1];
                    assignment.witness(component.W(7), i + 3) = ch_chunks[0][2];
                    assignment.witness(component.W(8), i + 3) = ch_chunks[0][3];
                    assignment.witness(component.W(0), i + 2) = ch_chunks[1][0];
                    assignment.witness(component.W(1), i + 2) = ch_chunks[1][1];
                    assignment.witness(component.W(2), i + 2) = ch_chunks[1][2];
                    assignment.witness(component.W(3), i + 2) = ch_chunks[1][3];

                    assignment.witness(component.W(0), i + 3) = sparse_values[6];
                    assignment.witness(component.W(1), i + 3) = d;
                    assignment.witness(component.W(2), i + 3) = h;
                    assignment.witness(component.W(3), i + 3) = message_scheduling_words[(i - row) / 8];
                    typename BlueprintFieldType::integral_type ch = ch_chunks[0][0] + ch_chunks[0][1] * (1 << 8) +
                                                                    ch_chunks[0][2] * (1 << 16) +
                                                                    ch_chunks[0][3] * (1 << 24);

                    typename BlueprintFieldType::value_type tmp1 = h + Sigma1 + ch +
                                                                   component_type::round_constant[(i - row) / 8] +
                                                                   message_scheduling_words[(i - row) / 8];
                    typename BlueprintFieldType::value_type sum = tmp1 + d;
                    typename BlueprintFieldType::value_type e_new =
                        typename BlueprintFieldType::integral_type(sum.data) %
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                    assignment.witness(component.W(4), i + 4) = tmp1;
                    assignment.witness(component.W(4), i + 3) = e_new;
                    assignment.witness(component.W(4), i + 2) =
                        (sum - e_new) / typename BlueprintFieldType::integral_type(
                                            typename BlueprintFieldType::value_type(2).pow(32).data);

                    typename BlueprintFieldType::integral_type integral_a2 =
                        typename BlueprintFieldType::integral_type(e_new.data);
                    assignment.witness(component.W(6), i + 1) = ( ((1 << 14) - 1) & (integral_a2) );
                    assignment.witness(component.W(7), i + 1) = ( ((1 << 14) - 1) & (integral_a2 >> 14) );
                    assignment.witness(component.W(8), i + 1) = ( ((1 << 14) - 1) & (integral_a2 >> 28) );

                    assignment.witness(component.W(0), i + 7) = a;
                    typename BlueprintFieldType::integral_type integral_a =
                        typename BlueprintFieldType::integral_type(a.data);
                    std::vector<bool> a_bits(32);
                    {
                        nil::marshalling::status_type status;
                        std::vector<bool> a_bits_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_a, status);
                        std::copy(a_bits_all.end() - 32, a_bits_all.end(), a_bits.begin());
                    }

                    std::vector<std::size_t> a_sizes = {2, 11, 9, 10};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> a_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(
                            a_bits, a_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(2), i + 7) = a_chunks[0][0];
                    assignment.witness(component.W(3), i + 7) = a_chunks[0][1];
                    assignment.witness(component.W(4), i + 7) = a_chunks[0][2];
                    assignment.witness(component.W(5), i + 7) = a_chunks[0][3];

                    assignment.witness(component.W(2), i + 6) = a_chunks[1][0];
                    assignment.witness(component.W(3), i + 6) = a_chunks[1][1];
                    assignment.witness(component.W(4), i + 6) = a_chunks[1][2];
                    assignment.witness(component.W(5), i + 6) = a_chunks[1][3];

                    sparse_values[0] = typename BlueprintFieldType::integral_type(
                        (a_chunks[1][0] + a_chunks[1][1] * base4_value.pow(a_sizes[0]) +
                         a_chunks[1][2] * base4_value.pow(a_sizes[0] + a_sizes[1]) +
                         a_chunks[1][3] * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2]))
                            .data);
                    assignment.witness(component.W(0), i + 5) = sparse_values[0];
                    assignment.witness(component.W(1), i + 5) = sparse_values[1];
                    typename BlueprintFieldType::integral_type sparse_Sigma0 =
                        (a_chunks[1][0] * ((one << 38) + (1 << 20) + (one << 60)) +
                         a_chunks[1][1] * ((one << 42) + 1 + (1 << 24)) +
                         a_chunks[1][2] * ((1 << 22) + (one << 46) + 1) +
                         a_chunks[1][3] * ((one << 40) + (1 << 18) + 1));
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> Sigma0_chunks =
                        detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_Sigma0, sigma_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(5), i + 5) = Sigma0_chunks[0][0];
                    assignment.witness(component.W(6), i + 5) = Sigma0_chunks[0][1];
                    assignment.witness(component.W(7), i + 5) = Sigma0_chunks[0][2];
                    assignment.witness(component.W(8), i + 5) = Sigma0_chunks[0][3];
                    assignment.witness(component.W(0), i + 6) = Sigma0_chunks[1][0];
                    assignment.witness(component.W(1), i + 6) = Sigma0_chunks[1][1];
                    assignment.witness(component.W(6), i + 6) = Sigma0_chunks[1][2];
                    assignment.witness(component.W(7), i + 6) = Sigma0_chunks[1][3];

                    typename BlueprintFieldType::integral_type Sigma0 =
                        Sigma0_chunks[0][0] + Sigma0_chunks[0][1] * (1 << sigma_sizes[0]) +
                        Sigma0_chunks[0][2] * (1 << (sigma_sizes[0] + sigma_sizes[1])) +
                        Sigma0_chunks[0][3] * (1 << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]));

                    typename BlueprintFieldType::integral_type sparse_maj =
                        (sparse_values[0] + sparse_values[1] + sparse_values[2]);
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> maj_chunks =
                        detail::reversed_sparse_and_split_maj<BlueprintFieldType>(
                            sparse_maj, ch_and_maj_sizes,
                            plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(5), i + 4) = maj_chunks[0][0];
                    assignment.witness(component.W(6), i + 4) = maj_chunks[0][1];
                    assignment.witness(component.W(7), i + 4) = maj_chunks[0][2];
                    assignment.witness(component.W(8), i + 4) = maj_chunks[0][3];
                    assignment.witness(component.W(0), i + 4) = maj_chunks[1][0];
                    assignment.witness(component.W(1), i + 4) = maj_chunks[1][1];
                    assignment.witness(component.W(2), i + 4) = maj_chunks[1][2];
                    assignment.witness(component.W(3), i + 4) = maj_chunks[1][3];
                    typename BlueprintFieldType::integral_type maj = maj_chunks[0][0] + maj_chunks[0][1] * (1 << 8) +
                                                                     maj_chunks[0][2] * (1 << 16) +
                                                                     maj_chunks[0][3] * (1 << 24);
                    assignment.witness(component.W(4), i + 5) = sparse_values[2];
                    typename BlueprintFieldType::value_type sum1 = tmp1 + Sigma0 + maj;
                    typename BlueprintFieldType::value_type a_new =
                        typename BlueprintFieldType::integral_type(sum1.data) %
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                    assignment.witness(component.W(2), i + 5) = a_new;
                    assignment.witness(component.W(3), i + 5) =
                        (sum1 - a_new) / typename BlueprintFieldType::value_type(2).pow(32);

                    integral_a2 =
                        typename BlueprintFieldType::integral_type(a_new.data);
                    assignment.witness(component.W(6), i + 7) = ( ((1 << 14) - 1) & (integral_a2) );
                    assignment.witness(component.W(7), i + 7) = ( ((1 << 14) - 1) & (integral_a2 >> 14) );
                    assignment.witness(component.W(8), i + 7) = ( ((1 << 14) - 1) & (integral_a2 >> 28) );

                    h = g;
                    sparse_values[7] = sparse_values[6];
                    g = f;
                    sparse_values[6] = sparse_values[5];
                    f = e;
                    sparse_values[5] = sparse_values[4];
                    e = e_new;
                    d = c;
                    sparse_values[3] = sparse_values[2];
                    c = b;
                    sparse_values[2] = sparse_values[1];
                    b = a;
                    sparse_values[1] = sparse_values[0];
                    a = a_new;
                }
                std::array<typename BlueprintFieldType::value_type, 8> output_state = {a, b, c, d, e, f, g, h};
                row = row + 512;
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(component.W(i), row) = input_state[i];
                    auto sum = typename BlueprintFieldType::integral_type(input_state[i].data) +
                               typename BlueprintFieldType::integral_type(output_state[i].data);
                    assignment.witness(component.W(i), row + 1) =
                        sum % typename BlueprintFieldType::integral_type(
                                  typename BlueprintFieldType::value_type(2).pow(32).data);
                    assignment.witness(component.W(i + 4), row) = output_state[i];
                    assignment.witness(component.W(i + 4), row + 1) =
                        (sum - sum % typename BlueprintFieldType::integral_type(
                                         typename BlueprintFieldType::value_type(2).pow(32).data)) /
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                }
                row = row + 2;
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(component.W(i), row) = input_state[i + 4];
                    auto sum = typename BlueprintFieldType::integral_type(input_state[i + 4].data) +
                               typename BlueprintFieldType::integral_type(output_state[i + 4].data);
                    assignment.witness(component.W(i), row + 1) =
                        sum % typename BlueprintFieldType::integral_type(
                                  typename BlueprintFieldType::value_type(2).pow(32).data);
                    assignment.witness(component.W(i + 4), row) = output_state[i + 4];
                    assignment.witness(component.W(i + 4), row + 1) =
                        (sum - sum % typename BlueprintFieldType::integral_type(
                                         typename BlueprintFieldType::value_type(2).pow(32).data)) /
                        typename BlueprintFieldType::integral_type(
                            typename BlueprintFieldType::value_type(2).pow(32).data);
                }

                row = row + 2;
                typename BlueprintFieldType::integral_type integral_a2;
                for (std::size_t i = 0; i < 4; i++) {
                    integral_a2 = typename BlueprintFieldType::integral_type(output_state[2 * i].data);
                    assignment.witness(component.W(0), row + i) = ( ((1 << 14) - 1) & (integral_a2) );
                    assignment.witness(component.W(1), row + i) = ( ((1 << 14) - 1) & (integral_a2 >> 14) );
                    assignment.witness(component.W(2), row + i) = ( ((1 << 14) - 1) & (integral_a2 >> 28) );
                    assignment.witness(component.W(3), row + i) = integral_a2;

                    integral_a2 = typename BlueprintFieldType::integral_type(output_state[2 * i + 1].data);
                    assignment.witness(component.W(4), row + i) = ( ((1 << 14) - 1) & (integral_a2) );
                    assignment.witness(component.W(5), row + i) = ( ((1 << 14) - 1) & (integral_a2 >> 14) );
                    assignment.witness(component.W(6), row + i) = ( ((1 << 14) - 1) & (integral_a2 >> 28) );
                    assignment.witness(component.W(7), row + i) = integral_a2;
                }
                /*std::vector<std::size_t> value_sizes = {14};
                // lookup table for sparse values with base = 4
                for (typename CurveType::scalar_field_type::integral_type i = 0;
                     i < typename CurveType::scalar_field_type::integral_type(16384);
                     i++) {
                    std::vector<bool> value(14);
                    for (std::size_t j = 0; j < 14; j++) {
                        value[14 - j - 1] = multiprecision::bit_test(i, j);
                    }
                    std::array<std::vector<uint64_t>, 2> value_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(value, value_sizes,
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.constant(0)[start_row_index + std::size_t(i)] = value_chunks[0][0];
                    assignment.constant(1)[start_row_index + std::size_t(i)] = value_chunks[1][0];
                }
                // lookup table for sparse values with base = 7
                for (typename CurveType::scalar_field_type::integral_type i = 0;
                     i < typename CurveType::scalar_field_type::integral_type(16384);
                     i++) {
                    std::vector<bool> value(14);
                    for (std::size_t j = 0; j < 14; j++) {
                        value[14 - j - 1] = multiprecision::bit_test(i, j);
                    }
                    std::array<std::vector<uint64_t>, 2> value_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(value, value_sizes,
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.constant(2)[start_row_index + std::size_t(i)] = value_chunks[0][0];
                    assignment.constant(3)[start_row_index + std::size_t(i)] = value_chunks[1][0];
                }
                // lookup table for maj function
                value_sizes = {8};
                for (typename CurveType::scalar_field_type::integral_type i = 0;
                     i < typename CurveType::scalar_field_type::integral_type(65535);
                     i++) {
                    static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                        value = detail::reversed_sparse_and_split<BlueprintFieldType>(i, value_sizes,
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.constant(4)[start_row_index + std::size_t(i)] = value[0][0];
                    assignment.constant(5)[start_row_index + std::size_t(i)] = i;
                }

                // lookup table for ch function
                for (typename CurveType::scalar_field_type::integral_type i = 0;
                     i < typename CurveType::scalar_field_type::integral_type(5765041);
                     i++) {
                    static std::array<std::vector<typename CurveType::scalar_field_type::integral_type>, 2>
                        value = detail::reversed_sparse_and_split<BlueprintFieldType>(i, value_sizes,
                        plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.constant(4)[start_row_index + std::size_t(i)] = value[0][0];
                    assignment.constant(5)[start_row_index + std::size_t(i)] = i;
                }*/

                return typename plonk_sha256_process<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_PROCESS_HPP