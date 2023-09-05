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
// @file Declaration of interfaces for auxiliary components for the SHA512_PROCESS component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_PROCESS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_PROCESS_HPP

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
            // Output: [y_0, y_1, y_2] - SHA512 permutation of [x_0, x_1, x_2]
            template<typename ArithmetizationType>
            class sha512_process;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class sha512_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                             ArithmetizationParams>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

            public:

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return sha512_process::gates_amount;
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
                    return 6*64 + 2 + 9*80 + 4;
                }

                constexpr static const std::size_t rounds_amount = 80;

                constexpr static const std::size_t base4 = 4;
                constexpr static const std::size_t base7 = 7;

                constexpr static const std::array<typename BlueprintFieldType::value_type, rounds_amount>
                    round_constant = {
                        0x428a2f98d728ae22_cppui64, 0x7137449123ef65cd_cppui64, 0xb5c0fbcfec4d3b2f_cppui64, 0xe9b5dba58189dbbc_cppui64,
                        0x3956c25bf348b538_cppui64, 0x59f111f1b605d019_cppui64, 0x923f82a4af194f9b_cppui64, 0xab1c5ed5da6d8118_cppui64,
                        0xd807aa98a3030242_cppui64, 0x12835b0145706fbe_cppui64, 0x243185be4ee4b28c_cppui64, 0x550c7dc3d5ffb4e2_cppui64,
                        0x72be5d74f27b896f_cppui64, 0x80deb1fe3b1696b1_cppui64, 0x9bdc06a725c71235_cppui64, 0xc19bf174cf692694_cppui64,
                        0xe49b69c19ef14ad2_cppui64, 0xefbe4786384f25e3_cppui64, 0x0fc19dc68b8cd5b5_cppui64, 0x240ca1cc77ac9c65_cppui64,
                        0x2de92c6f592b0275_cppui64, 0x4a7484aa6ea6e483_cppui64, 0x5cb0a9dcbd41fbd4_cppui64, 0x76f988da831153b5_cppui64,
                        0x983e5152ee66dfab_cppui64, 0xa831c66d2db43210_cppui64, 0xb00327c898fb213f_cppui64, 0xbf597fc7beef0ee4_cppui64,
                        0xc6e00bf33da88fc2_cppui64, 0xd5a79147930aa725_cppui64, 0x06ca6351e003826f_cppui64, 0x142929670a0e6e70_cppui64,
                        0x27b70a8546d22ffc_cppui64, 0x2e1b21385c26c926_cppui64, 0x4d2c6dfc5ac42aed_cppui64, 0x53380d139d95b3df_cppui64,
                        0x650a73548baf63de_cppui64, 0x766a0abb3c77b2a8_cppui64, 0x81c2c92e47edaee6_cppui64, 0x92722c851482353b_cppui64,
                        0xa2bfe8a14cf10364_cppui64, 0xa81a664bbc423001_cppui64, 0xc24b8b70d0f89791_cppui64, 0xc76c51a30654be30_cppui64,
                        0xd192e819d6ef5218_cppui64, 0xd69906245565a910_cppui64, 0xf40e35855771202a_cppui64, 0x106aa07032bbd1b8_cppui64,
                        0x19a4c116b8d2d0c8_cppui64, 0x1e376c085141ab53_cppui64, 0x2748774cdf8eeb99_cppui64, 0x34b0bcb5e19b48a8_cppui64,
                        0x391c0cb3c5c95a63_cppui64, 0x4ed8aa4ae3418acb_cppui64, 0x5b9cca4f7763e373_cppui64, 0x682e6ff3d6b2b8a3_cppui64,
                        0x748f82ee5defb2fc_cppui64, 0x78a5636f43172f60_cppui64, 0x84c87814a1f0ab72_cppui64, 0x8cc702081a6439ec_cppui64,
                        0x90befffa23631e28_cppui64, 0xa4506cebde82bde9_cppui64, 0xbef9a3f7b2c67915_cppui64, 0xc67178f2e372532b_cppui64,
                        0xca273eceea26619c_cppui64, 0xd186b8c721c0c207_cppui64, 0xeada7dd6cde0eb1e_cppui64, 0xf57d4f7fee6ed178_cppui64,
                        0x06f067aa72176fba_cppui64, 0x0a637dc5a2c898a6_cppui64, 0x113f9804bef90dae_cppui64, 0x1b710b35131c471b_cppui64,
                        0x28db77f523047d84_cppui64, 0x32caab7b40c72493_cppui64, 0x3c9ebe0a15c9bebc_cppui64, 0x431d67c49c100d4c_cppui64,
                        0x4cc5d4becb3e42b6_cppui64, 0x597f299cfc657e2a_cppui64, 0x5fcb6fab3ad6faec_cppui64, 0x6c44198c4a475817_cppui64};

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                constexpr static const std::size_t gates_amount = 10;

                struct input_type {
                    std::array<var, 8> input_state;
                    std::array<var, 16> input_words;
                };

                struct result_type {
                    std::array<var, 8> output_state;

                    result_type(const sha512_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &component, std::uint32_t start_row_index) {
                        output_state = {var(component.W(0), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(0), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 1, false)};
                    }
                };

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                sha512_process(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input):
                    component_type(witness, constant, public_input, get_manifest()){};

                sha512_process(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs):
                    component_type(witnesses, constants, public_inputs, get_manifest()){};

            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            using plonk_sha512_process =
                sha512_process<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            namespace detail {

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_assignments_constant(
                        const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::size_t start_row_index) {

                        std::size_t row = start_row_index + 386 + 3;
                        for (std::size_t i = 0; i < 80; i ++){
                            assignment.constant(component.C(0), row + i*9) =
                                plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::round_constant[i];
                        }
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_sigma0_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(2), -1) * (one << 1) + var(component.W(3), -1) * (one << 7) +
                                      var(component.W(4), -1) * (one << 8) + var(component.W(5), -1) * (one << 22) + var(component.W(6), -1) * (one << 36) +
                                      var(component.W(7), - 1) * (one << 50)));
                    auto constraint_2 = bp.add_constraint((var(component.W(1), -1) - 1) * (var(component.W(1), - 1)));
                    auto constraint_3 = bp.add_constraint((var(component.W(3), -1) - 1) * (var(component.W(3), - 1)));
                    auto constraint_4 = bp.add_constraint(
                        var(component.W(6), 0) + var(component.W(7), 0) * (one << (2*14)) + var(component.W(8), 0) * (one << (2*28)) +
                        var(component.W(0), +1) * (one << (2*42)) + var(component.W(1), +1) * (one << (2*56)) -
                        (var(component.W(8), -1) * ((one << (63*2)) + (one << (56*2))) +
                        var(component.W(0), 0) * (1 + (one << (57*2))) +
                        var(component.W(1), 0) * ((one << (6*2)) + (one << (63*2)) + 1) +
                        var(component.W(2), 0) * ((one << (7*2)) + 1 + (one << (1*2))) +
                        var(component.W(3), 0) * ((one << (21*2)) + (one << (14*2)) + (one << (15*2))) +
                        var(component.W(4), 0) * ((one << (35*2)) + (one << (28*2)) + (one << (29*2))) +
                        var(component.W(5), 0) * ((one << (49*2)) + (one << (42*2)) + (one << (43*2)))));

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_sigma1_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    std::size_t selector_index = first_selector_index;
                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(0), +1) - (var(component.W(1), 1) + var(component.W(2), 1) * (one << 6) + var(component.W(3), 1) * (one << 19) +
                                      var(component.W(4), 1) * (one << 33) + var(component.W(5), 1) * (one << 47) + var(component.W(6), 1) * (one << 61)));
                    auto constraint_2 = bp.add_constraint((var(component.W(6), 1) - 7) * (var(component.W(6), 1) - 6) * (var(component.W(6), 1) - 5) *
                                                          (var(component.W(6), 1) - 4) * (var(component.W(6), 1) - 3) * (var(component.W(6), 1) - 2) *
                                                          (var(component.W(6), 1) - 1) * var(component.W(6), 1));
                    auto constraint_3 = bp.add_constraint(
                        var(component.W(4), 0) + var(component.W(5), 0) * (one << 28) + var(component.W(6), 0) * (one << 56) + var(component.W(7), 0) * (one << (42*2)) +
                        var(component.W(8), 0) * (one << 112) -
                        (var(component.W(7), 1) * ((one << (2*45)) + (one << (2*3))) +
                        var(component.W(8), 1) * ((one << (2*51)) + (one << (2*9)) + 1) +
                        var(component.W(0), 0) * (1 + (one << (2*22)) + (one << (2*13))) +
                        var(component.W(1), 0) * ((one << (2*14)) + (one << (2*36)) + (one << (2 * 27))) +
                        var(component.W(2), 0) * ((one << (2*28)) + (one << (2*50)) + (one << (2*41))) +
                        var(component.W(3), 0) * ((one << (2*42)) + 1 + (one << (2 * 55)))));
                    ;

                    bp.add_gate(selector_index, {constraint_1, constraint_2, constraint_3});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_message_scheduling_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    generate_sigma0_gates(component, bp, assignment, first_selector_index);
                    typename BlueprintFieldType::integral_type one = 1;
                    auto m = typename BlueprintFieldType::value_type(2).pow(64);
                    auto constraint_1 = bp.add_constraint(
                        (var(component.W(5), 0) + m*var(component.W(6), 0) - (var(component.W(7), -1) + var(component.W(8), -1) + var(component.W(2), -1) + var(component.W(3), -1) * (one << 14) +
                                       var(component.W(4), -1) * (one << 28) + var(component.W(5), -1) * (one << 42) + var(component.W(6), -1) * (one << 56) +
                                       var(component.W(0), 0) + var(component.W(1), 0) * (one << 14) + var(component.W(2), 0) * (one << 28) +
                                       var(component.W(3), 0) * (one << 42) + var(component.W(4), 0) * (one << 56))));
                    auto constraint_2 = bp.add_constraint((var(component.W(6), 0) - 3) * (var(component.W(6), 0) - 2) * (var(component.W(6), 0)  - 1) * var(component.W(6), 0));
                    bp.add_gate(first_selector_index + 2, {constraint_1, constraint_2});
                    generate_sigma1_gates(component, bp, assignment, first_selector_index + 1);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_Sigma0_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    typename BlueprintFieldType::integral_type one = 1;
                    std::vector<std::size_t> a_sizes = {14, 14, 6, 5, 14, 11};
                    typename BlueprintFieldType::value_type base4_value =
                        plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4;
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(0), +1) - (var(component.W(1), +1) + var(component.W(2), 1) * (one << 14) + var(component.W(3), +1) * (one << 28) +
                                       var(component.W(4), +1) * (one << 34) + var(component.W(5), 1) * (one << 39) + var(component.W(6), 1) * (one << 53)));
                    auto constraint_2 = bp.add_constraint(
                        var(component.W(5), -1) - (var(component.W(7), +1)+ var(component.W(8), +1) * base4_value.pow(a_sizes[0]) +
                        var(component.W(0), 0) * base4_value.pow(a_sizes[0] + a_sizes[1]) +
                        var(component.W(1), 0) * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2]) +
                        var(component.W(2), 0) * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2] + a_sizes[3]) +
                        var(component.W(3), 0) * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2] + a_sizes[3] + a_sizes[4])));
                    auto constraint_3 = bp.add_constraint(
                        var(component.W(4), 0) + var(component.W(5), 0) * (one << (2*14)) + var(component.W(6), 0) * (one << (2*28)) +
                        var(component.W(7), 0) * (one << (2*42)) + var(component.W(8), 0) * (one << 112) -
                        (var(component.W(7), +1) * ((one << (36 *2)) + (one << (30*2)) + (one << (25*2))) +
                        var(component.W(8), +1) * ((one << (50 * 2)) + (one << (44*2)) + (one << (39*2))) +
                        var(component.W(0), 0) * (1 + (one << (58*2)) + (one << (53*2))) +
                        var(component.W(1), 0) * ((one << (6*2)) + 1 + (one << (59*2))) +
                        var(component.W(2), 0) * ((one << (11*2)) + (one << (5*2)) + 1) +
                        var(component.W(3), 0) * ((one << (25*2)) + (one << (19*2)) + (one << (14*2)))));

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_Sigma1_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    typename BlueprintFieldType::integral_type one = 1;
                    typename BlueprintFieldType::value_type base7_value =
                        plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7;
                    auto constraint_1 =
                        bp.add_constraint(var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(2), -1) * (one << 14) +
                                                         var(component.W(3), -1) * (one << 18) + var(component.W(4), -1) * (one << 32) +
                                                         var(component.W(5), -1) * (one << 41) + var(component.W(6), -1) * (one << 55)));
                    auto constraint_2 =
                        bp.add_constraint(var(component.W(5), +1) - (var(component.W(7), -1) + var(component.W(8), -1) * (base7_value.pow(14)) +
                                                         var(component.W(0), 0) * (base7_value.pow(18)) + var(component.W(1), 0) * (base7_value.pow(32)) +
                                                         var(component.W(2), 0) * (base7_value.pow(41)) + var(component.W(3), 0) * (base7_value.pow(55))));

                    auto constraint_3 = bp.add_constraint(
                        var(component.W(4), 0) + var(component.W(5), 0) * base7_value.pow(14) + var(component.W(6), 0) * base7_value.pow(28) +
                        var(component.W(7), 0) * base7_value.pow(42) +
                        var(component.W(8), 0) * base7_value.pow(56) -
                        (var(component.W(7),  -1) * (base7_value.pow(50) + base7_value.pow(46) + base7_value.pow(23)) +
                            var(component.W(8), -1) * (1 + base7_value.pow(60) + base7_value.pow(37)) +
                            var(component.W(0), 0) * (base7_value.pow(4) + 1 + base7_value.pow(41)) +
                            var(component.W(1), 0) * (base7_value.pow(18) + base7_value.pow(14) + base7_value.pow(55))+
                            var(component.W(2), 0) * (base7_value.pow(27) + base7_value.pow(23) + 1)+
                            var(component.W(3), 0)* (base7_value.pow(41) + base7_value.pow(37) + base7_value.pow(14))));

                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_Maj_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    typename BlueprintFieldType::integral_type one = 1;
                    auto constraint_1 =
                        bp.add_constraint(var(component.W(7), 0) + var(component.W(8), 0) * (one << 32) + var(component.W(0), -1) * (one << 64) +
                                          var(component.W(1), -1) * (one << 96) - (var(component.W(5), 0) + var(component.W(6), 0) + var(component.W(6), -1)));

                    bp.add_gate(first_selector_index, {constraint_1});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_Ch_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    typename BlueprintFieldType::value_type base7_value =
                        plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7;
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(7), 0) + var(component.W(8), 0) * base7_value.pow(16) + var(component.W(0), +1) * base7_value.pow(32) +
                        var(component.W(1), +1) * base7_value.pow(48) - (var(component.W(5), 0) + 2 * var(component.W(6), 0) + 3 * var(component.W(6), +1)));

                    bp.add_gate(first_selector_index, {constraint_1});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_compression_gates(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const std::uint32_t first_selector_index) {

                    using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                    std::vector<std::size_t> sigma_sizes = {14, 14, 14, 14, 8};
                    typename BlueprintFieldType::integral_type one = 1;
                    auto m = typename BlueprintFieldType::value_type(2).pow(64);
                    generate_Sigma1_gates(component, bp, assignment, first_selector_index);
                    generate_Ch_gates(component, bp, assignment, first_selector_index + 2);
                    auto constraint_1 = bp.add_constraint(
                    var(component.W(1), +1) -
                    (var(component.W(8), 0) + var(component.W(0), +1) +
                    var(component.W(0), -1) + var(component.W(1), -1) * (1 << (sigma_sizes[0])) +
                    var(component.W(2), -1) * (one << (sigma_sizes[0] + sigma_sizes[1])) +
                    var(component.W(3), -1) * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]))  +
                    var(component.W(4), -1) * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2] + sigma_sizes[3])) +
                    var(component.W(2), 0) + var(component.W(3), 0) * (1 << 16) +
                    var(component.W(4), 0) * (one << 32) + var(component.W(5), 0) * (one << 48) +
                    var(component.W(0), 0, true, var::column_type::constant)));
                    auto constraint_2 = bp.add_constraint(
                        var(component.W(1), +1) + var(component.W(7), 0) - (var(component.W(2), +1) + m*var(component.W(3), +1)));
                    auto constraint_3 = bp.add_constraint(
                        (var(component.W(3), +1) - 5)* (var(component.W(3), +1) - 4)*(var(component.W(3), +1) - 3)*
                    (var(component.W(3), +1) - 2) * (var(component.W(3), +1) - 1) * var(component.W(3), +1)
                    );
                    bp.add_gate(first_selector_index + 4, {constraint_1, constraint_2, constraint_3});

                    auto constraint_4 = bp.add_constraint(
                        var(component.W(7), 0) + m*var(component.W(8), 0)-
                        (var(component.W(1), -1) +
                        var(component.W(0), +1) + var(component.W(1), +1) * (1 << sigma_sizes[0]) +
                        var(component.W(2), +1) * (one << (sigma_sizes[0] + sigma_sizes[1])) +
                        var(component.W(3), +1) * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2])) +
                        var(component.W(4), +1) * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2] + sigma_sizes[3])) +
                         var(component.W(2), 0) + var(component.W(3), 0) * (1 << 16) +
                         var(component.W(4), 0) * (one << 32) + var(component.W(5), 0) * (one << 48)));
                    auto constraint_5 = bp.add_constraint((var(component.W(8), 0) - 6) * (var(component.W(8), 0) - 5) *
                    (var(component.W(8), 0) - 4)* (var(component.W(8), 0) - 3) * (var(component.W(8), 0) - 2) * (var(component.W(8), 0) - 1) *var(component.W(8), 0));
                    bp.add_gate(first_selector_index + 5, {constraint_4, constraint_5});
                    generate_Maj_gates(component, bp, assignment, first_selector_index + 3);

                    generate_Sigma0_gates(component, bp, assignment, first_selector_index + 1);
                    auto constraint_out_1 = bp.add_constraint(var(component.W(0), +1) + m*var(component.W(4), +1)- (var(component.W(0), 0) + var(component.W(4), 0)));
                    auto constraint_out_2 = bp.add_constraint(var(component.W(1), +1) + m*var(component.W(5), +1) - (var(component.W(1), 0) + var(component.W(5), 0)));
                    auto constraint_out_3 = bp.add_constraint(var(component.W(2), +1) + m*var(component.W(6), +1) - (var(component.W(2), 0) + var(component.W(6), 0)));
                    auto constraint_out_4 = bp.add_constraint(var(component.W(3), +1) + m*var(component.W(7), +1) - (var(component.W(3), 0) + var(component.W(7), 0)));

                    bp.add_gate(first_selector_index + 6, {constraint_out_1,
                    constraint_out_2, constraint_out_3, constraint_out_4});
                }
            }   // namespace detail

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_sha512_process<BlueprintFieldType,
                        ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>;

                std::size_t row = start_row_index;

                typename BlueprintFieldType::integral_type one = 1;
                std::array<typename BlueprintFieldType::value_type, 8> input_state = {
                    var_value(assignment, instance_input.input_state[0]), var_value(assignment, instance_input.input_state[1]),
                    var_value(assignment, instance_input.input_state[2]), var_value(assignment, instance_input.input_state[3]),
                    var_value(assignment, instance_input.input_state[4]), var_value(assignment, instance_input.input_state[5]),
                    var_value(assignment, instance_input.input_state[6]), var_value(assignment, instance_input.input_state[7])};
                std::array<typename BlueprintFieldType::value_type, 80> message_scheduling_words;
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
                    std::vector<bool> input_state_sparse(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> input_state_sparse_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_input_state_sparse, status);
                        std::copy(input_state_sparse_all.end() - 64, input_state_sparse_all.end(), input_state_sparse.begin());
                    }

                    std::vector<std::size_t> input_state_sparse_sizes = {64};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> input_state_sparse_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(input_state_sparse, input_state_sparse_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(i), row + 1) = input_state_sparse_chunks[1][0];
                    sparse_values[i] = input_state_sparse_chunks[1][0];
                }
                for (std::size_t i = 4; i < 8; i++) {
                    assignment.witness(component.W(i), row) = input_state[i];
                    typename BlueprintFieldType::integral_type integral_input_state_sparse =
                        typename BlueprintFieldType::integral_type(input_state[i].data);
                    std::vector<bool> input_state_sparse(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> input_state_sparse_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_input_state_sparse, status);
                        std::copy(input_state_sparse_all.end() - 64, input_state_sparse_all.end(), input_state_sparse.begin());
                    }

                    std::vector<std::size_t> input_state_sparse_sizes = {64};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> input_state_sparse_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(input_state_sparse, input_state_sparse_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(i), row + 1) = input_state_sparse_chunks[1][0];
                    sparse_values[i] = input_state_sparse_chunks[1][0];
                }
                row = row + 2;
                std::vector<std::size_t> sigma_sizes = {14, 14, 14, 14, 8};
                std::vector<std::size_t> ch_and_maj_sizes = {16, 16, 16, 16};
                typename BlueprintFieldType::value_type base4_value =
                    plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4;
                typename BlueprintFieldType::value_type base7_value =
                    plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7;
                for (std::size_t i = row; i < row + 379; i = i + 6) {
                    typename BlueprintFieldType::integral_type integral_a =
                        typename BlueprintFieldType::integral_type(
                            message_scheduling_words[(i - row) / 6 + 1].data);
                    assignment.witness(component.W(0), i) = message_scheduling_words[(i - row) / 6 + 1];
                    std::vector<bool> a(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> a_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_a, status);
                        std::copy(a_all.end() - 64, a_all.end(), a.begin());
                    }

                    std::vector<std::size_t> a_sizes = {1, 6, 1, 14, 14, 14, 14};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> a_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(a, a_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(1), i) = a_chunks[0][0];
                    assignment.witness(component.W(2), i) = a_chunks[0][1];
                    assignment.witness(component.W(3), i) = a_chunks[0][2];
                    assignment.witness(component.W(4), i) = a_chunks[0][3];
                    assignment.witness(component.W(5), i) = a_chunks[0][4];
                    assignment.witness(component.W(6), i) = a_chunks[0][5];
                    assignment.witness(component.W(7), i) = a_chunks[0][6];
                    assignment.witness(component.W(8), i) = a_chunks[1][0];
                    assignment.witness(component.W(0), i + 1) = a_chunks[1][1];
                    assignment.witness(component.W(1), i + 1) = a_chunks[1][2];
                    assignment.witness(component.W(2), i + 1) = a_chunks[1][3];
                    assignment.witness(component.W(3), i + 1) = a_chunks[1][4];
                    assignment.witness(component.W(4), i + 1) = a_chunks[1][5];
                    assignment.witness(component.W(5), i + 1) = a_chunks[1][6];
                    typename BlueprintFieldType::integral_type sparse_sigma0 =
                        a_chunks[1][0] * ((one << (63*2)) + (one << (56*2))) +
                        a_chunks[1][1] * (1 + (one << (57*2))) +
                        a_chunks[1][2] * ((one << (6*2)) + (one << (63*2)) + 1) +
                        a_chunks[1][3] * ((one << (7*2)) + 1 + (one << (1*2))) +
                        a_chunks[1][4] * ((one << (21*2)) + (one << (14*2)) + (one << (15*2))) +
                        a_chunks[1][5] * ((one << (35*2)) + (one << (28*2)) + (one << (29*2))) +
                        a_chunks[1][6] * ((one << (49*2)) + (one << (42*2)) + (one << (43*2)));
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        sigma0_chunks =
                            detail::reversed_sparse_and_split<BlueprintFieldType>(sparse_sigma0, sigma_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(6), i + 1) = sigma0_chunks[1][0];
                    assignment.witness(component.W(7), i + 1) = sigma0_chunks[1][1];
                    assignment.witness(component.W(8), i + 1) = sigma0_chunks[1][2];
                    assignment.witness(component.W(0), i + 2) = sigma0_chunks[1][3];
                    assignment.witness(component.W(1), i + 2) = sigma0_chunks[1][4];

                    assignment.witness(component.W(2), i + 2) = sigma0_chunks[0][0];
                    assignment.witness(component.W(3), i + 2) = sigma0_chunks[0][1];
                    assignment.witness(component.W(4), i + 2) = sigma0_chunks[0][2];
                    assignment.witness(component.W(5), i + 2) = sigma0_chunks[0][3];
                    assignment.witness(component.W(6), i + 2) = sigma0_chunks[0][4];
                    assignment.witness(component.W(7), i + 2) = message_scheduling_words[(i - row) / 6 + 9];
                    assignment.witness(component.W(8), i + 2) = message_scheduling_words[(i - row) / 6];

                    typename BlueprintFieldType::integral_type integral_b =
                        typename BlueprintFieldType::integral_type(
                            message_scheduling_words[(i - row) / 6 + 14].data);
                    std::vector<bool> b(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> b_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);
                        std::copy(b_all.end() - 64, b_all.end(), b.begin());
                    }

                    std::vector<std::size_t> b_sizes = {6, 13, 14, 14, 14, 3};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> b_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(b, b_sizes,
                        plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(0), i + 5) = message_scheduling_words[(i - row) / 6 + 14];
                    assignment.witness(component.W(1), i + 5) = b_chunks[0][0];
                    assignment.witness(component.W(2), i + 5) = b_chunks[0][1];
                    assignment.witness(component.W(3), i + 5) = b_chunks[0][2];
                    assignment.witness(component.W(4), i + 5) = b_chunks[0][3];
                    assignment.witness(component.W(5), i + 5) = b_chunks[0][4];
                    assignment.witness(component.W(6), i + 5) = b_chunks[0][5];

                    assignment.witness(component.W(7), i + 5) = b_chunks[1][0];
                    assignment.witness(component.W(8), i + 5) = b_chunks[1][1];
                    assignment.witness(component.W(0), i + 4) = b_chunks[1][2];
                    assignment.witness(component.W(1), i + 4) = b_chunks[1][3];
                    assignment.witness(component.W(2), i + 4) = b_chunks[1][4];
                    assignment.witness(component.W(3), i + 4) = b_chunks[1][5];

                    typename BlueprintFieldType::integral_type sparse_sigma1 =
                        b_chunks[1][0] * ((one << (2*45)) + (one << (2*3))) +
                        b_chunks[1][1] * ((one << (2*51)) + (one << (2*9)) + 1) +
                        b_chunks[1][2] * (1 + (one << (2*22)) + (one << (2*13))) +
                        b_chunks[1][3] * ((one << (2*14)) + (one << (2*36)) + (one << (2 * 27))) +
                        b_chunks[1][4] * ((one << (2*28)) + (one << (2*50)) + (one << (2*41))) +
                        b_chunks[1][5] * ((one << (2*42)) + 1 + (one << (2 * 55)));

                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        sigma1_chunks =
                            detail::reversed_sparse_and_split<BlueprintFieldType>(sparse_sigma1, sigma_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(4), i + 4) = sigma1_chunks[1][0];
                    assignment.witness(component.W(5), i + 4) = sigma1_chunks[1][1];
                    assignment.witness(component.W(6), i + 4) = sigma1_chunks[1][2];
                    assignment.witness(component.W(7), i + 4) = sigma1_chunks[1][3];
                    assignment.witness(component.W(8), i + 4) = sigma1_chunks[1][4];

                    assignment.witness(component.W(0), i + 3) = sigma1_chunks[0][0];
                    assignment.witness(component.W(1), i + 3) = sigma1_chunks[0][1];
                    assignment.witness(component.W(2), i + 3) = sigma1_chunks[0][2];
                    assignment.witness(component.W(3), i + 3) = sigma1_chunks[0][3];
                    assignment.witness(component.W(4), i + 3) = sigma1_chunks[0][4];
                    typename BlueprintFieldType::value_type sum = message_scheduling_words[(i - row) / 6 + 9] + message_scheduling_words[(i - row) / 6] +
                        sigma1_chunks[0][0] + sigma0_chunks[0][0] +
                        (one << 14) * (sigma1_chunks[0][1] + sigma0_chunks[0][1]) +
                        (one << 28) * (sigma1_chunks[0][2] + sigma0_chunks[0][2]) +
                        (one << 42) * (sigma1_chunks[0][3] + sigma0_chunks[0][3]) +
                        (one << 56) * (sigma1_chunks[0][4] + sigma0_chunks[0][4]) ;
                    message_scheduling_words[(i - row) / 6 + 16] =
                        typename BlueprintFieldType::integral_type(sum.data) %
                        typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                    assignment.witness(component.W(5), i + 3) = message_scheduling_words[(i - row) / 6 + 16];
                    assignment.witness(component.W(6), i + 3) = (sum - message_scheduling_words[(i - row) / 6 + 16]) /
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                }
                row = row + 384;
                for (std::size_t i = row; i < row + 720; i = i + 9) {
                    assignment.witness(component.W(0), i) = e;
                    typename BlueprintFieldType::integral_type integral_e =
                        typename BlueprintFieldType::integral_type(e.data);
                    std::vector<bool> e_bits(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> e_bits_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_e, status);
                        std::copy(e_bits_all.end() - 64, e_bits_all.end(), e_bits.begin());
                    }

                    std::vector<std::size_t> e_sizes = {14, 4, 14, 9, 14, 9};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> e_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(e_bits, e_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(1), i) = e_chunks[0][0];
                    assignment.witness(component.W(2), i) = e_chunks[0][1];
                    assignment.witness(component.W(3), i) = e_chunks[0][2];
                    assignment.witness(component.W(4), i) = e_chunks[0][3];
                    assignment.witness(component.W(5), i) = e_chunks[0][4];
                    assignment.witness(component.W(6), i) = e_chunks[0][5];

                    assignment.witness(component.W(7), i) = e_chunks[1][0];
                    assignment.witness(component.W(8), i) = e_chunks[1][1];
                    assignment.witness(component.W(0), i + 1) = e_chunks[1][2];
                    assignment.witness(component.W(1), i + 1) = e_chunks[1][3];
                    assignment.witness(component.W(2), i + 1) = e_chunks[1][4];
                    assignment.witness(component.W(3), i + 1) = e_chunks[1][5];

                    typename BlueprintFieldType::integral_type sparse_Sigma1 =
                        typename BlueprintFieldType::integral_type((
                        e_chunks[1][0] * (base7_value.pow(50) + base7_value.pow(46) + base7_value.pow(23)) +
                        e_chunks[1][1] * (1 + base7_value.pow(60) + base7_value.pow(37)) +
                        e_chunks[1][2] * (base7_value.pow(4) + 1 + base7_value.pow(41)) +
                        e_chunks[1][3] * (base7_value.pow(18) + base7_value.pow(14) + base7_value.pow(55))+
                        e_chunks[1][4] * (base7_value.pow(27) + base7_value.pow(23) + 1)+
                        e_chunks[1][5] * (base7_value.pow(41) + base7_value.pow(37) + base7_value.pow(14))
                        ).data);
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        Sigma1_chunks =
                            detail::reversed_sparse_and_split<BlueprintFieldType>(sparse_Sigma1, sigma_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(4), i + 1) = Sigma1_chunks[1][0];
                    assignment.witness(component.W(5), i + 1) = Sigma1_chunks[1][1];
                    assignment.witness(component.W(6), i + 1) = Sigma1_chunks[1][2];
                    assignment.witness(component.W(7), i + 1) = Sigma1_chunks[1][3];
                    assignment.witness(component.W(8), i + 1) = Sigma1_chunks[1][4];

                    assignment.witness(component.W(0), i + 2) = Sigma1_chunks[0][0];
                    assignment.witness(component.W(1), i + 2) = Sigma1_chunks[0][1];
                    assignment.witness(component.W(2), i + 2) = Sigma1_chunks[0][2];
                    assignment.witness(component.W(3), i + 2) = Sigma1_chunks[0][3];
                    assignment.witness(component.W(4), i + 2) = Sigma1_chunks[0][4];
                    typename BlueprintFieldType::integral_type Sigma1 =
                        Sigma1_chunks[0][0] + Sigma1_chunks[0][1] * (1 << (sigma_sizes[0])) +
                        Sigma1_chunks[0][2] * (one << (sigma_sizes[0] + sigma_sizes[1])) +
                        Sigma1_chunks[0][3] * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2]))  +
                        Sigma1_chunks[0][4] * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2] + sigma_sizes[3]));


                    sparse_values[4] = typename BlueprintFieldType::integral_type((e_chunks[1][0] +
                                        e_chunks[1][1] * base7_value.pow(e_sizes[0]) +
                                       e_chunks[1][2] * base7_value.pow(e_sizes[0] + e_sizes[1]) +
                                       e_chunks[1][3] * base7_value.pow(e_sizes[0] + e_sizes[1] + e_sizes[2]) +
                                       e_chunks[1][4] * base7_value.pow(e_sizes[0] + e_sizes[1] + e_sizes[2] + e_sizes[3]) +
                                       e_chunks[1][5] * base7_value.pow(e_sizes[0] + e_sizes[1] + e_sizes[2] + e_sizes[3] + e_sizes[4])).data);
                    assignment.witness(component.W(5), i + 2) = sparse_values[4];
                    assignment.witness(component.W(6), i + 2) = sparse_values[5];

                    typename BlueprintFieldType::integral_type sparse_ch =
                        sparse_values[4] + 2 * sparse_values[5] + 3 * sparse_values[6];

                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        ch_chunks =
                            detail::reversed_sparse_and_split_ch<BlueprintFieldType>(sparse_ch, ch_and_maj_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base7);
                    assignment.witness(component.W(7), i + 2) = ch_chunks[1][0];
                    assignment.witness(component.W(8), i + 2) = ch_chunks[1][1];
                    assignment.witness(component.W(0), i + 3) = ch_chunks[1][2];
                    assignment.witness(component.W(1), i + 3) = ch_chunks[1][3];

                    assignment.witness(component.W(2), i + 3) = ch_chunks[0][0];
                    assignment.witness(component.W(3), i + 3) = ch_chunks[0][1];
                    assignment.witness(component.W(4), i + 3) = ch_chunks[0][2];
                    assignment.witness(component.W(5), i + 3) = ch_chunks[0][3];

                    assignment.witness(component.W(6), i + 3) = sparse_values[6];
                    assignment.witness(component.W(7), i + 3) = d;
                    assignment.witness(component.W(8), i + 3) = h;
                    assignment.witness(component.W(0), i + 4) = message_scheduling_words[(i - row) / 9];
                    typename BlueprintFieldType::integral_type ch =
                        ch_chunks[0][0] + ch_chunks[0][1] * (1 << 16) + ch_chunks[0][2] * (one << 32) +
                        ch_chunks[0][3] * (one << 48);

                    typename BlueprintFieldType::value_type tmp1 = h + Sigma1 + ch +
                        plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::round_constant[(i - row) / 9] +
                        message_scheduling_words[(i - row) / 9];
                    typename BlueprintFieldType::value_type sum = tmp1 + d;
                    typename BlueprintFieldType::value_type e_new = typename BlueprintFieldType::integral_type(sum.data) %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                    assignment.witness(component.W(1), i + 4) = tmp1;
                    assignment.witness(component.W(2), i + 4) = e_new;
                    assignment.witness(component.W(3), i + 4) = (sum - e_new)/typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);

                    assignment.witness(component.W(0), i + 8) = a;
                    typename BlueprintFieldType::integral_type integral_a =
                        typename BlueprintFieldType::integral_type(a.data);
                    std::vector<bool> a_bits(64);
                    {
                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::value_bits> a_bits_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_a, status);
                        std::copy(a_bits_all.end() - 64, a_bits_all.end(), a_bits.begin());
                    }

                    std::vector<std::size_t> a_sizes = {14, 14, 6, 5, 14, 11};
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> a_chunks =
                        detail::split_and_sparse<BlueprintFieldType>(a_bits, a_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(1), i + 8) = a_chunks[0][0];
                    assignment.witness(component.W(2), i + 8) = a_chunks[0][1];
                    assignment.witness(component.W(3), i + 8) = a_chunks[0][2];
                    assignment.witness(component.W(4), i + 8) = a_chunks[0][3];
                    assignment.witness(component.W(5), i + 8) = a_chunks[0][4];
                    assignment.witness(component.W(6), i + 8) = a_chunks[0][5];

                    assignment.witness(component.W(7), i + 8) = a_chunks[1][0];
                    assignment.witness(component.W(8), i + 8) = a_chunks[1][1];
                    assignment.witness(component.W(0), i + 7) = a_chunks[1][2];
                    assignment.witness(component.W(1), i + 7) = a_chunks[1][3];
                    assignment.witness(component.W(2), i + 7) = a_chunks[1][4];
                    assignment.witness(component.W(3), i + 7) = a_chunks[1][5];

                    typename BlueprintFieldType::integral_type sparse_Sigma0 =
                        (a_chunks[1][0] * ((one << (36 *2)) + (one << (30*2)) + (one << (25*2))) +
                         a_chunks[1][1] * ((one << (50 * 2)) + (one << (44*2)) + (one << (39*2))) +
                         a_chunks[1][2] * (1 + (one << (58*2)) + (one << (53*2))) +
                         a_chunks[1][3] * ((one << (6*2)) + 1 + (one << (59*2))) +
                         a_chunks[1][4] * ((one << (11*2)) + (one << (5*2)) + 1) +
                         a_chunks[1][5] * ((one << (25*2)) + (one << (19*2)) + (one << (14*2))));
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        Sigma0_chunks =
                            detail::reversed_sparse_and_split<BlueprintFieldType>(sparse_Sigma0, sigma_sizes,
                            plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(4), i + 7) = Sigma0_chunks[1][0];
                    assignment.witness(component.W(5), i + 7) = Sigma0_chunks[1][1];
                    assignment.witness(component.W(6), i + 7) = Sigma0_chunks[1][2];
                    assignment.witness(component.W(7), i + 7) = Sigma0_chunks[1][3];
                    assignment.witness(component.W(8), i + 7) = Sigma0_chunks[1][4];

                    assignment.witness(component.W(0), i + 6) = Sigma0_chunks[0][0];
                    assignment.witness(component.W(1), i + 6) = Sigma0_chunks[0][1];
                    assignment.witness(component.W(2), i + 6) = Sigma0_chunks[0][2];
                    assignment.witness(component.W(3), i + 6) = Sigma0_chunks[0][3];
                    assignment.witness(component.W(4), i + 6) = Sigma0_chunks[0][4];

                    typename BlueprintFieldType::integral_type Sigma0 =
                        Sigma0_chunks[0][0] + Sigma0_chunks[0][1] * (1 << sigma_sizes[0]) +
                        Sigma0_chunks[0][2] * (one << (sigma_sizes[0] + sigma_sizes[1])) +
                        Sigma0_chunks[0][3] * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2])) +
                        Sigma0_chunks[0][4] * (one << (sigma_sizes[0] + sigma_sizes[1] + sigma_sizes[2] + sigma_sizes[3]));

                    sparse_values[0] = typename BlueprintFieldType::integral_type((a_chunks[1][0] + a_chunks[1][1] * base4_value.pow(a_sizes[0]) +
                                       a_chunks[1][2] * base4_value.pow(a_sizes[0] + a_sizes[1]) +
                                       a_chunks[1][3] * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2]) +
                                       a_chunks[1][4] * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2] + a_sizes[3]) +
                                       a_chunks[1][5] * base4_value.pow(a_sizes[0] + a_sizes[1] + a_sizes[2] + a_sizes[3] + a_sizes[4])
                                       ).data);
                    assignment.witness(component.W(5), i + 6) = sparse_values[0];
                    assignment.witness(component.W(6), i + 6) = sparse_values[1];

                    typename BlueprintFieldType::integral_type sparse_maj =
                        (sparse_values[0] + sparse_values[1] + sparse_values[2]);
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                        maj_chunks =
                            detail::reversed_sparse_and_split_maj<BlueprintFieldType>(
                                sparse_maj, ch_and_maj_sizes,
                                plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::base4);
                    assignment.witness(component.W(7), i + 6) = maj_chunks[1][0];
                    assignment.witness(component.W(8), i + 6) = maj_chunks[1][1];
                    assignment.witness(component.W(0), i + 5) = maj_chunks[1][2];
                    assignment.witness(component.W(1), i + 5) = maj_chunks[1][3];

                    assignment.witness(component.W(2), i + 5) = maj_chunks[0][0];
                    assignment.witness(component.W(3), i + 5) = maj_chunks[0][1];
                    assignment.witness(component.W(4), i + 5) = maj_chunks[0][2];
                    assignment.witness(component.W(5), i + 5) = maj_chunks[0][3];
                    typename BlueprintFieldType::integral_type maj =
                        maj_chunks[0][0] + maj_chunks[0][1] * (1 << 16) + maj_chunks[0][2] * (one << 32) +
                        maj_chunks[0][3] * (one << 48);
                    assignment.witness(component.W(6), i + 5) = sparse_values[2];
                    typename BlueprintFieldType::value_type sum1 = tmp1 + Sigma0 + maj;
                    typename BlueprintFieldType::value_type a_new = typename BlueprintFieldType::integral_type(sum1.data) %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                    assignment.witness(component.W(7), i + 5) = a_new;
                    assignment.witness(component.W(8), i + 5) = (sum1 - a_new)/ typename BlueprintFieldType::value_type(2).pow(64);
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
                row = row + 720;
                for(std::size_t i = 0; i < 4; i ++){
                    assignment.witness(component.W(i), row)= input_state[i];
                    auto sum = typename BlueprintFieldType::integral_type(input_state[i].data) + typename BlueprintFieldType::integral_type(output_state[i].data);
                    assignment.witness(component.W(i), row + 1) = sum %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                    assignment.witness(component.W(i + 4), row) = output_state[i];
                    assignment.witness(component.W(i + 4), row + 1) = (sum - sum %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data))/
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                }
                row = row + 2;
                    for(std::size_t i = 0; i < 4; i ++){
                    assignment.witness(component.W(i), row) = input_state[i + 4];
                    auto sum = typename BlueprintFieldType::integral_type(input_state[i + 4].data) + typename BlueprintFieldType::integral_type(output_state[i + 4].data);
                    assignment.witness(component.W(i), row + 1) = sum %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                    assignment.witness(component.W(i + 4), row) = output_state[i + 4];
                    assignment.witness(component.W(i + 4), row + 1) = (sum - sum %
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data))/
                    typename BlueprintFieldType::integral_type(typename BlueprintFieldType::value_type(2).pow(64).data);
                }
                return typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t first_selector_index) {

                detail::generate_message_scheduling_gates(component, bp, assignment, first_selector_index);
                detail::generate_compression_gates(component, bp, assignment, first_selector_index + 3);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index + 2;

                for (std::size_t i = 1; i <= 15; ++i) {
                    bp.add_copy_constraint({var(component.W(0), row + (i - 1)*6 + 0, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 9; i <= 15; ++i) {
                    bp.add_copy_constraint({var(component.W(7), row + (i - 9)*6 + 2, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 0; i <= 15; ++i) {
                    bp.add_copy_constraint({var(component.W(8), row + (i - 0)*6 + 2, false), instance_input.input_words[i]});
                }
                for (std::size_t i = 14; i <= 15; ++i) {
                   bp.add_copy_constraint({var(component.W(0), row + (i - 14)*6 + 5, false), instance_input.input_words[i]});
                }

                row = row + 384;

                bp.add_copy_constraint({var(component.W(6), row + 2, false), var(component.W(5), start_row_index + 1)});
                bp.add_copy_constraint({var(component.W(6), row + 3, false), var(component.W(6), start_row_index + 1)});
                bp.add_copy_constraint({var(component.W(6), row + 6, false), var(component.W(1), start_row_index + 1)});
                bp.add_copy_constraint({var(component.W(6), row + 5, false), var(component.W(2), start_row_index + 1)});

                for (std::size_t i = row; i < row + 720 - 9; i = i + 9){
                    bp.add_copy_constraint({var(component.W(6), (i + 2) + 9, false), var(component.W(5), (i + 2), false)});
                    bp.add_copy_constraint({var(component.W(6), (i + 3) + 9, false), var(component.W(6), (i + 2), false)});
                    bp.add_copy_constraint({var(component.W(6), (i + 5) + 9, false), var(component.W(6), (i + 6), false)});
                    bp.add_copy_constraint({var(component.W(6), (i + 6) + 9, false), var(component.W(5), (i + 6), false)});
                }

                bp.add_copy_constraint({var(component.W(0), row + 8, false), instance_input.input_state[0]});
                bp.add_copy_constraint({var(component.W(7), row + 3, false), instance_input.input_state[3]});
                bp.add_copy_constraint({var(component.W(0), row + 0, false), instance_input.input_state[4]});
                bp.add_copy_constraint({var(component.W(8), row + 3, false), instance_input.input_state[7]});

                row = row + 720;

                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.input_state[0]});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.input_state[1]});
                bp.add_copy_constraint({var(component.W(2), row, false), instance_input.input_state[2]});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.input_state[3]});
                bp.add_copy_constraint({var(component.W(0), row + 2, false), instance_input.input_state[4]});
                bp.add_copy_constraint({var(component.W(1), row + 2, false), instance_input.input_state[5]});
                bp.add_copy_constraint({var(component.W(2), row + 2, false), instance_input.input_state[6]});
                bp.add_copy_constraint({var(component.W(3), row + 2, false), instance_input.input_state[7]});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_sha512_process<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index){

                    std::size_t j = start_row_index;
                    detail::generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                    j = j + 2;
                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component,
                            component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }
                    assignment.enable_selector(first_selector_index, j + 1, j + 383, 6);
                    assignment.enable_selector(first_selector_index + 1, j + 4, j + 383, 6);
                    assignment.enable_selector(first_selector_index + 2, j + 3, j + 383, 6);
                    j = j + 384;
                    assignment.enable_selector(first_selector_index + 3, j + 1, j + 719, 9);
                    assignment.enable_selector(first_selector_index + 4, j + 7, j + 719, 9);
                    assignment.enable_selector(first_selector_index + 5, j + 2, j + 719, 9);
                    assignment.enable_selector(first_selector_index + 6, j + 6, j + 719, 9);
                    assignment.enable_selector(first_selector_index + 7, j + 3, j + 719, 9);
                    assignment.enable_selector(first_selector_index + 8, j + 5, j + 719, 9);
                    j = j + 720;
                    assignment.enable_selector(first_selector_index + 9, j, j + 2, 2);
                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                    return typename plonk_sha512_process<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
                }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_PROCESS_HPP
