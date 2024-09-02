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
// @file Declaration of interfaces for auxiliary components for the SHA512 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512_process.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class sha512;

            template<typename BlueprintFieldType>
            class sha512<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType> {

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using sha512_process_component = sha512_process<ArithmetizationType>;
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return sha512::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(sha512_process_component::get_gate_manifest(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<nil::blueprint::manifest_param>(
                            new nil::blueprint::manifest_single_value_param(9)),
                        true
                    ).merge_with(sha512_process_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return
                        rows_amount_creating_input_words_component +
                        sha512_process_component::get_rows_amount(witness_amount) * 2 /* + 2 */;
                }

                constexpr static const std::size_t gates_amount = 5;
                constexpr static const std::size_t rows_amount_creating_input_words_component = 15;
                const std::string component_name = "sha512 hash";
//
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());

                struct var_ec_point {
                    std::array<var, 4> x;
                    std::array<var, 4> y;
                };

                struct input_type {
                    var_ec_point R;
                    var_ec_point A;
                    std::array<var, 4> M;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(20);
                        result.insert(result.end(), R.x.begin(), R.x.end());
                        result.insert(result.end(), R.y.begin(), R.y.end());
                        result.insert(result.end(), A.x.begin(), A.x.end());
                        result.insert(result.end(), A.y.begin(), A.y.end());
                        result.insert(result.end(), M.begin(), M.end());
                        return result;
                    }
                };

                struct result_type {
                    std::array<var, 8> output_state;

                    result_type(const sha512 &component, const std::size_t &start_row_index) {
                        output_state = {var(component.W(0), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 3, false),
                                        var(component.W(0), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(3), start_row_index + component.rows_amount - 1, false)};
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(8);
                        result.insert(result.end(), output_state.begin(), output_state.end());
                        return result;
                    }
                };

                template <typename ContainerType>
                    sha512(ContainerType witness):
                        component_type(witness, {}, {}, get_manifest()){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                    sha512(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                        component_type(witness, constant, public_input, get_manifest()){};

                    sha512(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                                   std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                                   std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs, get_manifest()){};
            };

            template<typename BlueprintFieldType>
            using plonk_sha512 = sha512<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_sha512<BlueprintFieldType>::result_type
                generate_circuit(
                    const plonk_sha512<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_sha512<BlueprintFieldType>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type = plonk_sha512<BlueprintFieldType>;
                    using sha512_process_component = typename component_type::sha512_process_component;
                    using var = typename component_type::var;

                    generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                    auto selector_indices = generate_gates(component, bp, assignment, instance_input);

                    std::size_t j = start_row_index;

                    assignment.enable_selector(selector_indices[0], j + 1);
                    assignment.enable_selector(selector_indices[1], j + 4);
                    assignment.enable_selector(selector_indices[2], j + 7);
                    assignment.enable_selector(selector_indices[3], j + 10);
                    assignment.enable_selector(selector_indices[4], j + 13);

                    std::array<var, 16> input_words_vars_1;

                    for(std::size_t k = 0; k < 4; k++) {
                        for(std::size_t i = 0; i < 4; i++) {
                            input_words_vars_1[4*k + i] = var(2*i, start_row_index + 1 + 3*k, false);
                        }
                    }

                    std::array<var, 8> constants_var = {var(0, start_row_index, false, var::column_type::constant),
                                                        var(0, start_row_index + 1, false, var::column_type::constant),
                                                        var(0, start_row_index + 2, false, var::column_type::constant),
                                                        var(0, start_row_index + 3, false, var::column_type::constant),
                                                        var(0, start_row_index + 4, false, var::column_type::constant),
                                                        var(0, start_row_index + 5, false, var::column_type::constant),
                                                        var(0, start_row_index + 6, false, var::column_type::constant),
                                                        var(0, start_row_index + 7, false, var::column_type::constant)};
                    sha512_process_component sha512_process_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});
                    typename sha512_process_component::input_type sha_params = {constants_var, input_words_vars_1};
                    j = j + 15;
                    auto sha_output =
                        generate_circuit(sha512_process_instance, bp, assignment, sha_params, j).output_state;
                    j += sha512_process_instance.rows_amount;

                    // second chunk
                    std::array<var, 16> input_words_vars_2;

                    for(std::size_t i = 0; i < 4; i++) {
                        input_words_vars_2[i] = var(2*i, start_row_index + 1 + 12, false);
                    }

                    for (std::size_t i = 4; i < 15; i++) {
                        input_words_vars_2[i] = var(0, start_row_index + 8, false, var::column_type::constant);
                    }
                    input_words_vars_2[15] = var(0, start_row_index + 9, false, var::column_type::constant);


                    sha_params = {sha_output, input_words_vars_2};
                    generate_circuit(sha512_process_instance, bp, assignment, sha_params, j);

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                    return typename plonk_sha512<BlueprintFieldType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType>
            typename plonk_sha512<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_sha512<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_sha512<BlueprintFieldType>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                    using var = typename sha512<ArithmetizationType>::var;

                    std::size_t row = start_row_index;

                    std::array<typename BlueprintFieldType::integral_type, 20> RAM = {
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.x[0]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.x[1]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.x[2]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.x[3]).data),

                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.y[0]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.y[1]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.y[2]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.R.y[3]).data),

                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.x[0]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.x[1]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.x[2]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.x[3]).data),

                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.y[0]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.y[1]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.y[2]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A.y[3]).data),

                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.M[0]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.M[1]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.M[2]).data),
                        typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.M[3]).data)
                        };



                    std::array<typename BlueprintFieldType::integral_type, 32> input_words_values;
                    typename BlueprintFieldType::integral_type integral_one = 1;
                    typename BlueprintFieldType::integral_type mask = ((integral_one<<64) - 1);
                    input_words_values[0] = (RAM[0]) & mask;
                    input_words_values[1] = ((RAM[0] >> 64) + (RAM[1] << 2)) & mask;
                    input_words_values[2] = ((RAM[1] >> 62) + (RAM[2] << 4)) & mask;
                    input_words_values[3] = ((RAM[2] >> 60) + (RAM[3] << 6) + (RAM[4] << 63)) & mask;
                    input_words_values[4] = ((RAM[4] >> 1)) & mask;
                    input_words_values[5] = ((RAM[4] >> 65) + (RAM[5] << 1)) & mask;
                    input_words_values[6] = ((RAM[5] >> 63) + (RAM[6] << 3)) & mask;
                    input_words_values[7] = ((RAM[6] >> 61) + (RAM[7] << 5) + (RAM[8] << 62)) & mask;
                    input_words_values[8] = ((RAM[8] >> 2)) & mask;
                    input_words_values[9] = ((RAM[9])) & mask;
                    input_words_values[10] = ((RAM[9] >> 64) + (RAM[10] << 2)) & mask;
                    input_words_values[11] = ((RAM[10] >> 62) + (RAM[11] << 4) + (RAM[12] << 61)) & mask;
                    input_words_values[12] = ((RAM[12] >> 3) + (RAM[13] << 63)) & mask;
                    input_words_values[13] = ((RAM[13] >> 1)) & mask;
                    input_words_values[14] = ((RAM[13] >> 65) + (RAM[14] << 1)) & mask;
                    input_words_values[15] = ((RAM[14] >> 63) + (RAM[15] << 3) + (RAM[16] << 60)) & mask;
                    input_words_values[16] = ((RAM[16] >> 4) + (RAM[17] << 62)) & mask;
                    input_words_values[17] = ((RAM[17] >> 2)) & mask;
                    input_words_values[18] = ((RAM[18])) & mask;
                    input_words_values[19] = ((RAM[18] >> 64) + (RAM[19] << 2) + (integral_one << 60));


                    for (std::size_t i = 20; i < 31; ++i) {
                        input_words_values[i] = 0;
                    }
                    input_words_values[31] = 1024 + 252;


                    std::array<typename BlueprintFieldType::integral_type, 77> range_chunks;

                    typename BlueprintFieldType::integral_type mask22 = ((integral_one<<22) - 1);
                    typename BlueprintFieldType::integral_type mask21 = ((integral_one<<21) - 1);
                    typename BlueprintFieldType::integral_type mask20 = ((integral_one<<20) - 1);
                    typename BlueprintFieldType::integral_type mask19 = ((integral_one<<19) - 1);
                    typename BlueprintFieldType::integral_type mask18 = ((integral_one<<18) - 1);
                    typename BlueprintFieldType::integral_type mask17 = ((integral_one<<17) - 1);
                    typename BlueprintFieldType::integral_type mask16 = ((integral_one<<16) - 1);
                    typename BlueprintFieldType::integral_type mask14 = ((integral_one<<14) - 1);
                    typename BlueprintFieldType::integral_type mask13 = ((integral_one<<13) - 1);

                    auto row_witness = row + 1;

                    // W0,1     W1,1                    W1,0                 W1, -1
                    // 12|34567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[0] = RAM[0] & mask22;
                    range_chunks[1] = (RAM[0] >> 22) & mask22;
                    range_chunks[2] = (RAM[0] >> 44) & mask20;
                    range_chunks[3] = (RAM[0] >> 64) & 0b11;

                    assignment.witness(component.W(0), row_witness - 1) = RAM[0];
                    assignment.witness(component.W(0), row_witness - 0) = input_words_values[0];
                    assignment.witness(component.W(1), row_witness - 1) = range_chunks[0];
                    assignment.witness(component.W(1), row_witness - 0) = range_chunks[1];
                    assignment.witness(component.W(1), row_witness + 1) = range_chunks[2];
                    assignment.witness(component.W(0), row_witness + 1) = range_chunks[3];


                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 1234|567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[4] = (RAM[1]) & mask22;
                    range_chunks[5] = (RAM[1] >> 22) & mask22;
                    range_chunks[6] = (RAM[1] >> 44) & mask18;
                    range_chunks[7] = (RAM[1] >> 62) & 15;

                    assignment.witness(component.W(2), row_witness - 1) = RAM[1];
                    assignment.witness(component.W(2), row_witness - 0) = input_words_values[1];
                    assignment.witness(component.W(3), row_witness - 1) = range_chunks[4];
                    assignment.witness(component.W(3), row_witness - 0) = range_chunks[5];
                    assignment.witness(component.W(3), row_witness + 1) = range_chunks[6];
                    assignment.witness(component.W(2), row_witness + 1) = range_chunks[7];





                    //  W4,1        W5,1                W5,0                  W5, -1
                    // 123456|7890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[8] = (RAM[2]) & mask22;
                    range_chunks[9] = (RAM[2] >> 22) & mask22;
                    range_chunks[10] = (RAM[2] >> 44) & mask16;
                    range_chunks[11] = (RAM[2] >> 60) & 0b111111;

                    assignment.witness(component.W(4), row_witness - 1) = RAM[2];
                    assignment.witness(component.W(4), row_witness - 0) = input_words_values[2];
                    assignment.witness(component.W(5), row_witness - 1) = range_chunks[8];
                    assignment.witness(component.W(5), row_witness - 0) = range_chunks[9];
                    assignment.witness(component.W(5), row_witness + 1) = range_chunks[10];
                    assignment.witness(component.W(4), row_witness + 1) = range_chunks[11];



                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    range_chunks[12] = (RAM[3]) & mask22;
                    range_chunks[13] = (RAM[3] >> 22) & mask22;
                    range_chunks[14] = (RAM[3] >> 44) & mask13;

                    assignment.witness(component.W(6), row_witness - 1) = RAM[3];
                    assignment.witness(component.W(6), row_witness - 0) = input_words_values[3];
                    assignment.witness(component.W(7), row_witness - 1) = range_chunks[12];
                    assignment.witness(component.W(7), row_witness - 0) = range_chunks[13];
                    assignment.witness(component.W(7), row_witness + 1) = range_chunks[14];



                    row_witness += 3;

                    // W0,1      W1,1                  W1,0               W1,-1             W8,-1
                    // 1|234567890123456789012.3456789012345678901234.567890123456789012345|6
                    range_chunks[15] = (RAM[4]) & 1;
                    range_chunks[16] = (RAM[4] >> 1) & mask21;
                    range_chunks[17] = (RAM[4] >> 22) & mask22;
                    range_chunks[18] = (RAM[4] >> 44) & mask21;
                    range_chunks[19] = (RAM[4] >> 65) & 1;

                    assignment.witness(component.W(6), row_witness-3 + 1) = range_chunks[15];
                    assignment.witness(component.W(8), row_witness - 1) = range_chunks[15];


                    assignment.witness(component.W(0), row_witness - 1) = RAM[4];
                    assignment.witness(component.W(0), row_witness - 0) = input_words_values[4];
                    assignment.witness(component.W(1), row_witness - 1) = range_chunks[16];
                    assignment.witness(component.W(1), row_witness - 0) = range_chunks[17];
                    assignment.witness(component.W(1), row_witness + 1) = range_chunks[18];
                    assignment.witness(component.W(0), row_witness + 1) = range_chunks[19];


                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 123|4567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[20] = (RAM[5]) & mask22;
                    range_chunks[21] = (RAM[5] >> 22) & mask22;
                    range_chunks[22] = (RAM[5] >> 44) & mask19;
                    range_chunks[23] = (RAM[5] >> 63) & 0b111;

                    assignment.witness(component.W(2), row_witness - 1) = RAM[5];
                    assignment.witness(component.W(2), row_witness - 0) = input_words_values[5];
                    assignment.witness(component.W(3), row_witness - 1) = range_chunks[20];
                    assignment.witness(component.W(3), row_witness - 0) = range_chunks[21];
                    assignment.witness(component.W(3), row_witness + 1) = range_chunks[22];
                    assignment.witness(component.W(2), row_witness + 1) = range_chunks[23];



                    //  W4,1        W5,1                W5,0                  W5, -1
                    // 12345|67890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[24] = (RAM[6]) & mask22;
                    range_chunks[25] = (RAM[6] >> 22) & mask22;
                    range_chunks[26] = (RAM[6] >> 44) & mask17;
                    range_chunks[27] = (RAM[6] >> 61) & 0b11111;

                    assignment.witness(component.W(4), row_witness - 1) = RAM[6];
                    assignment.witness(component.W(4), row_witness - 0) = input_words_values[6];
                    assignment.witness(component.W(5), row_witness - 1) = range_chunks[24];
                    assignment.witness(component.W(5), row_witness - 0) = range_chunks[25];
                    assignment.witness(component.W(5), row_witness + 1) = range_chunks[26];
                    assignment.witness(component.W(4), row_witness + 1) = range_chunks[27];



                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    range_chunks[28] = (RAM[7]) & mask22;
                    range_chunks[29] = (RAM[7] >> 22) & mask22;
                    range_chunks[30] = (RAM[7] >> 44) & mask13;

                    assignment.witness(component.W(6), row_witness - 1) = RAM[7];
                    assignment.witness(component.W(6), row_witness - 0) = input_words_values[7];
                    assignment.witness(component.W(7), row_witness - 1) = range_chunks[28];
                    assignment.witness(component.W(7), row_witness - 0) = range_chunks[29];
                    assignment.witness(component.W(7), row_witness + 1) = range_chunks[30];

                    row_witness += 3;



                    //          W0,1                    W1,1                  W1,0        W1,-1
                    // |1234567890123456789012.3456789012345678901234.56789012345678901234|56
                    range_chunks[31] = RAM[8] & 0b11;
                    range_chunks[32] = (RAM[8] >> 2) & mask20;
                    range_chunks[33] = (RAM[8] >> 22) & mask22;
                    range_chunks[34] = (RAM[8] >> 44) & mask22;

                    assignment.witness(component.W(6), row_witness-3 + 1) = range_chunks[31];

                    assignment.witness(component.W(0), row_witness - 1) = RAM[8];
                    assignment.witness(component.W(0), row_witness - 0) = input_words_values[8];
                    assignment.witness(component.W(1), row_witness - 1) = range_chunks[31];
                    assignment.witness(component.W(1), row_witness - 0) = range_chunks[32];
                    assignment.witness(component.W(1), row_witness + 1) = range_chunks[33];
                    assignment.witness(component.W(0), row_witness + 1) = range_chunks[34];



                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 12|34567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[35] = (RAM[9]) & mask22;
                    range_chunks[36] = (RAM[9] >> 22) & mask22;
                    range_chunks[37] = (RAM[9] >> 44) & mask20;
                    range_chunks[38] = (RAM[9] >> 64) & 0b11;

                    assignment.witness(component.W(2), row_witness - 1) = RAM[9];
                    assignment.witness(component.W(2), row_witness - 0) = input_words_values[9];
                    assignment.witness(component.W(3), row_witness - 1) = range_chunks[35];
                    assignment.witness(component.W(3), row_witness - 0) = range_chunks[36];
                    assignment.witness(component.W(3), row_witness + 1) = range_chunks[37];
                    assignment.witness(component.W(2), row_witness + 1) = range_chunks[38];



                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 1234|567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[39] = (RAM[10]) & mask22;
                    range_chunks[40] = (RAM[10] >> 22) & mask22;
                    range_chunks[41] = (RAM[10] >> 44) & mask18;
                    range_chunks[42] = (RAM[10] >> 62) & 0b1111;

                    assignment.witness(component.W(4), row_witness - 1) = RAM[10];
                    assignment.witness(component.W(4), row_witness - 0) = input_words_values[10];
                    assignment.witness(component.W(5), row_witness - 1) = range_chunks[39];
                    assignment.witness(component.W(5), row_witness - 0) = range_chunks[40];
                    assignment.witness(component.W(5), row_witness + 1) = range_chunks[41];
                    assignment.witness(component.W(4), row_witness + 1) = range_chunks[42];



                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    range_chunks[43] = (RAM[11]) & mask22;
                    range_chunks[44] = (RAM[11] >> 22) & mask22;
                    range_chunks[45] = (RAM[11] >> 44) & mask13;

                    assignment.witness(component.W(6), row_witness - 1) = RAM[11];
                    assignment.witness(component.W(6), row_witness - 0) = input_words_values[11];
                    assignment.witness(component.W(7), row_witness - 1) = range_chunks[43];
                    assignment.witness(component.W(7), row_witness - 0) = range_chunks[44];
                    assignment.witness(component.W(7), row_witness + 1) = range_chunks[45];

                    row_witness += 3;


                    //         W0,1                    W1,1                  W1,0        (W1,-1  &  W6,1-3)
                    // 1234567890123456789012.3456789012345678901234.5678901234567890123|456
                    range_chunks[46] = (RAM[12]) & 0b111;
                    range_chunks[47] = (RAM[12] >> 3) & mask19;
                    range_chunks[48] = (RAM[12] >> 22) & mask22;
                    range_chunks[49] = (RAM[12] >> 44) & mask22;

                    assignment.witness(component.W(6), row_witness-3 + 1) = range_chunks[46];

                    assignment.witness(component.W(0), row_witness - 1) = RAM[12];
                    assignment.witness(component.W(0), row_witness - 0) = input_words_values[12];
                    assignment.witness(component.W(1), row_witness - 1) = range_chunks[46];
                    assignment.witness(component.W(1), row_witness - 0) = range_chunks[47];
                    assignment.witness(component.W(1), row_witness + 1) = range_chunks[48];
                    assignment.witness(component.W(0), row_witness + 1) = range_chunks[49];



                    // W2,1       W3,1                  W3,0                  W3, -1        W8, -1
                    // 1|234567890123456789012.3456789012345678901234.567890123456789012345|6
                    range_chunks[50] = (RAM[13]) & 1;
                    range_chunks[51] = (RAM[13] >> 1) & mask21;
                    range_chunks[52] = (RAM[13] >> 22) & mask22;
                    range_chunks[53] = (RAM[13] >> 44) & mask21;
                    range_chunks[54] = (RAM[13] >> 65) & 1;

                    assignment.witness(component.W(2), row_witness - 1) = RAM[13];
                    assignment.witness(component.W(2), row_witness - 0) = input_words_values[13];
                    assignment.witness(component.W(8), row_witness - 1) = range_chunks[50];
                    assignment.witness(component.W(3), row_witness - 1) = range_chunks[51];
                    assignment.witness(component.W(3), row_witness - 0) = range_chunks[52];
                    assignment.witness(component.W(3), row_witness + 1) = range_chunks[53];
                    assignment.witness(component.W(2), row_witness + 1) = range_chunks[54];




                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 123|4567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[55] = (RAM[14]) & mask22;
                    range_chunks[56] = (RAM[14] >> 22) & mask22;
                    range_chunks[57] = (RAM[14] >> 44) & mask19;
                    range_chunks[58] = (RAM[14] >> 63) & 0b111;

                    assignment.witness(component.W(4), row_witness - 1) = RAM[14];
                    assignment.witness(component.W(4), row_witness - 0) = input_words_values[14];
                    assignment.witness(component.W(5), row_witness - 1) = range_chunks[55];
                    assignment.witness(component.W(5), row_witness - 0) = range_chunks[56];
                    assignment.witness(component.W(5), row_witness + 1) = range_chunks[57];
                    assignment.witness(component.W(4), row_witness + 1) = range_chunks[58];




                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    range_chunks[59] = (RAM[15]) & mask22;
                    range_chunks[60] = (RAM[15] >> 22) & mask22;
                    range_chunks[61] = (RAM[15] >> 44) & mask13;

                    assignment.witness(component.W(6), row_witness - 1) = RAM[15];
                    assignment.witness(component.W(6), row_witness - 0) = input_words_values[15];
                    assignment.witness(component.W(7), row_witness - 1) = range_chunks[59];
                    assignment.witness(component.W(7), row_witness - 0) = range_chunks[60];
                    assignment.witness(component.W(7), row_witness + 1) = range_chunks[61];

                    row_witness += 3;




                    //         W0,1                    W1,1                  W1,0        (W1,-1  &  W6,1-3)
                    // 1234567890123456789012.3456789012345678901234.567890123456789012|3456
                    range_chunks[62] = (RAM[16]) & 0b1111;
                    range_chunks[63] = (RAM[16] >> 4) & mask18;
                    range_chunks[64] = (RAM[16] >> 22) & mask22;
                    range_chunks[65] = (RAM[16] >> 44) & mask22;

                    assignment.witness(component.W(6), row_witness-3 + 1) = range_chunks[62];

                    assignment.witness(component.W(0), row_witness - 1) = RAM[16];
                    assignment.witness(component.W(0), row_witness - 0) = input_words_values[16];
                    assignment.witness(component.W(1), row_witness - 1) = range_chunks[62];
                    assignment.witness(component.W(1), row_witness - 0) = range_chunks[63];
                    assignment.witness(component.W(1), row_witness + 1) = range_chunks[64];
                    assignment.witness(component.W(0), row_witness + 1) = range_chunks[65];



                    //           W2,1                    W3,1                  W3,0      W3, -1
                    // |1234567890123456789012.3456789012345678901234.56789012345678901234|56
                    range_chunks[66] = (RAM[17]) & 3;
                    range_chunks[67] = (RAM[17] >> 2) & mask20;
                    range_chunks[68] = (RAM[17] >> 22) & mask22;
                    range_chunks[69] = (RAM[17] >> 44) & mask22;
                    assignment.witness(component.W(2), row_witness - 1) = RAM[17];
                    assignment.witness(component.W(2), row_witness - 0) = input_words_values[17];
                    assignment.witness(component.W(3), row_witness - 1) = range_chunks[66];
                    assignment.witness(component.W(3), row_witness - 0) = range_chunks[67];
                    assignment.witness(component.W(3), row_witness + 1) = range_chunks[68];
                    assignment.witness(component.W(2), row_witness + 1) = range_chunks[69];




                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 12|34567890123456789012.3456789012345678901234.5678901234567890123456
                    range_chunks[70] = (RAM[18]) & mask22;
                    range_chunks[71] = (RAM[18] >> 22) & mask22;
                    range_chunks[72] = (RAM[18] >> 44) & mask20;
                    range_chunks[73] = (RAM[18] >> 64) & 0b11;

                    assignment.witness(component.W(4), row_witness - 1) = RAM[18];
                    assignment.witness(component.W(4), row_witness - 0) = input_words_values[18];
                    assignment.witness(component.W(5), row_witness - 1) = range_chunks[70];
                    assignment.witness(component.W(5), row_witness - 0) = range_chunks[71];
                    assignment.witness(component.W(5), row_witness + 1) = range_chunks[72];
                    assignment.witness(component.W(4), row_witness + 1) = range_chunks[73];




                    //     W7, 1              W7, 0                 W7, -1
                    // 12345678901234.5678901234567890123456.7890123456789012345678
                    range_chunks[74] = (RAM[19]) & mask22;
                    range_chunks[75] = (RAM[19] >> 22) & mask22;
                    range_chunks[76] = (RAM[19] >> 44) & mask14;

                    assignment.witness(component.W(6), row_witness - 1) = RAM[19];
                    assignment.witness(component.W(6), row_witness - 0) = input_words_values[19];
                    assignment.witness(component.W(7), row_witness - 1) = range_chunks[74];
                    assignment.witness(component.W(7), row_witness - 0) = range_chunks[75];
                    assignment.witness(component.W(7), row_witness + 1) = range_chunks[76];
                    assignment.witness(component.W(8), row_witness + 1) = 1;




                    std::array<var, 16> input_words_vars_1;
                    std::array<var, 16> input_words_vars_2;


                    for(std::size_t j = 0; j < 4; j++) {
                        for(std::size_t i = 0; i < 4; i++) {
                            input_words_vars_1[4*j + i] = var(component.W(2*i), row + 1 + 3*j, false);
                        }
                    }

                    for(std::size_t i = 0; i < 4; i++) {
                        input_words_vars_2[i] = var(component.W(2*i), row + 1 + 12, false);
                    }

                    for (std::size_t i = 4; i < 15; i++) {
                        input_words_vars_2[i] =
                            var(component.C(0), start_row_index + 8, false, var::column_type::constant);
                    }
                    input_words_vars_2[15] =
                        var(component.C(0), start_row_index + 9, false, var::column_type::constant);


                    row = start_row_index + component.rows_amount_creating_input_words_component;

                    std::array<var, 8> constants_var = {
                        var(component.C(0), start_row_index, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 2, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 3, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 4, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 5, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 6, false, var::column_type::constant),
                        var(component.C(0), start_row_index + 7, false, var::column_type::constant)};

                    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                    typename sha512_process<ArithmetizationType>::input_type sha512_process_input = {constants_var, input_words_vars_1};

                    sha512_process<ArithmetizationType> sha512_process_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});

                    typename sha512_process<ArithmetizationType>::result_type sha_output = generate_assignments(sha512_process_instance, assignment, sha512_process_input, row);
                    row += sha512_process_instance.rows_amount;

                    //TODO

                    /*for (std::size_t i = 0; i < 8; i++) {
                        assignment.witness(i), row) = input_words_values[16 + i];
                        assignment.witness(i), row+1) = input_words_values[16 + i+8];
                        input_words_vars_2[i] = var(i, row, false);
                        input_words_vars_2[i+8] = var(i, row+1, false);
                    }*/

                    // row = row + 2;
                    sha512_process_input = {sha_output.output_state, input_words_vars_2};



                   /*std::array<typename BlueprintFieldType::value_type, 16> input_words2 = {
                        1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 9};
                    for (int i = 0; i < 16; i++) {
                        assignment.constant(0), component_start_row + 8 + i) = input_words2[i];
                    }
                    std::vector<var> input_words2_var = {var(0, row + 8, false, var::column_type::constant),
                                                         var(0, row + 9, false, var::column_type::constant),
                                                         var(0, row + 10, false, var::column_type::constant),
                                                         var(0, row + 11, false, var::column_type::constant),
                                                         var(0, row + 12, false, var::column_type::constant),
                                                         var(0, row + 13, false, var::column_type::constant),
                                                         var(0, row + 14, false, var::column_type::constant),
                                                         var(0, row + 15, false, var::column_type::constant),
                                                         var(0, row + 16, false, var::column_type::constant),
                                                         var(0, row + 17, false, var::column_type::constant),
                                                         var(0, row + 18, false, var::column_type::constant),
                                                         var(0, row + 19, false, var::column_type::constant),
                                                         var(0, row + 20, false, var::column_type::constant),
                                                         var(0, row + 21, false, var::column_type::constant),
                                                         var(0, row + 22, false, var::column_type::constant),
                                                         var(0, row + 23, false, var::column_type::constant)};
                    typename sha512_process_component::params_type sha_params2 = {sha_output.output_state,
                                                                                  input_words2_var}; */

                    sha_output = generate_assignments(sha512_process_instance, assignment, sha512_process_input, row);
                    row += sha512_process_instance.rows_amount;
                    return typename plonk_sha512<BlueprintFieldType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType>
            std::array<std::size_t, 5> generate_gates(
                    const plonk_sha512<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_sha512<BlueprintFieldType>::input_type
                        &instance_input) {

                    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                    using var = typename sha512<ArithmetizationType>::var;

                    typename BlueprintFieldType::integral_type one = 1;


                    auto constraint_ram_0 =
                        var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(1), 0) * (one << 22) + var(component.W(1), 1) * (one << 44) + var(component.W(0), 1) * (one << 64));
                    auto constraint_word_0 =
                        var(component.W(0),  0) - (var(component.W(1), -1) + var(component.W(1), 0) * (one << 22) + var(component.W(1), 1) * (one << 44));

                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 1234|567890123456789012.3456789012345678901234.5678901234567890123456

                    auto constraint_ram_1 =
                        var(component.W(2), -1) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << 22) + var(component.W(3), 1) * (one << 44) + var(component.W(2), 1) * (one << 62));
                    auto constraint_word_1 =
                        var(component.W(2), 0) - (var(component.W(0), 1) + var(component.W(3), -1) * (one << 2) + var(component.W(3), 0) * (one << 24) + var(component.W(3), 1) * (one << 46));

                    //  W4,1        W5,1                W5,0                  W5, -1
                    // 123456|7890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_2 =
                        var(component.W(4), -1) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44) + var(component.W(4), 1) * (one << 60));
                    auto constraint_word_2 =
                        var(component.W(4), 0) - (var(component.W(2), 1) + var(component.W(5), -1) * (one << 4) + var(component.W(5), 0) * (one << (4 + 22)) + var(component.W(5), 1) * (one << (4 + 44)));

                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567

                    auto constraint_ram_3 =
                        var(component.W(6), -1) - (var(component.W(7), -1) + var(component.W(7), 0) * (one << 22) + var(component.W(7), 1) * (one << 44));
                    auto constraint_word_3 =
                        var(component.W(6),  0) - (var(component.W(4), 1) + var(component.W(7), -1) * (one << 6) + var(component.W(7), 0) * (one << (6 + 22)) + var(component.W(7), 1) * (one << (6 + 44)) + var(component.W(6), 1) * (one << 63));

                    std::size_t selector_1 = bp.add_gate(
                        {constraint_ram_0, constraint_ram_1, constraint_ram_2, constraint_ram_3, constraint_word_0,
                         constraint_word_1, constraint_word_2, constraint_word_3});

                    // W0,1      W1,1                  W1,0               W1,-1             W8,-1
                    // 1|234567890123456789012.3456789012345678901234.567890123456789012345|6
                    auto constraint_ram_4 =
                        var(component.W(0), -1) - (var(component.W(8), -1) + var(component.W(1), -1) * (1 << 1) + var(component.W(1), 0) * (one << 22) + var(component.W(1), 1) * (one << 44) + var(component.W(0), 1) * (one << 65));
                    auto constraint_word_4 =
                        var(component.W(0), 0) - (var(component.W(1), -1) + var(component.W(1), 0) * (one << (22-1)) + var(component.W(1), 1) * (one << (22 + 22 - 1)));

                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 123|4567890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_5 =
                        var(component.W(2), -1) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << 22) + var(component.W(3), 1) * (one << 44) + var(component.W(2), 1) * (one << 63));
                    auto constraint_word_5 =
                        var(component.W(2), 0) - (var(component.W(0), 1) + var(component.W(3), -1) * (1 << 1) + var(component.W(3), 0) * (one << (22 + 1)) + var(component.W(3), 1) * (one << (44 + 1)));

                    //  W4,1        W5,1                W5,0                  W5, -1
                    // 12345|67890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_6 =
                        var(component.W(4), -1) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44) + var(component.W(4), 1) * (one << 61));
                    auto constraint_word_6 =
                        var(component.W(4), 0) - (var(component.W(2), 1) + var(component.W(5), -1) * (one << 3) + var(component.W(5), 0) * (one << (3 + 22)) + var(component.W(5), 1) * (one << (3 + 44)));

                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    auto constraint_ram_7 =
                        var(component.W(6), -1) - (var(component.W(7), -1) + var(component.W(7), 0) * (one << 22) + var(component.W(7), 1) * (one << 44));
                    auto constraint_word_7 =
                        var(component.W(6), 0) - (var(component.W(4), 1) + var(component.W(7), -1) * (one << 5) + var(component.W(7), 0) * (one << (5 + 22)) + var(component.W(7), 1) * (one << (5 + 44)) + var(component.W(6), 1) * (one << 62));

                    std::size_t selector_2 = bp.add_gate(
                        {constraint_ram_4, constraint_ram_5, constraint_ram_6, constraint_ram_7, constraint_word_4,
                         constraint_word_5, constraint_word_6, constraint_word_7});



                    //          W0,1                    W1,1                  W1,0        W1,-1
                    // |1234567890123456789012.3456789012345678901234.56789012345678901234|56
                    auto constraint_ram_8 =
                        var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(1), 0) * (1 << 2) + var(component.W(1), 1) * (one << 22) + var(component.W(0), 1) * (one << 44));
                    auto constraint_word_8 =
                        var(component.W(0), 0) - (var(component.W(1), 0) + var(component.W(1), 1) * (one << 20) + var(component.W(0), 1) * (one << 42));

                    // W2,1       W3,1                  W3,0                  W3, -1
                    // 12|34567890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_9 =
                        var(component.W(2), -1) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << 22) + var(component.W(3), 1) * (one << 44) + var(component.W(2), 1) * (one << 64));
                    auto constraint_word_9 =
                        var(component.W(2), 0) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << 22) + var(component.W(3), 1) * (one << 44));

                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 1234|567890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_10 =
                        var(component.W(4), -1) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44) + var(component.W(4), 1) * (one << 62));
                    auto constraint_word_10 =
                        var(component.W(4), 0) - (var(component.W(2), 1) + var(component.W(5), -1) * (one << 2) + var(component.W(5), 0) * (one << 24) + var(component.W(5), 1) * (one << 46));

                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    auto constraint_ram_11 =
                        var(component.W(6), -1) - (var(component.W(7), -1) + var(component.W(7), 0) * (one << 22) + var(component.W(7), 1) * (one << 44));
                    auto constraint_word_11 =
                        var(component.W(6), 0) - (var(component.W(4), 1) + var(component.W(7), -1) * (one << 4) + var(component.W(7), 0) * (one << (4 + 22)) + var(component.W(7), 1) * (one << (4 + 44)) + var(component.W(6), 1) * (one << 61));

                    std::size_t selector_3 = bp.add_gate(
                        {constraint_ram_8, constraint_ram_9, constraint_ram_10, constraint_ram_11,  constraint_word_8,
                         constraint_word_9, constraint_word_10, constraint_word_11});



                    //         W0,1                    W1,1                  W1,0        (W1,-1  &  W6,1-3)
                    // 1234567890123456789012.3456789012345678901234.5678901234567890123|456
                    auto constraint_ram_12 =
                        var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(1), 0) * (one << 3) + var(component.W(1), 1) * (one << 22) + var(component.W(0), 1) * (one << 44));
                    auto constraint_word_12 =
                        var(component.W(0), 0) - (var(component.W(1), 0) + var(component.W(1), 1) * (one << 19) + var(component.W(0), 1) * (one << (19+22)) + var(component.W(8), -1) * (one << 63));

                    // W2,1       W3,1                  W3,0                  W3, -1        W8, -1
                    // 1|234567890123456789012.3456789012345678901234.567890123456789012345|6
                    auto constraint_ram_13 =
                        var(component.W(2), -1) - (var(component.W(8), -1) + var(component.W(3), -1) * (1 << 1) + var(component.W(3), 0) * (one << 22) + var(component.W(3), 1) * (one << 44) + var(component.W(2), 1) * (one << 65));
                    auto constraint_word_13 =
                        var(component.W(2), 0) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << (22-1)) + var(component.W(3), 1) * (one << (22 + 22 - 1)));

                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 123|4567890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_14 =
                        var(component.W(4), -1) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44) + var(component.W(4), 1) * (one << 63));
                    auto constraint_word_14 =
                        var(component.W(4), 0) - (var(component.W(2), 1) + var(component.W(5), -1) * (1 << 1) + var(component.W(5), 0) * (one << (22 + 1)) + var(component.W(5), 1) * (one << (44 + 1)));

                    //     W7, 1              W7, 0                 W7, -1
                    // 1234567890123.4567890123456789012345.6789012345678901234567
                    auto constraint_ram_15 =
                        var(component.W(6), -1) - (var(component.W(7), -1) + var(component.W(7), 0) * (one << 22) + var(component.W(7), 1) * (one << 44));
                    auto constraint_word_15 =
                        var(component.W(6), 0) - (var(component.W(4), 1) + var(component.W(7), -1) * (one << 3) + var(component.W(7), 0) * (one << (3 + 22)) + var(component.W(7), 1) * (one << (3 + 44)) + var(component.W(6), 1) * (one << 60));

                    std::size_t selector_4 = bp.add_gate(
                        {constraint_ram_12, constraint_ram_13, constraint_ram_14, constraint_ram_15,
                         constraint_word_12, constraint_word_13, constraint_word_14, constraint_word_15});



                    //         W0,1                    W1,1                  W1,0        (W1,-1  &  W6,1-3)
                    // 1234567890123456789012.3456789012345678901234.567890123456789012|3456
                    auto constraint_ram_16 =
                        var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(1), 0) * (one << 4) + var(component.W(1), 1) * (one << 22) + var(component.W(0), 1) * (one << 44));
                    auto constraint_word_16 =
                        var(component.W(0), 0) - (var(component.W(1), 0) + var(component.W(1), 1) * (one << 18) + var(component.W(0), 1) * (one << (18+22)) + var(component.W(3), -1) * (one << 62));

                    //           W2,1                    W3,1                  W3,0      W3, -1
                    // |1234567890123456789012.3456789012345678901234.56789012345678901234|56
                    auto constraint_ram_17 =
                        var(component.W(2), -1) - (var(component.W(3), -1) + var(component.W(3), 0) * (one << 2) + var(component.W(3), 1) * (one << 22) + var(component.W(2), 1) * (one << 44));
                    auto constraint_word_17 =
                        var(component.W(2), 0) - (var(component.W(3), 0) + var(component.W(3), 1) * (one << 20) + var(component.W(2), 1) * (one << 42));

                    // W4,1        W5,1                 W5,0                  W5, -1
                    // 12|34567890123456789012.3456789012345678901234.5678901234567890123456
                    auto constraint_ram_18 =
                        var(component.W(4), -1) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44) + var(component.W(4), 1) * (one << 64));
                    auto constraint_word_18 =
                        var(component.W(4), 0) - (var(component.W(5), -1) + var(component.W(5), 0) * (one << 22) + var(component.W(5), 1) * (one << 44));

                    //     W7, 1              W7, 0                 W7, -1
                    // 12345678901234.5678901234567890123456.7890123456789012345678
                    auto constraint_ram_19 =
                        var(component.W(6), -1) - (var(component.W(7), -1) + var(component.W(7), 0) * (one << 22) + var(component.W(7), 1) * (one << 44));
                    auto constraint_word_19 =
                        var(component.W(6), 0) - (var(component.W(4), 1) + var(component.W(7), -1) * (one << 2) + var(component.W(7), 0) * (one << (2 + 22)) + var(component.W(7), 1) * (one << (2 + 44)) + var(component.W(8), 1) * (one << 60));

                    std::size_t selector_5 = bp.add_gate(
                        {constraint_ram_16, constraint_ram_17, constraint_ram_18, constraint_ram_19,
                         constraint_word_16, constraint_word_17, constraint_word_18, constraint_word_19});

                    return {selector_1, selector_2, selector_3, selector_4, selector_5};
                }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                    const plonk_sha512<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_sha512<BlueprintFieldType>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                    using var = typename sha512<ArithmetizationType>::var;

                    std::size_t row = start_row_index;

                    for(std::size_t i = 0; i < 4; i++) {
                        bp.add_copy_constraint ( { var(component.W(2*i), row +  0, false), instance_input.R.x[i] } );
                        bp.add_copy_constraint ( { var(component.W(2*i), row +  3, false), instance_input.R.y[i] } );
                        bp.add_copy_constraint ( { var(component.W(2*i), row +  6, false), instance_input.A.x[i] } );
                        bp.add_copy_constraint ( { var(component.W(2*i), row +  9, false), instance_input.A.y[i] } );
                        bp.add_copy_constraint ( { var(component.W(2*i), row + 12, false), instance_input.M[i] } );

                    }

                    bp.add_copy_constraint( { var(component.W(6), (row+4) - 3 + 1, false), var(component.W(8), (row+4) - 1, false) });
                    for(std::size_t i = 0; i < 3; i++){
                        std::size_t current_row = row + 1 + 6 + 3*i;
                        bp.add_copy_constraint( { var(component.W(6), (current_row - 3) + 1, false), var(component.W(1), current_row - 1, false) });
                    }

                }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_sha512<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_sha512<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::array<typename BlueprintFieldType::value_type, 8> constants = {
                    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
                };

                for (int i = 0; i < 8; i++) {
                    assignment.constant(component.C(0), start_row_index + i) = constants[i];
                }
                assignment.constant(component.C(0), start_row_index + 8) = 0;
                assignment.constant(component.C(0), start_row_index + 9) = 252 + 1024;
            }


            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType>
            class input_type_converter<plonk_sha512<BlueprintFieldType>> {

                using component_type = plonk_sha512<BlueprintFieldType>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_assignment) {

                    input_type new_input;
                    for (std::size_t i = 0; i < input.R.x.size(); i++) {
                        tmp_assignment.public_input(0, i) = var_value(assignment, input.R.x[i]);
                        new_input.R.x[i] = var(0, i, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.R.y.size(); i++) {
                        std::size_t new_index = input.R.x.size();
                        tmp_assignment.public_input(0, i + new_index) = var_value(assignment, input.R.y[i]);
                        new_input.R.y[i] = var(0, i + new_index, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.A.x.size(); i++) {
                        std::size_t new_index = input.R.x.size() + input.R.y.size();
                        tmp_assignment.public_input(0, i + new_index) = var_value(assignment, input.A.x[i]);
                        new_input.A.x[i] = var(0, i + new_index, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.A.y.size(); i++) {
                        std::size_t new_index = input.R.x.size() + input.R.y.size() + input.A.x.size();
                        tmp_assignment.public_input(0, i + new_index) = var_value(assignment, input.A.y[i]);
                        new_input.A.y[i] = var(0, i + new_index, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < 4; i++) {
                        std::size_t new_index = input.R.x.size() + input.R.y.size() +
                                                input.A.x.size() + input.A.y.size();
                        tmp_assignment.public_input(0, i + new_index) = var_value(assignment, input.M[i]);
                        new_input.M[i] = var(0, i + new_index, false, var::column_type::public_input);
                    }

                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    if (std::size_t(variable.rotation) < input.R.x.size()) {
                        return input.R.x[variable.rotation];
                    } else if (std::size_t(variable.rotation) < input.R.x.size() + input.R.y.size()) {
                        return input.R.y[variable.rotation - input.R.x.size()];
                    } else if (std::size_t(variable.rotation) < input.R.x.size() + input.R.y.size() + input.A.x.size()) {
                        return input.A.x[variable.rotation - input.R.x.size() - input.R.y.size()];
                    } else if (std::size_t(variable.rotation) < input.R.x.size() + input.R.y.size() +
                                                                input.A.x.size() + input.A.y.size()) {
                        return input.A.y[variable.rotation - input.R.x.size() - input.R.y.size() - input.A.x.size()];
                    } else {
                        return input.M[variable.rotation - input.R.x.size() - input.R.y.size()
                                                         - input.A.x.size() - input.A.y.size()];
                    }
                }
            };

            template<typename BlueprintFieldType>
            class result_type_converter<plonk_sha512<BlueprintFieldType>> {

                using component_type = plonk_sha512<BlueprintFieldType>;
                using result_type = typename component_type::result_type;
                using input_type = typename component_type::input_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    for (std::size_t i = 0; i < 8; i++) {
                        new_result.output_state[i] =
                            component.move_var(
                                old_result.output_state[i],
                                start_row_index + component.line_mapping[old_result.output_state[i].rotation],
                                instance_input);
                    }

                    return new_result;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA512_HPP