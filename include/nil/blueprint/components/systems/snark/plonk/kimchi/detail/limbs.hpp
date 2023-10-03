//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP

#include <vector>
#include <array>
#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            ///////////////// From Limbs ////////////////////////////////
            // Recalculate field element from two 64-bit chunks
            // It's a part of transcript functionality
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L87
            // Input: x1 = [a_0, ..., a_63], x2 = [b_0, ..., b_63]
            // Output: y = [a_0, ...., a_63, b_0, ..., b_63]
            template<typename ArithmetizationType>
            class from_limbs;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class from_limbs<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;
                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return from_limbs::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                        std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                std::size_t lookup_column_amount) {
                    return 1;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                static constexpr const std::size_t gates_amount = 1;

                struct input_type {
                    var first_limb = var(0, 0, false);
                    var second_limb = var(0, 0, false);
                    input_type(std::array<var, 2> input) : first_limb(input[0]), second_limb(input[1]) {
                    }
                    input_type(var first, var second) : first_limb(first), second_limb(second) {
                    }

                    std::vector<var> all_vars() const {
                        return {first_limb, second_limb};
                    }
                };

                struct result_type {
                    var result = var(0, 0);

                    result_type(const from_limbs &component, std::size_t start_row_index) {
                        result = var(component.W(2), static_cast<int>(start_row_index), false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {result};
                    }
                };

                template <typename ContainerType>
                    from_limbs(ContainerType witness):
                        component_type(witness, {}, {}, get_manifest()){};

                template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                    from_limbs(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                        component_type(witness, constant, public_input, get_manifest()){};

                from_limbs(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs, get_manifest()){};

            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_from_limbs = from_limbs<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                typename BlueprintFieldType::value_type first_limb =  var_value(assignment, instance_input.first_limb);
                typename BlueprintFieldType::value_type second_limb = var_value(assignment, instance_input.second_limb);
                assignment.witness(component.W(0), row) = first_limb;
                assignment.witness(component.W(1), row) = second_limb;
                typename BlueprintFieldType::value_type scalar = 2;
                scalar = scalar.pow(64) * second_limb + first_limb;
                assignment.witness(component.W(2), row) = scalar;

                return typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                typename BlueprintFieldType::value_type scalar = 2;
                auto constraint_1 =
                    var(component.W(0), 0) + var(component.W(1), 0) * scalar.pow(64) - var(component.W(2), 0);

                return bp.add_gate({constraint_1});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_copy_constraints(
                const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                bp.add_copy_constraint(
                    {{component.W(0), static_cast<int>(start_row_index), false},
                        {instance_input.first_limb.index, instance_input.first_limb.rotation, false, instance_input.first_limb.type}});
                bp.add_copy_constraint(
                    {{component.W(1), static_cast<int>(start_row_index), false},
                        {instance_input.second_limb.index, instance_input.second_limb.rotation, false, instance_input.second_limb.type}});
            }

            /////////////// To Limbs ////////////////////////////////
            // Split field element into four 64-bit chunks
            // It's a part of transcript functionality
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L110
            // Input: x = [a_0, ...., a255]
            // Output: y0 = [a_0, ..., a_63], y1 = [a_64, ..., a_127], y2 = [a_128, ..., a_191], y3 = [a_192, ...,
            // a_255]
            template<typename ArithmetizationType>
            class to_limbs;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class to_limbs<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {


                constexpr static const std::size_t chunk_size = 64;
                using range_check_component = nil::blueprint::components::range_check<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;
                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return to_limbs::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                        std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(range_check_component::get_gate_manifest(witness_amount,
                                                                                lookup_column_amount,
                                                                                chunk_size));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        false
                    ).merge_with(range_check_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1 + 2 * chunk_amount *
                                range_check_component::get_rows_amount(witness_amount, lookup_column_amount,
                                                                       chunk_size);
                }

                constexpr static const std::size_t chunk_size_public = chunk_size;
                constexpr static const std::size_t chunk_amount = 4;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    var param;

                    input_type(var value) : param(value) {
                    }

                    std::vector<var> all_vars() const {
                        return {param};
                    }
                };

                struct result_type {
                    std::array<var, 4> result;

                    result_type(const to_limbs &component, std::size_t start_row_index) {
                        result = {var(component.W(1), static_cast<int>(start_row_index), false, var::column_type::witness),
                                    var(component.W(2), static_cast<int>(start_row_index), false, var::column_type::witness),
                                    var(component.W(3), static_cast<int>(start_row_index), false, var::column_type::witness),
                                    var(component.W(4), static_cast<int>(start_row_index), false, var::column_type::witness)};
                    }

                    std::vector<var> all_vars() const {
                        return {result[0], result[1], result[2], result[3]};
                    }
                };

                template <typename ContainerType>
                    to_limbs(ContainerType witness):
                        component_type(witness, {}, {}, get_manifest()){};

                template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                    to_limbs(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                        component_type(witness, constant, public_input, get_manifest()){};

                to_limbs(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs, get_manifest()){};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_to_limbs = to_limbs<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>;
                range_check<ArithmetizationType> range_check_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{},component_type::chunk_size_public);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                std::size_t row = start_row_index;
                std::array<var, component_type::chunk_amount> chunks = {
                    var(component.W(1), row, false),
                    var(component.W(2), row, false),
                    var(component.W(3), row, false),
                    var(component.W(4), row, false)
                };
                std::array<var, component_type::chunk_amount> b_chunks_vars = {
                    var(component.W(5), row, false),
                    var(component.W(6), row, false),
                    var(component.W(7), row, false),
                    var(component.W(8), row, false)
                };

                row++;

                for (std::size_t i = 0; i < component_type::chunk_amount; i++) {
                    generate_circuit(range_check_instance, bp, assignment, {chunks[i]}, row);
                    row += range_check_instance.rows_amount;
                    generate_circuit(range_check_instance, bp, assignment, {b_chunks_vars[i]}, row);
                    row += range_check_instance.rows_amount;
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);

            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_assignments(
                const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>;
                range_check<ArithmetizationType> range_check_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{},component_type::chunk_size_public);

                std::size_t row = start_row_index;
                typename BlueprintFieldType::value_type value = var_value(assignment, instance_input.param);
                auto value_data = value.data;
                auto shifted_data = value_data >> 64 << 64;
                assignment.witness(component.W(0), row) = value_data;
                assignment.witness(component.W(1), row) = value_data - shifted_data;
                value_data = value_data >> 64;
                shifted_data = shifted_data >> 64 >> 64 << 64;
                assignment.witness(component.W(2), row) = value_data - shifted_data;
                value_data = value_data >> 64;
                shifted_data = shifted_data >> 64 >> 64 << 64;
                assignment.witness(component.W(3), row) = value_data - shifted_data;
                value_data = value_data >> 64;
                assignment.witness(component.W(4), row) = value_data;

                typename BlueprintFieldType::extended_integral_type modulus_p = BlueprintFieldType::modulus;
                typename BlueprintFieldType::extended_integral_type one = 1;
                typename BlueprintFieldType::extended_integral_type power = (one << 256);
                typename BlueprintFieldType::extended_integral_type c = power - modulus_p;
                typename BlueprintFieldType::extended_integral_type mask = (one << 64) - 1;
                std::array<typename BlueprintFieldType::extended_integral_type, 4> c_chunks = {
                    c & mask, (c >> 64) & mask, (c >> 128) & mask, (c >> 192) & mask};

                typename BlueprintFieldType::extended_integral_type b =
                    typename BlueprintFieldType::extended_integral_type(value.data) + c;
                std::array<typename BlueprintFieldType::extended_integral_type, 4> b_chunks = {
                    b & mask, (b >> 64) & mask, (b >> 128) & mask, (b >> 192) & mask};
                assignment.witness(component.W(5), row) = b_chunks[0];
                assignment.witness(component.W(6), row) = b_chunks[1];
                assignment.witness(component.W(7), row) = b_chunks[2];
                assignment.witness(component.W(8), row) = b_chunks[3];
                assignment.witness(component.W(9), row) =
                    (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(1), row).data) +
                        c_chunks[0] - b_chunks[0]) >>
                    64;
                assignment.witness(component.W(10), row) =
                    (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(2), row).data) +
                        c_chunks[1] - b_chunks[1] +
                        typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(9), row).data)) >>
                    64;
                assignment.witness(component.W(11), row) =
                    (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(3), row).data) +
                        c_chunks[2] - b_chunks[2] +
                        typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(10), row).data)) >>
                    64;
                std::array<var, component_type::chunk_amount> chunks = {
                    var(component.W(1), row, false),
                    var(component.W(2), row, false),
                    var(component.W(3), row, false),
                    var(component.W(4), row, false)};

                std::array<var, component_type::chunk_amount> b_chunks_vars = {
                    var(component.W(5), row, false),
                    var(component.W(6), row, false),
                    var(component.W(7), row, false),
                    var(component.W(8), row, false)};

                row++;

                for (std::size_t i = 0; i < component_type::chunk_amount; i++) {
                    generate_assignments(range_check_instance, assignment, {chunks[i]}, row);
                    row += range_check_instance.rows_amount;
                    generate_assignments(range_check_instance, assignment, {b_chunks_vars[i]}, row);
                    row += range_check_instance.rows_amount;
                }

                return typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                typename BlueprintFieldType::value_type scalar = 2;
                typename BlueprintFieldType::extended_integral_type modulus_p = BlueprintFieldType::modulus;
                typename BlueprintFieldType::extended_integral_type one = 1;
                typename BlueprintFieldType::extended_integral_type power = (one << 256);
                typename BlueprintFieldType::extended_integral_type c = power - modulus_p;
                typename BlueprintFieldType::extended_integral_type mask = (one << 64) - 1;
                std::array<typename BlueprintFieldType::extended_integral_type, 4> c_chunks = {
                    c & mask, (c >> 64) & mask, (c >> 128) & mask, (c >> 192) & mask};
                auto constraint_1 =
                    var(component.W(1), 0) + var(component.W(2), 0) * scalar.pow(64) +
                    var(component.W(3), 0) * scalar.pow(128) + var(component.W(4), 0) * scalar.pow(192) -
                    var(component.W(0), 0);
                auto constraint_2 =
                    -var(component.W(1), 0) - typename BlueprintFieldType::value_type(c_chunks[0]) +
                    var(component.W(5), 0) + var(component.W(9), 0) * (one << 64);
                auto constraint_3 =
                    -var(component.W(2), 0) - typename BlueprintFieldType::value_type(c_chunks[1]) -
                    var(component.W(9), 0) + var(component.W(6), 0) + var(component.W(10), 0) * (one << 64);
                auto constraint_4 =
                    -var(component.W(3), 0) - typename BlueprintFieldType::value_type(c_chunks[2]) -
                    var(component.W(10), 0) + var(component.W(7), 0) + var(component.W(11), 0) * (one << 64);
                auto constraint_5 =
                    -var(component.W(4), 0) - typename BlueprintFieldType::value_type(c_chunks[3]) -
                    var(component.W(11), 0) + var(component.W(8), 0);

                auto constraint_6 = var(component.W(9), 0) * (var(component.W(9), 0) - 1);
                auto constraint_7 = var(component.W(10), 0) * (var(component.W(10), 0) - 1);
                auto constraint_8 = var(component.W(11), 0) * (var(component.W(11), 0) - 1);

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                    constraint_7, constraint_8});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                bp.add_copy_constraint({{component.W(0), static_cast<int>(start_row_index), false},
                                        {instance_input.param.index, instance_input.param.rotation, false, instance_input.param.type}});
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class input_type_converter<plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &tmp_assignment) {

                    input_type new_input(var(0, 0, false, var::column_type::public_input));
                    tmp_assignment.public_input(0, 0) = var_value(assignment, input.param);
                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    return input.param;
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class result_type_converter<plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>;
                using input_type = typename component_type::input_type;
                using result_type = typename component_type::result_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, ArithmetizationParams, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    for (std::size_t i = 0; i < 4; i++) {
                        new_result.result[i] = component.move_var(
                            old_result.result[i],
                            start_row_index + component.line_mapping[old_result.result[i].rotation],
                            instance_input
                        );
                    }

                    return new_result;
                }
            };
        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP
