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
// @file Declaration of interfaces for auxiliary components for the DECOMPOSITION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_DECOMPOSITION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_DECOMPOSITION_EDWARD25519_HPP

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class reduction;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class reduction<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType,
                            basic_non_native_policy<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                using operating_field_type = crypto3::algebra::fields::curve25519_scalar_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return reduction::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 4;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                static const std::size_t gates_amount = 2;

                struct input_type {
                    std::array<var, 8> k;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]};
                    }
                };

                struct result_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type output;

                    result_type(const reduction &component, std::uint32_t start_row_index) {
                        output = var(component.W(4), start_row_index + component.rows_amount - 3, false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit reduction(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                reduction(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                reduction(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                          std::initializer_list<typename component_type::constant_container_type::value_type>
                              constants,
                          std::initializer_list<typename component_type::public_input_container_type::value_type>
                              public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_reduction =
                reduction<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType,
                          basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_reduction<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                std::size_t row = start_row_index;
                std::array<typename ArithmetizationType::field_type::integral_type, 8> data = {
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[0]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[1]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[2]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[3]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[4]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[5]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[6]).data),
                    typename ArithmetizationType::field_type::integral_type(
                        var_value(assignment, instance_input.k[7]).data)};

                auto L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui512;
                auto k = 0x00_cppui512;
                auto shft = 0x01_cppui512;

                for (std::size_t i = 0; i < 8; i++) {
                    assignment.witness(component.W(i), row + 3) = data[i];
                    k = k + data[i] * (shft % L);
                    shft = shft * 0x10000000000000000_cppui255;
                }

                auto r = k % L;
                auto q = (k / L);

                assignment.witness(component.W(3), row + 2) = q & 127;
                assignment.witness(component.W(2), row + 2) = (q >> 7) & ((1 << (20)) - 1);
                assignment.witness(component.W(1), row + 2) = (q >> 27) & ((1 << (20)) - 1);
                assignment.witness(component.W(0), row + 2) = (q >> 47) & ((1 << (20)) - 1);
                assignment.witness(component.W(4), row + 1) = r;

                assignment.witness(component.W(3), row + 1) =
                    typename ArithmetizationType::field_type::value_type((r) & ((1 << (13)) - 1));
                assignment.witness(component.W(2), row + 1) =
                    typename ArithmetizationType::field_type::value_type((r >> 13) & ((1 << (20)) - 1));
                assignment.witness(component.W(1), row + 1) =
                    typename ArithmetizationType::field_type::value_type((r >> 33) & ((1 << (20)) - 1));
                assignment.witness(component.W(0), row + 1) =
                    typename ArithmetizationType::field_type::value_type((r >> 53) & ((1 << (20)) - 1));
                assignment.witness(component.W(8), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 73) & ((1 << (20)) - 1));
                assignment.witness(component.W(7), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 93) & ((1 << (20)) - 1));
                assignment.witness(component.W(6), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 113) & ((1 << (20)) - 1));
                assignment.witness(component.W(5), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 133) & ((1 << (20)) - 1));
                assignment.witness(component.W(4), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 153) & ((1 << (20)) - 1));
                assignment.witness(component.W(3), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 173) & ((1 << (20)) - 1));
                assignment.witness(component.W(2), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 193) & ((1 << (20)) - 1));
                assignment.witness(component.W(1), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 213) & ((1 << (20)) - 1));
                assignment.witness(component.W(0), row) =
                    typename ArithmetizationType::field_type::value_type((r >> 233));

                typename ArithmetizationType::field_type::value_type s_r = assignment.witness(component.W(0), row);
                for (size_t i = 1; i < 9; i++) {
                    s_r += assignment.witness(component.W(i), row);
                }
                s_r += assignment.witness(component.W(0), row + 1) + assignment.witness(component.W(1), row + 1) +
                       assignment.witness(component.W(2), row + 1);
                s_r -= 12 * ((1 << (20)) - 1);
                crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type one = 1;
                assignment.witness(component.W(5), row + 1) = s_r.inversed();

                // if ((r) & ((1 << (13)) - 1) (L - (one << 252))) { \\TO-DO
                assignment.witness(component.W(6), row + 1) = 1;
                //} else {
                //}

                auto c = data[0] + data[1] * ((one << 64)) + data[3] * (((one << 192) % L) & ((one << 73) - 1)) +
                         data[4] * (((one << 256) % L) & ((one << 73) - 1)) +
                         data[5] * (((one << 320) % L) & ((one << 73) - 1)) +
                         data[6] * (((one << 384) % L) & ((one << 73) - 1)) +
                         data[7] * (((one << 448) % L) & ((one << 73) - 1)) + q * ((one << 73) - (L % (one << 73)));
                auto d = (r) & ((1 << (13)) - 1) + ((r >> 13) & ((1 << (20)) - 1)) * (one << 13) +
                                   ((r >> 33) & ((1 << (20)) - 1)) * (one << 33) +
                                   ((r >> 53) & ((1 << (20)) - 1)) * (one << 53);
                auto v = (c - d) >> 69;

                assignment.witness(component.W(8), row + 3) = v;
                assignment.witness(component.W(4), row + 2) = v >> 56;
                assignment.witness(component.W(5), row + 2) = (v >> 34) & ((1 << (22)) - 1);
                assignment.witness(component.W(6), row + 2) = (v >> 12) & ((1 << (22)) - 1);
                assignment.witness(component.W(7), row + 2) = v & 4095;

                return typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::array<std::size_t, 2> generate_gates(
                const plonk_reduction<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::var;

                auto L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui512;

                auto constraint_1 =
                    var(component.W(0), +1) * 0x01_cppui512 + var(component.W(1), +1) * 0x10000000000000000_cppui512 +
                    var(component.W(2), +1) * 0x100000000000000000000000000000000_cppui512 +
                    var(component.W(3), +1) * 0x1000000000000000000000000000000000000000000000000_cppui512 +
                    var(component.W(4), +1) *
                        0xffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d_cppui512 +
                    var(component.W(5), +1) *
                        0xffffffffffffffeb2106215d086329a93b8c838d39a5e065812631a5cf5d3ed_cppui512 +
                    var(component.W(6), +1) *
                        0x2106215d086329a7ed9ce5a30a2c131b64a7f435e4fdd9539822129a02a6271_cppui512 +
                    var(component.W(7), +1) *
                        0xed9ce5a30a2c131b399411b7c309a3de24babbe38d1d7a979daf520a00acb65_cppui512 -
                    var(component.W(4), -1) -
                    (var(component.W(0), 0) * 0x800000000000_cppui512 + var(component.W(1), 0) * 0x8000000_cppui512 +
                     var(component.W(2), 0) * 0x80_cppui512 + var(component.W(3), 0)) *
                        L;

                auto s_r = var(component.W(0), -1) + var(component.W(1), -1) + var(component.W(2), -1) +
                           var(component.W(3), -1) + var(component.W(4), -1) + var(component.W(5), -1) +
                           var(component.W(6), -1) + var(component.W(7), -1) + var(component.W(8), -1) +
                           var(component.W(0), 0) + var(component.W(1), 0) + var(component.W(2), 0) -
                           12 * ((1 << (20)) - 1);

                auto constraint_2 =
                    var(component.W(4), 0) -
                    (var(component.W(3), 0) + var(component.W(2), 0) * 0x2000_cppui255 +
                     var(component.W(1), 0) * 0x200000000_cppui255 +
                     var(component.W(0), 0) * 0x20000000000000_cppui255 +
                     var(component.W(8), -1) * 0x2000000000000000000_cppui255 +
                     var(component.W(7), -1) * 0x200000000000000000000000_cppui255 +
                     var(component.W(6), -1) * 0x20000000000000000000000000000_cppui255 +
                     var(component.W(5), -1) * 0x2000000000000000000000000000000000_cppui255 +
                     var(component.W(4), -1) * 0x200000000000000000000000000000000000000_cppui255 +
                     var(component.W(3), -1) * 0x20000000000000000000000000000000000000000000_cppui255 +
                     var(component.W(2), -1) * 0x2000000000000000000000000000000000000000000000000_cppui255 +
                     var(component.W(1), -1) * 0x200000000000000000000000000000000000000000000000000000_cppui255 +
                     var(component.W(0), -1) * 0x20000000000000000000000000000000000000000000000000000000000_cppui255);

                auto constraint_3 = (s_r) * ((s_r)*var(component.W(5), 0) - 1);

                auto constraint_4 =
                    (s_r) * var(component.W(5), 0) +
                    (1 - (s_r)*var(component.W(5), 0)) * var(component.W(6), 0) - 1;
                crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type one = 1;
                std::array<crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type, 5> m = {
                    ((one << 192) % L), ((one << 256) % L), ((one << 320) % L), ((one << 384) % L), ((one << 448) % L)};
                auto constraint_5 =
                    var(component.W(0), +1) + var(component.W(1), +1) * (one << 64) +
                    var(component.W(3), +1) * (m[0] & ((one << 73) - 1)) +
                    var(component.W(4), +1) * (m[1] & ((one << 73) - 1)) +
                    var(component.W(5), +1) * (m[2] & ((one << 73) - 1)) +
                    var(component.W(6), +1) * (m[3] & ((one << 73) - 1)) +
                    var(component.W(7), +1) * (m[4] & ((one << 73) - 1)) +
                    (var(component.W(0), 0) * 0x800000000000_cppui512 + var(component.W(1), 0) * 0x8000000_cppui512 +
                     var(component.W(2), 0) * 0x80_cppui512 + var(component.W(3), 0)) *
                        ((one << 73) - (L % (one << 73))) -
                    (var(component.W(3), -1) + var(component.W(2), -1) * (one << 13) +
                     var(component.W(1), -1) * (one << 33) + var(component.W(0), -1) * (one << 53)) -
                    var(component.W(8), +1) * (one << 69);

                auto constraint_6 =
                    var(component.W(8), +1) -
                    (var(component.W(4), 0) * (one << 56) + var(component.W(5), 0) * (one << 34) +
                     var(component.W(6), 0) * (one << 12) + var(component.W(7), 0));

                std::size_t selector_index_1 = bp.add_gate({constraint_2, constraint_3, constraint_4});

                std::size_t selector_index_2 = bp.add_gate({constraint_1, constraint_5, constraint_6});

                return {selector_index_1, selector_index_2};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_reduction<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;

                bp.add_copy_constraint({var(component.W(0), row + 3, false), instance_input.k[0]});
                bp.add_copy_constraint({var(component.W(1), row + 3, false), instance_input.k[1]});
                bp.add_copy_constraint({var(component.W(2), row + 3, false), instance_input.k[2]});
                bp.add_copy_constraint({var(component.W(3), row + 3, false), instance_input.k[3]});
                bp.add_copy_constraint({var(component.W(4), row + 3, false), instance_input.k[4]});
                bp.add_copy_constraint({var(component.W(5), row + 3, false), instance_input.k[5]});
                bp.add_copy_constraint({var(component.W(6), row + 3, false), instance_input.k[6]});
                bp.add_copy_constraint({var(component.W(7), row + 3, false), instance_input.k[7]});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_reduction<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::array<std::size_t, 2> selector_indices = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_indices[0], start_row_index + 1);
                assignment.enable_selector(selector_indices[1], start_row_index + 2);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_reduction<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_REDUCTION_HPP