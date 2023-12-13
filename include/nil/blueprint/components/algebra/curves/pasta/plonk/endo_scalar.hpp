//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <sstream>
#include <string>

namespace nil {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType>
                class endo_scalar;
                // Input: x
                // Output: y
                // Such as:
                // mul(x, G) = endomul(y, G), for G \in E(F)

                template<typename CurveType>
                struct endo_scalar_params;

                template<>
                struct endo_scalar_params<nil::crypto3::algebra::curves::vesta> {
                    using curve_type = nil::crypto3::algebra::curves::vesta;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using base_field_type = typename curve_type::base_field_type;
                    constexpr static const typename scalar_field_type::value_type endo_r =
                        0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                    constexpr static const typename base_field_type::value_type endo_q =
                        0x2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547_cppui255;
                };

                template<>
                struct endo_scalar_params<nil::crypto3::algebra::curves::pallas> {
                    using curve_type = nil::crypto3::algebra::curves::pallas;
                    using scalar_field_type = typename curve_type::scalar_field_type;
                    using base_field_type = typename curve_type::base_field_type;
                    constexpr static const typename scalar_field_type::value_type endo_r =
                        0x397E65A7D7C1AD71AEE24B27E308F0A61259527EC1D4752E619D1840AF55F1B1_cppui255;
                    constexpr static const typename base_field_type::value_type endo_q =
                        0x2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547_cppui255;
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                class endo_scalar<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                    using endo_params = endo_scalar_params<CurveType>;

                public:
                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                    using var = typename component_type::var;
                    using manifest_type = nil::blueprint::plonk_component_manifest;

                    class gate_manifest_type : public component_gate_manifest {
                    public:
                        std::uint32_t gates_amount() const override {
                            return endo_scalar::gates_amount;
                        }
                    };

                    static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                            std::size_t lookup_column_amount) {
                        static gate_manifest manifest = gate_manifest(gate_manifest_type());
                        return manifest;
                    }

                    static manifest_type get_manifest() {
                        static manifest_type manifest = manifest_type(
                            std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                            false
                        );
                        return manifest;
                    }

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                 std::size_t lookup_column_amount) {
                        return 8;
                    }

                    const std::size_t scalar_size;

                    const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                    static constexpr std::size_t gates_amount = 2;

                    constexpr static const typename BlueprintFieldType::value_type endo_r = endo_params::endo_r;
                    constexpr static const typename CurveType::base_field_type::value_type endo_q = endo_params::endo_q;

                    struct input_type {
                        var scalar;

                        std::vector<std::reference_wrapper<var>> all_vars() {
                            return {scalar};
                        }
                    };

                    struct result_type {
                        var output = var(0, 0, false);
                        result_type(const endo_scalar &component, const input_type &params, std::size_t start_row_index) {
                            output = var(component.W(6), start_row_index + component.rows_amount - 1,
                                         false, var::column_type::witness);
                        }

                        std::vector<var> all_vars() const {
                            return {output};
                        }
                    };

                    template <typename ContainerType>
                        endo_scalar(ContainerType witness, std::size_t scalar_size_):
                            component_type(witness, {}, {}, get_manifest()),
                            scalar_size(scalar_size_) {};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                        endo_scalar(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input, std::size_t scalar_size_):
                            component_type(witness, constant, public_input, get_manifest()),
                            scalar_size(scalar_size_) {};

                    endo_scalar(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        std::size_t scalar_size_):
                            component_type(witnesses, constants, public_inputs, get_manifest()),
                            scalar_size(scalar_size_) {};

                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                using plonk_endo_scalar =
                    endo_scalar<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        CurveType
                    >;

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                        generate_circuit(
                        const plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        std::array<std::size_t, 2> selector_indices =
                            generate_gates(component, bp, assignment, instance_input);

                        std::size_t j = start_row_index;
                        assignment.enable_selector(selector_indices[0], j, j + component.rows_amount - 1);
                        assignment.enable_selector(selector_indices[1], j + component.rows_amount - 1);

                        generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                        return typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, instance_input, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                        generate_assignments(
                        const plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        std::size_t row = start_row_index;

                        const std::size_t crumbs_per_row = 8;
                        const std::size_t bits_per_crumb = 2;
                        const std::size_t bits_per_row =
                            bits_per_crumb * crumbs_per_row;    // we suppose that scalar_size % bits_per_row = 0

                        typename BlueprintFieldType::value_type scalar = var_value(assignment, instance_input.scalar);
                        typename BlueprintFieldType::integral_type integral_scalar =
                            typename BlueprintFieldType::integral_type(scalar.data);
                        std::vector<bool> bits_msb(component.scalar_size);
                        {
                            nil::marshalling::status_type status;
                            assert(component.scalar_size <= BlueprintFieldType::modulus_bits);

                            std::array<bool, BlueprintFieldType::modulus_bits> bits_msb_all =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_scalar, status);

                            assert(status == nil::marshalling::status_type::success);

                            std::copy(bits_msb_all.end() - component.scalar_size, bits_msb_all.end(), bits_msb.begin());

                            for(std::size_t i = 0; i < BlueprintFieldType::modulus_bits - component.scalar_size; ++i) {
                                assert(bits_msb_all[i] == false);
                            }
                        }
                        typename BlueprintFieldType::value_type a = 2;
                        typename BlueprintFieldType::value_type b = 2;
                        typename BlueprintFieldType::value_type n = 0;

                        assert (component.scalar_size % bits_per_row == 0);
                        for (std::size_t chunk_start = 0; chunk_start < bits_msb.size(); chunk_start += bits_per_row) {
                            assignment.witness(component.W(0), row) = n;
                            assignment.witness(component.W(2), row) = a;
                            assignment.witness(component.W(3), row) = b;

                            for (std::size_t j = 0; j < crumbs_per_row; j++) {
                                std::size_t crumb = chunk_start + j * bits_per_crumb;
                                typename BlueprintFieldType::value_type b0 = static_cast<int>(bits_msb[crumb + 1]);
                                typename BlueprintFieldType::value_type b1 = static_cast<int>(bits_msb[crumb + 0]);

                                typename BlueprintFieldType::value_type crumb_value = b0 + b1.doubled();
                                assignment.witness(component.W(7 + j), row) = crumb_value;

                                a = a.doubled();
                                b = b.doubled();

                                typename BlueprintFieldType::value_type s =
                                    (b0 == BlueprintFieldType::value_type::one()) ? 1 : -1;

                                if (b1 == BlueprintFieldType::value_type::zero()) {
                                    b += s;
                                } else {
                                    a += s;
                                }

                                n = (n.doubled()).doubled();
                                n += crumb_value;
                            }

                            assignment.witness(component.W(1), row) = n;
                            assignment.witness(component.W(4), row) = a;
                            assignment.witness(component.W(5), row) = b;
                            row++;
                        }
                        auto res = a * component.endo_r + b;
                        assignment.witness(component.W(6), row - 1) = res;
                        return typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, instance_input, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    std::array<std::size_t, 2> generate_gates(
                        const plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input) {

                        using F = typename BlueprintFieldType::value_type;
                        using var =
                            typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

                        auto c_f = [](var x) {
                            return (F(11) * F(6).inversed()) * x + (-F(5) * F(2).inversed()) * x * x +
                                   (F(2) * F(3).inversed()) * x * x * x;
                        };

                        auto d_f = [](var x) {
                            return -F::one() + (F(29) * F(6).inversed()) * x + (-F(7) * F(2).inversed()) * x * x +
                                   (F(2) * F(3).inversed()) * x * x * x;
                        };

                        auto constraint_1 =
                            var(component.W(7), 0) * (var(component.W(7), 0) - 1) *
                            (var(component.W(7), 0) - 2) * (var(component.W(7), 0) - 3);
                        auto constraint_2 =
                            var(component.W(8), 0) *
                            (var(component.W(8), 0) - 1) * (var(component.W(8), 0) - 2) * (var(component.W(8), 0) - 3);
                        auto constraint_3 =
                            var(component.W(9), 0) * (var(component.W(9), 0) - 1) *
                            (var(component.W(9), 0) - 2) * (var(component.W(9), 0) - 3);
                        auto constraint_4 =
                            var(component.W(10), 0) * (var(component.W(10), 0) - 1) *
                            (var(component.W(10), 0) - 2) * (var(component.W(10), 0) - 3);
                        auto constraint_5 =
                            var(component.W(11), 0) * (var(component.W(11), 0) - 1) *
                            (var(component.W(11), 0) - 2) * (var(component.W(11), 0) - 3);
                        auto constraint_6 =
                            var(component.W(12), 0) * (var(component.W(12), 0) - 1) *
                            (var(component.W(12), 0) - 2) * (var(component.W(12), 0) - 3);
                        auto constraint_7 =
                            var(component.W(13), 0) * (var(component.W(13), 0) - 1) *
                            (var(component.W(13), 0) - 2) * (var(component.W(13), 0) - 3);
                        auto constraint_8 =
                            var(component.W(14), 0) * (var(component.W(14), 0) - 1) *
                            (var(component.W(14), 0) - 2) * (var(component.W(14), 0) - 3);
                        auto constraint_9 =
                            var(component.W(4), 0) - (256 * var(component.W(2), 0) + 128 * c_f(var(component.W(7), 0)) + 64 * c_f(var(component.W(8), 0)) +
                                          32 * c_f(var(component.W(9), 0)) + 16 * c_f(var(component.W(10), 0)) + 8 * c_f(var(component.W(11), 0)) +
                                          4 * c_f(var(component.W(12), 0)) + 2 * c_f(var(component.W(13), 0)) + c_f(var(component.W(14), 0)));
                        auto constraint_10 =
                            var(component.W(5), 0) - (256 * var(component.W(3), 0) + 128 * d_f(var(component.W(7), 0)) + 64 * d_f(var(component.W(8), 0)) +
                                          32 * d_f(var(component.W(9), 0)) + 16 * d_f(var(component.W(10), 0)) + 8 * d_f(var(component.W(11), 0)) +
                                          4 * d_f(var(component.W(12), 0)) + 2 * d_f(var(component.W(13), 0)) + d_f(var(component.W(14), 0)));
                        auto constraint_11 =
                            var(component.W(1), 0) - ((1 << 16) * var(component.W(0), 0) + (1 << 14) * var(component.W(7), 0) + (1 << 12) * var(component.W(8), 0) +
                                          (1 << 10) * var(component.W(9), 0) + (1 << 8) * var(component.W(10), 0) + (1 << 6) * var(component.W(11), 0) +
                                          (1 << 4) * var(component.W(12), 0) + (1 << 2) * var(component.W(13), 0) + var(component.W(14), 0));

                        auto constraint_12 = var(component.W(6), 0) -
                            (component.endo_r * var(component.W(4), 0) + var(component.W(5), 0));

                        std::size_t selector_index_1 = bp.add_gate(
                            {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                             constraint_7, constraint_8, constraint_9, constraint_10, constraint_11});

                        std::size_t selector_index_2 = bp.add_gate({constraint_12});

                        return {selector_index_1, selector_index_2};
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                        void generate_copy_constraints(
                        const plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_endo_scalar<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        std::size_t j = start_row_index;

                        for (std::size_t z = 1; z < component.rows_amount; z++) {
                            bp.add_copy_constraint(
                                {{component.W(0), static_cast<int>(j + z), false}, {component.W(1), static_cast<int>(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{component.W(2), static_cast<int>(j + z), false}, {component.W(4), static_cast<int>(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{component.W(3), static_cast<int>(j + z), false}, {component.W(5), static_cast<int>(j + z - 1), false}});
                        }

                        // check that the recalculated n is equal to the input challenge
                        bp.add_copy_constraint({{component.W(1), static_cast<int>(j + component.rows_amount - 1), false}, instance_input.scalar});
                    }
            }    // namespace components
        }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP
