//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_COMPLETE_ADDITION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_COMPLETE_ADDITION_EDWARD25519_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/subtraction.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                     typename NonNativePolicyType>
            class complete_addition;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            class complete_addition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    Ed25519Type,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                constexpr static std::size_t rows_amount_internal(std::size_t witness_amount) {
                    return
                        2 * non_native_range_component::get_rows_amount(witness_amount, 0) +
                        8 * multiplication_component::get_rows_amount(witness_amount, 0) +
                        3 * addition_component::get_rows_amount(witness_amount, 0) +
                        subtraction_component::get_rows_amount(witness_amount, 0);
                }
            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = typename component_type::manifest_type;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return complete_addition::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(
                            non_native_range_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(multiplication_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(subtraction_component::get_gate_manifest(witness_amount, lookup_column_amount));

                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        true
                    ).merge_with(multiplication_component::get_manifest())
                     .merge_with(addition_component::get_manifest())
                     .merge_with(subtraction_component::get_manifest())
                     .merge_with(non_native_range_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return rows_amount_internal(witness_amount);
                }

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using non_native_range_component = components::range<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using multiplication_component = multiplication<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using addition_component = addition<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using subtraction_component = subtraction<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount());

                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var_ec_point R;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {T.x[0], T.x[1], T.x[2], T.x[3], T.y[0], T.y[1], T.y[2], T.y[3],
                                R.x[0], R.x[1], R.x[2], R.x[3], R.y[0], R.y[1], R.y[2], R.y[3]};
                    }
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const complete_addition &component, std::uint32_t start_row_index) {
                        output.x = {var(component.W(0), start_row_index, false),
                                    var(component.W(1), start_row_index, false),
                                    var(component.W(2), start_row_index, false),
                                    var(component.W(3), start_row_index, false)};
                        std::size_t non_native_range_component_rows_amount =
                            non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                        output.y = {
                            var(component.W(0), start_row_index + non_native_range_component_rows_amount, false),
                            var(component.W(1), start_row_index + non_native_range_component_rows_amount, false),
                            var(component.W(2), start_row_index + non_native_range_component_rows_amount, false),
                            var(component.W(3), start_row_index + non_native_range_component_rows_amount, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output.x[0], output.x[1], output.x[2], output.x[3],
                                output.y[0], output.y[1], output.y[2], output.y[3]};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                complete_addition(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                complete_addition(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            using plonk_ed25519_complete_addition = complete_addition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;

                    using non_native_range_component = components::range<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using multiplication_component = multiplication<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using addition_component = addition<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using subtraction_component = subtraction<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;

                    non_native_range_component non_native_range_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    multiplication_component multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    addition_component addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    subtraction_component subtraction_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});



                    std::size_t row = start_row_index;
                    typename Ed25519Type::base_field_type::integral_type base = 1;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;
                    std::array<typename BlueprintFieldType::value_type, 4> T_x_array = {
                        var_value(assignment, instance_input.T.x[0]),
                        var_value(assignment, instance_input.T.x[1]),
                        var_value(assignment, instance_input.T.x[2]),
                        var_value(assignment, instance_input.T.x[3])};
                    std::array<typename BlueprintFieldType::value_type, 4> T_y_array = {
                        var_value(assignment, instance_input.T.y[0]),
                        var_value(assignment, instance_input.T.y[1]),
                        var_value(assignment, instance_input.T.y[2]),
                        var_value(assignment, instance_input.T.y[3])};

                    std::array<var, 4> R_x = instance_input.R.x;
                    std::array<var, 4> R_y = instance_input.R.y;
                    std::array<typename BlueprintFieldType::value_type, 4> R_x_array = {
                        var_value(assignment, instance_input.R.x[0]),
                        var_value(assignment, instance_input.R.x[1]),
                        var_value(assignment, instance_input.R.x[2]),
                        var_value(assignment, instance_input.R.x[3])};
                    std::array<typename BlueprintFieldType::value_type, 4> R_y_array = {
                        var_value(assignment, instance_input.R.y[0]),
                        var_value(assignment, instance_input.R.y[1]),
                        var_value(assignment, instance_input.R.y[2]),
                        var_value(assignment, instance_input.R.y[3])};

                    typename Ed25519Type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T(
                        (typename Ed25519Type::base_field_type::integral_type(T_x_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                        (typename Ed25519Type::base_field_type::integral_type(T_y_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));
                    typename Ed25519Type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R(
                        (typename Ed25519Type::base_field_type::integral_type(R_x_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(R_x_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(R_x_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(R_x_array[3].data) * (base << 198)),
                        (typename Ed25519Type::base_field_type::integral_type(R_y_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(R_y_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(R_y_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(R_y_array[3].data) * (base << 198)));

                    typename Ed25519Type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = T + R;

                    typename Ed25519Type::base_field_type::integral_type mask = (base << 66) - 1;

                    typename Ed25519Type::base_field_type::integral_type Px_integral =
                        typename Ed25519Type::base_field_type::integral_type(P.X.data);
                    std::array<typename Ed25519Type::base_field_type::integral_type, 4> x3 = {
                        Px_integral & mask, (Px_integral >> 66) & mask, (Px_integral >> 132) & mask,
                        (Px_integral >> 198) & mask};

                    typename Ed25519Type::base_field_type::integral_type Py_integral =
                        typename Ed25519Type::base_field_type::integral_type(P.Y.data);
                    std::array<typename Ed25519Type::base_field_type::integral_type, 4> y3 = {
                        Py_integral & mask, (Py_integral >> 66) & mask, (Py_integral >> 132) & mask,
                        (Py_integral >> 198) & mask};

                    assignment.witness(component.W(0), row) = x3[0];
                    assignment.witness(component.W(1), row) = x3[1];
                    assignment.witness(component.W(2), row) = x3[2];
                    assignment.witness(component.W(3), row) = x3[3];
                    std::array<var, 4> P_x = {
                        var(component.W(0), row, false),
                        var(component.W(1), row, false),
                        var(component.W(2), row, false),
                        var(component.W(3), row, false)};

                    generate_assignments(non_native_range_instance, assignment,
                        typename non_native_range_component::input_type({P_x}), row);
                    row += non_native_range_instance.rows_amount;

                    assignment.witness(component.W(1), row) = y3[1];
                    assignment.witness(component.W(0), row) = y3[0];
                    assignment.witness(component.W(2), row) = y3[2];
                    assignment.witness(component.W(3), row) = y3[3];
                    std::array<var, 4> P_y = {
                        var(component.W(0), row, false),
                        var(component.W(1), row, false),
                        var(component.W(2), row, false),
                        var(component.W(3), row, false)};

                    generate_assignments(non_native_range_instance, assignment,
                        typename non_native_range_component::input_type({P_y}), row);
                    row += non_native_range_instance.rows_amount;

                    typename multiplication_component::result_type t0 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_x, R_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t1 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_y, R_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t2 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_x, R_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t3 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_y, R_y}), row);
                    row += multiplication_instance.rows_amount;

                    generate_assignments( // z0
                        addition_instance, assignment,
                        typename addition_component::input_type({t0.output, t1.output}), row);
                    row += addition_instance.rows_amount;

                    generate_assignments( // z1
                        addition_instance, assignment,
                        typename addition_component::input_type({t2.output, t3.output}), row);
                    row += addition_instance.rows_amount;

                    typename multiplication_component::result_type z2 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({t0.output, t1.output}), row);
                    row += multiplication_instance.rows_amount;

                    std::array<var, 4> d_var_array = {var(component.C(0), row + 4, false, var::column_type::constant),
                                                      var(component.C(0), row + 5, false, var::column_type::constant),
                                                      var(component.C(0), row + 6, false, var::column_type::constant),
                                                      var(component.C(0), row + 7, false, var::column_type::constant)};

                    typename multiplication_component::result_type k0 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({d_var_array, z2.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type k1 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({P_x, k0.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type k2 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({P_y, k0.output}), row);
                    row += multiplication_instance.rows_amount;

                    generate_assignments( // k3
                        addition_instance, assignment,
                        typename addition_component::input_type({P_x, k1.output}), row);
                    row += addition_instance.rows_amount;

                    generate_assignments( // k4
                        subtraction_instance, assignment,
                        typename subtraction_component::input_type({P_y, k2.output}), row);
                    row += subtraction_instance.rows_amount;

                    return typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;

                    using non_native_range_component = components::range<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using multiplication_component = multiplication<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using addition_component = addition<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                    using subtraction_component = subtraction<
                        ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;

                    non_native_range_component non_native_range_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    multiplication_component multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    addition_component addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    subtraction_component subtraction_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    std::size_t row = start_row_index;
                    std::array<var, 4> P_x = {
                        var(component.W(0), row, false),
                        var(component.W(1), row, false),
                        var(component.W(2), row, false),
                        var(component.W(3), row, false)};

                    generate_circuit(non_native_range_instance, bp, assignment,
                        typename non_native_range_component::input_type({P_x}), row);
                    row += non_native_range_instance.rows_amount;

                    std::array<var, 4> P_y = {
                        var(component.W(0), row, false),
                        var(component.W(1), row, false),
                        var(component.W(2), row, false),
                        var(component.W(3), row, false)};

                    generate_circuit(non_native_range_instance, bp, assignment,
                        typename non_native_range_component::input_type({P_y}), row);
                    row += non_native_range_instance.rows_amount;

                    std::array<var, 4> R_x = instance_input.R.x;
                    std::array<var, 4> R_y = instance_input.R.y;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename multiplication_component::result_type t0 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_x, R_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t1 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_y, R_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t2 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_x, R_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t3 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_y, R_y}), row);
                    row += multiplication_instance.rows_amount;

                    generate_circuit( // z0
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({t0.output, t1.output}), row);
                    row += addition_instance.rows_amount;

                    generate_circuit( // z1
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({t2.output, t3.output}), row);
                    row += addition_instance.rows_amount;

                    typename multiplication_component::result_type z2 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({t0.output, t1.output}), row);
                    row += multiplication_instance.rows_amount;

                    std::array<var, 4> d_var_array = {var(component.C(0), row + 4, false, var::column_type::constant),
                                                      var(component.C(0), row + 5, false, var::column_type::constant),
                                                      var(component.C(0), row + 6, false, var::column_type::constant),
                                                      var(component.C(0), row + 7, false, var::column_type::constant)};

                    typename multiplication_component::result_type k0 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({d_var_array, z2.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type k1 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({P_x, k0.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type k2 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({P_y, k0.output}), row);
                    row += multiplication_instance.rows_amount;

                    generate_circuit( // k3
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({P_x, k1.output}), row);
                    row += addition_instance.rows_amount;

                    generate_circuit( // k4
                        subtraction_instance, bp, assignment,
                        typename subtraction_component::input_type({P_y, k2.output}), row);
                    row += subtraction_instance.rows_amount;

                    generate_constants(component, bp, assignment, instance_input, start_row_index);
                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                    return typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }


            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            void generate_copy_constraints(
                const plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>;

                row += component_type::non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                row += component_type::non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);

                for (std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({{component.W(i), (std::int32_t)(row + 2), false},
                                            {component.W(i),
                                                (std::int32_t)(start_row_index + component.rows_amount - 4 - 2),
                                                false}});
                }
                row += component_type::addition_component::get_rows_amount(component.witness_amount(), 0);

                for (std::size_t i = 0; i < 4; i++) {
                    bp.add_copy_constraint({{component.W(i), (std::int32_t)(row + 2), false},
                                            {component.W(i),
                                                (std::int32_t)(start_row_index + component.rows_amount - 2),
                                                false}});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            void generate_constants(
                const plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using Ed25519Type = typename crypto3::algebra::curves::ed25519;

                using non_native_range_component = components::range<
                    ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                using multiplication_component = multiplication<
                    ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;
                using addition_component = addition<
                    ArithmetizationType, Ed25519Type::base_field_type, non_native_policy_type>;

                row += non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                row += non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                row += multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += multiplication_component::get_rows_amount(component.witness_amount(), 0);
                row += addition_component::get_rows_amount(component.witness_amount(), 0);
                row += addition_component::get_rows_amount(component.witness_amount(), 0);
                row += multiplication_component::get_rows_amount(component.witness_amount(), 0);

                typename Ed25519Type::base_field_type::integral_type base = 1;
                typename Ed25519Type::base_field_type::integral_type mask = (base << 66) - 1;

                typename Ed25519Type::base_field_type::integral_type d =
                    typename Ed25519Type::base_field_type::integral_type(
                        0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui256);
                assignment.constant(component.C(0), row + 4) = d & mask;
                assignment.constant(component.C(0), row + 5) = (d >> 66) & mask;
                assignment.constant(component.C(0), row + 6) = (d >> 132) & mask;
                assignment.constant(component.C(0), row + 7) = (d >> 198) & mask;
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            class input_type_converter<
                plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>> {

                using component_type =
                    plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>;
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

                    input_type new_input;

                    for (std::size_t i = 0; i < input.T.x.size(); i++) {
                        tmp_assignment.public_input(0, i) = var_value(assignment, input.T.x[i]);
                        new_input.T.x[i] = var(0, i, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.T.y.size(); i++) {
                        std::size_t new_idx = input.T.x.size() + i;
                        tmp_assignment.public_input(0, new_idx) = var_value(assignment, input.T.y[i]);
                        new_input.T.y[i] = var(0, new_idx, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.R.x.size(); i++) {
                        std::size_t new_idx = input.T.x.size() + input.T.y.size() + i;
                        tmp_assignment.public_input(0, new_idx) = var_value(assignment, input.R.x[i]);
                        new_input.R.x[i] = var(0, new_idx, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.R.y.size(); i++) {
                        std::size_t new_idx = input.T.x.size() + input.T.y.size() + input.R.x.size() + i;
                        tmp_assignment.public_input(0, new_idx) = var_value(assignment, input.R.y[i]);
                        new_input.R.y[i] = var(0, new_idx, false, var::column_type::public_input);
                    }

                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    if (std::size_t(variable.rotation) < input.T.x.size()) {
                        return input.T.x[variable.rotation];
                    } else if (std::size_t(variable.rotation) < input.T.x.size() + input.T.y.size()) {
                        return input.T.y[variable.rotation - input.T.x.size()];
                    } else if (std::size_t(variable.rotation) < input.T.x.size() + input.T.y.size() + input.R.x.size()) {
                        return input.R.x[variable.rotation - input.T.x.size() - input.T.y.size()];
                    } else {
                        return input.R.y[variable.rotation - input.T.x.size() - input.T.y.size() - input.R.x.size()];
                    }
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            class result_type_converter<
                plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>> {

                using component_type =
                    plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>;
                using input_type = typename component_type::input_type;
                using result_type = typename component_type::result_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, ArithmetizationParams, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    for (std::size_t i = 0; i < 4; i++) {
                        new_result.output.x[i] = component.move_var(
                            old_result.output.x[i],
                            start_row_index + component.line_mapping[old_result.output.x[i].rotation],
                            instance_input
                        );
                        new_result.output.y[i] = component.move_var(
                            old_result.output.y[i],
                            start_row_index + component.line_mapping[old_result.output.y[i].rotation],
                            instance_input
                        );
                    }

                    return new_result;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP