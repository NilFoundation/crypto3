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
// @file Declaration of interfaces for auxiliary components for the DOUBLING component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_DOUBLING_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_DOUBLING_EDWARD25519_HPP

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
            class doubling;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            class doubling<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    Ed25519Type,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

            public:
                using var = typename component_type::var;
                using manifest_type = typename component_type::manifest_type;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                using non_native_range_component = components::range<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using multiplication_component = multiplication<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using addition_component = addition<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;
                using subtraction_component = subtraction<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return doubling::gates_amount;
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
                        false
                    ).merge_with(multiplication_component::get_manifest())
                     .merge_with(addition_component::get_manifest())
                     .merge_with(subtraction_component::get_manifest())
                     .merge_with(non_native_range_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return
                        2 * non_native_range_component::get_rows_amount(witness_amount, lookup_column_amount) +
                        5 * multiplication_component::get_rows_amount(witness_amount, lookup_column_amount) +
                        4 * addition_component::get_rows_amount(witness_amount, lookup_column_amount) +
                        2 * subtraction_component::get_rows_amount(witness_amount, lookup_column_amount);
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const doubling &component, std::size_t start_row_index) {
                        output.x = {var(component.W(0), start_row_index, false),
                                    var(component.W(1), start_row_index, false),
                                    var(component.W(2), start_row_index, false),
                                    var(component.W(3), start_row_index, false)};
                        std::size_t non_native_rows_amount = non_native_range_component::get_rows_amount(
                            component.witness_amount(), 0);
                        output.y = {
                            var(component.W(0), start_row_index + non_native_rows_amount, false),
                            var(component.W(1), start_row_index + non_native_rows_amount, false),
                            var(component.W(2), start_row_index + non_native_rows_amount, false),
                            var(component.W(3), start_row_index + non_native_rows_amount, false)};
                    }
                };

                template<typename ContainerType>
                doubling(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                doubling(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                doubling(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            using plonk_ed25519_doubling = doubling<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;


            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = typename
                        plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams,
                                               CurveType>::non_native_policy_type;

                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

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
                    std::array<typename CurveType::base_field_type::value_type, 4> T_x_array = {
                        var_value(assignment, instance_input.T.x[0]),
                        var_value(assignment, instance_input.T.x[1]),
                        var_value(assignment, instance_input.T.x[2]),
                        var_value(assignment, instance_input.T.x[3])};
                    std::array<typename CurveType::base_field_type::value_type, 4> T_y_array = {
                        var_value(assignment, instance_input.T.y[0]),
                        var_value(assignment, instance_input.T.y[1]),
                        var_value(assignment, instance_input.T.y[2]),
                        var_value(assignment, instance_input.T.y[3])};

                    typename Ed25519Type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T(
                        (typename Ed25519Type::base_field_type::integral_type(T_x_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                        (typename Ed25519Type::base_field_type::integral_type(T_y_array[0].data) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));

                    typename Ed25519Type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = T + T;

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
                        var(component.W(0), row),
                        var(component.W(1), row),
                        var(component.W(2), row),
                        var(component.W(3), row)};

                    generate_assignments(non_native_range_instance, assignment,
                        typename non_native_range_component::input_type({P_x}), row);
                    row += non_native_range_instance.rows_amount;

                    assignment.witness(component.W(0), row) = y3[0];
                    assignment.witness(component.W(1), row) = y3[1];
                    assignment.witness(component.W(2), row) = y3[2];
                    assignment.witness(component.W(3), row) = y3[3];
                    std::array<var, 4> P_y = {
                        var(component.W(0), row),
                        var(component.W(1), row),
                        var(component.W(2), row),
                        var(component.W(3), row)};

                    generate_assignments(non_native_range_instance, assignment,
                        typename non_native_range_component::input_type({P_y}), row);
                    row += non_native_range_instance.rows_amount;

                    typename multiplication_component::result_type t0 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_y, T_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t1 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_x, T_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t2 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({T_x, T_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename subtraction_component::result_type t3 = generate_assignments(
                        subtraction_instance, assignment,
                        typename subtraction_component::input_type({t0.output, t1.output}), row);
                    row += subtraction_instance.rows_amount;

                    typename addition_component::result_type t4 = generate_assignments(
                        addition_instance, assignment,
                        typename addition_component::input_type({t2.output, t2.output}), row);
                    row += addition_instance.rows_amount;

                    typename addition_component::result_type t5 = generate_assignments(
                        addition_instance, assignment,
                        typename addition_component::input_type({t1.output, t0.output}), row);
                    row += addition_instance.rows_amount;

                    typename subtraction_component::result_type t6 = generate_assignments(
                        subtraction_instance, assignment,
                        typename subtraction_component::input_type({t1.output, t0.output}), row);
                    row += subtraction_instance.rows_amount;

                    typename multiplication_component::result_type t7 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({P_x, t3.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename addition_component::result_type t8 = generate_assignments(
                        addition_instance, assignment,
                        typename addition_component::input_type({P_y, P_y}), row);
                    row += addition_instance.rows_amount;

                    typename multiplication_component::result_type t9 = generate_assignments(
                        multiplication_instance, assignment,
                        typename multiplication_component::input_type({P_y, t6.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename addition_component::result_type t10 = generate_assignments(
                        addition_instance, assignment,
                        typename addition_component::input_type({t8.output, t9.output}), row);
                    row += addition_instance.rows_amount;

                    return typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }



            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = typename
                        plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams,
                                               CurveType>::non_native_policy_type;

                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

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
                        var(component.W(0), row),
                        var(component.W(1), row),
                        var(component.W(2), row),
                        var(component.W(3), row)};

                    generate_circuit(non_native_range_instance, bp, assignment,
                        typename non_native_range_component::input_type({P_x}), row);
                    row += non_native_range_instance.rows_amount;

                    std::array<var, 4> P_y = {
                        var(component.W(0), row),
                        var(component.W(1), row),
                        var(component.W(2), row),
                        var(component.W(3), row)};
                    generate_circuit(non_native_range_instance, bp, assignment,
                        typename non_native_range_component::input_type({P_y}), row);
                    row += non_native_range_instance.rows_amount;

                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;


                    typename multiplication_component::result_type t0 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_y, T_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t1 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_x, T_x}), row);
                    row += multiplication_instance.rows_amount;

                    typename multiplication_component::result_type t2 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({T_x, T_y}), row);
                    row += multiplication_instance.rows_amount;

                    typename subtraction_component::result_type t3 = generate_circuit(
                        subtraction_instance, bp, assignment,
                        typename subtraction_component::input_type({t0.output, t1.output}), row);
                    row += subtraction_instance.rows_amount;

                    typename addition_component::result_type t4 = generate_circuit(
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({t2.output, t2.output}), row);
                    row += addition_instance.rows_amount;

                    typename addition_component::result_type t5 = generate_circuit(
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({t1.output, t0.output}), row);
                    row += addition_instance.rows_amount;

                    typename subtraction_component::result_type t6 = generate_circuit(
                        subtraction_instance, bp, assignment,
                        typename subtraction_component::input_type({t1.output, t0.output}), row);
                    row += subtraction_instance.rows_amount;

                    typename multiplication_component::result_type t7 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({P_x, t3.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename addition_component::result_type t8 = generate_circuit(
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({P_y, P_y}), row);
                    row += addition_instance.rows_amount;

                    typename multiplication_component::result_type t9 = generate_circuit(
                        multiplication_instance, bp, assignment,
                        typename multiplication_component::input_type({P_y, t6.output}), row);
                    row += multiplication_instance.rows_amount;

                    typename addition_component::result_type t10 = generate_circuit(
                        addition_instance, bp, assignment,
                        typename addition_component::input_type({t8.output, t9.output}), row);
                    row += addition_instance.rows_amount;

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                    return typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                void generate_copy_constraints(
                    const plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;
                    using component_type = plonk_ed25519_doubling<BlueprintFieldType, ArithmetizationParams, CurveType>;

                    row += component_type::non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::non_native_range_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::subtraction_component::get_rows_amount(component.witness_amount(), 0);
                    std::size_t t4_row = row;
                    row += component_type::addition_component::get_rows_amount(component.witness_amount(), 0);
                    std::size_t t5_row = row;
                    row += component_type::addition_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::subtraction_component::get_rows_amount(component.witness_amount(), 0);
                    std::size_t t7_row = row;
                    row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::addition_component::get_rows_amount(component.witness_amount(), 0);
                    row += component_type::multiplication_component::get_rows_amount(component.witness_amount(), 0);
                    std::size_t t10_row = row;
                    row += component_type::addition_component::get_rows_amount(component.witness_amount(), 0);

                    for (std::size_t i = 0; i < 4; i++) {
                        bp.add_copy_constraint(
                            {{component.W(3 + i), (std::int32_t)(t7_row + 5), false},
                             {component.W(i    ), (std::int32_t)(t4_row + 2), false}});
                    }

                    for (std::size_t i = 0; i < 4; i++) {
                        bp.add_copy_constraint(
                            {{component.W(3 + i), (std::int32_t)(t5_row + 2), false},
                             {component.W(3 + i), (std::int32_t)(t10_row + 2), false}});
                    }
                }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP