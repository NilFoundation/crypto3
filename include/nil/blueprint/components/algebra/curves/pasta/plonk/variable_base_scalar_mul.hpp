//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Using results from https://arxiv.org/pdf/math/0208038.pdf
            // Vesta curve:
            // Input: x \in F_p, P \in E(F_p)
            // Output: y * P, where x = (y - 2^255 - 1) / 2 (if x is not -1, 0, 1)
            // Output: y * P, where x = (y - 2^255)         (if x is -1, 0, 1)
            // Pallas curve:
            // Input: x, x_high_bit \in F_p, P \in E(F_p)
            // Output: y * P, where x + 2^254 * x_high_bit  = (y - 2^255 - 1) / 2 (if (x + 2^254 * x_high_bit) is not -1, 0, 1)
            // Output: y * P, where x + 2^254 * x_high_bit  = (y - 2^255)         (if (x + 2^254 * x_high_bit)  is -1, 0, 1)

            // clang-format off
// _____________________________________________________________________________________________________________________________________________________
// |        |   W0   |   W1   |   W2    |   W3    |   W4    |   W5    |   W6    |   W7   |   W8   |   W9   |  W10   |  W11   |  W12   |  W13   |  W14   |
// |‾row‾0‾‾|‾‾ calculating 2T ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
// | row 1  |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |         | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 2  | P[5].X | P[5].Y | bits[0] | bits[1] | bits[2] | bits[3] | bits[4] |   s0   |   s1   |   s2   |  s3    |  s4    |        |        |        |
// | row 3  |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |         | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 4  | P[5].X | P[5].Y | bits[5] | bits[6] | bits[7] | bits[8] | bits[9] |   s0   |   s1   |   s2   |  s3    |  s4    |        |        |        |
// |        | ...                                                                                                                                       |
// |        | ...                                                                                                                                       |
// | row 59 |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |  u      | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 60 | P[5].X | P[5].Y | bits[5] | bits[6] | bits[7] | bits[8] | bits[9] |   s0   |   s1   |   s2   |  s3    |  s4    | u0     | u1     | u_next |
// |        | ...                                                                                                                                       |
// |        | ...                                                                                                                                       |
// | row 99 |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |  u      | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 100| P[5].X | P[5].Y | bits[5] | bits[6] | bits[7] | bits[8] | bits[9] |   s0   |   s1   |   s2   |  s3    |  s4    | u0     | u1     | u_next |
// | row 101|  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |  u      | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 102| P[5].X | P[5].Y | bits[5] | bits[6] | bits[7] | bits[8] | bits[9] |   s0   |   s1   |   s2   |  s3    |  s4    | u0     | u1     | u_next |
// | row 103|    x   |    y   |   t0    |   t1    |   t2    |  n_next |   T.X   |  T.Y   |   m    |   e1   |  e2    |  b     | aux    |        |        |
//  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
            // clang-format on

            ////////////////////////////////
            template<typename ConstFieldType>
            struct variable_base_scalar_mul_shifted_consts;

            template<>
            struct variable_base_scalar_mul_shifted_consts<typename nil::crypto3::algebra::curves::pallas> {
                using FieldType = nil::crypto3::algebra::fields::pallas_base_field;

                constexpr static const typename FieldType::value_type shifted_minus_one = 0x224698fc0994a8dd8c46eb2100000000_cppui255;
                constexpr static const typename FieldType::value_type shifted_zero = 0x200000000000000000000000000000003369e57a0e5efd4c526a60b180000001_cppui255;
                constexpr static const typename FieldType::value_type shifted_one = 0x224698fc0994a8dd8c46eb2100000001_cppui255;
            };

            template<>
            struct variable_base_scalar_mul_shifted_consts<typename nil::crypto3::algebra::curves::vesta> {
                using FieldType = nil::crypto3::algebra::fields::vesta_base_field;

                constexpr static const typename FieldType::value_type shifted_minus_one = 0x448d31f81299f237325a61da00000001_cppui255;
                constexpr static const typename FieldType::value_type shifted_zero =      0x448d31f81299f237325a61da00000002_cppui255;
                constexpr static const typename FieldType::value_type shifted_one =       0x448d31f81299f237325a61da00000003_cppui255;
            };
            ////////////////////////////////

            template<typename ArithmetizationType, typename CurveType>
            class curve_element_variable_base_scalar_mul;

            template<typename BlueprintFieldType, typename CurveType>
            class curve_element_variable_base_scalar_mul<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                CurveType
            >: public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using add_component =
                    nil::blueprint::components::unified_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, CurveType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return curve_element_variable_base_scalar_mul::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                        std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(add_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        true
                    ).merge_with(add_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                std::size_t lookup_column_amount) {
                    return rows_amount;
                }

                constexpr static const std::size_t mul_rows_amount = 102;
                constexpr static const std::size_t add_component_rows_amount =
                    add_component::get_rows_amount(11, 0);
                constexpr static const std::size_t rows_amount = add_component_rows_amount + mul_rows_amount + 1;
                constexpr static const std::size_t gates_amount = 3;
                const std::string component_name = "native curve multiplication by shifted const (https://arxiv.org/pdf/math/0208038.pdf)";

                constexpr static const std::size_t aux_bits_rows_amount = 44;
                constexpr static const std::size_t aux_bits_start_row = rows_amount - aux_bits_rows_amount - 1; // = 59

                constexpr static const typename BlueprintFieldType::value_type shifted_minus_one = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_minus_one;
                constexpr static const typename BlueprintFieldType::value_type shifted_zero = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_zero;
                constexpr static const typename BlueprintFieldType::value_type shifted_one = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_one;

                constexpr static const typename BlueprintFieldType::value_type t_q = 0x224698fc0994a8dd8c46eb2100000001_cppui255; // q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui255 = 2**254 + t_q
                constexpr static const typename BlueprintFieldType::value_type t_p = 0x224698fc094cf91b992d30ed00000001_cppui255; // p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255 = 2**254 + t_p (q > p)
                constexpr static const typename BlueprintFieldType::value_type two = 2;

                struct input_type {
                    struct var_ec_point {
                        var x;
                        var y;
                    };

                    var_ec_point T;
                    var b;
                    var b_high;
                    input_type(var_ec_point _T, var _b): T(_T), b(_b) {};
                    input_type(var_ec_point _T, var _b, var _b_high): T(_T), b(_b), b_high(_b_high) {};

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                            return {T.x, T.y, b, b_high};
                        } else {
                            return {T.x, T.y, b};
                        }
                    }
                };

                struct result_type {
                    var X;
                    var Y;
                    result_type(const curve_element_variable_base_scalar_mul &component, input_type &params, std::size_t start_row_index) {
                        X = var(component.W(0), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                        Y = var(component.W(1), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                    }
                    result_type(const curve_element_variable_base_scalar_mul &component, std::size_t start_row_index) {
                        X = var(component.W(0), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                        Y = var(component.W(1), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {X, Y};
                    }
                };

                template <typename ContainerType>
                curve_element_variable_base_scalar_mul(ContainerType witness):
                    component_type(witness, {}, {}, get_manifest()){};

                template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                curve_element_variable_base_scalar_mul(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                    component_type(witness, constant, public_input, get_manifest()){};

                curve_element_variable_base_scalar_mul(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                                std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                                std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                    component_type(witnesses, constants, public_inputs, get_manifest()){};
            };

            template<typename BlueprintFieldType, typename CurveType>
            using plonk_curve_element_variable_base_scalar_mul =
                curve_element_variable_base_scalar_mul<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    CurveType
                >;

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::result_type
                generate_assignments(
                    const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using add_component = typename plonk_curve_element_variable_base_scalar_mul<
                    BlueprintFieldType, CurveType>::add_component;

                typename BlueprintFieldType::value_type b = var_value(assignment, instance_input.b);
                typename BlueprintFieldType::value_type b_high;
                if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                    b_high = var_value(assignment, instance_input.b_high);
                } else {
                    b_high = 0;
                }
                typename BlueprintFieldType::value_type T_x = var_value(assignment, instance_input.T.x);
                typename BlueprintFieldType::value_type T_y = var_value(assignment, instance_input.T.y);
                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T(T_x,
                                                                                                            T_y);

                std::array<
                    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type, 6>
                    P;
                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type Q;

                typename CurveType::scalar_field_type::integral_type integral_b =
                    typename CurveType::scalar_field_type::integral_type(b.data);
                const std::size_t scalar_size = 255;
                nil::marshalling::status_type status;
                std::array<bool, scalar_size> bits =
                    nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);

                typename BlueprintFieldType::value_type z_n2;
                typename BlueprintFieldType::value_type aux;
                if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                    z_n2 = integral_b;
                    aux = z_n2 - component.t_q + component.two.pow(130);
                    typename BlueprintFieldType::integral_type intehral_b_high = typename BlueprintFieldType::integral_type(b_high.data);
                    if (intehral_b_high == 1) {
                        bits[0] = 1;
                    }
                } else {
                    z_n2 = integral_b - bits[0] * component.two.pow(254);
                    aux = z_n2 - component.t_p + component.two.pow(130);
                }
                typename CurveType::scalar_field_type::integral_type integral_aux =
                    typename CurveType::scalar_field_type::integral_type(aux.data);
                const std::size_t base_size = 255;
                std::array<bool, base_size> aux_bits =
                    nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_aux, status);

                typename BlueprintFieldType::value_type n = 0;
                typename BlueprintFieldType::value_type n_next = 0;

                add_component unified_addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                component.W(10)},{},{});

                typename add_component::input_type addition_input = {{instance_input.T.x, instance_input.T.y},
                                                                        {instance_input.T.x, instance_input.T.y}};

                typename add_component::result_type addition_res =
                    generate_assignments(unified_addition_instance, assignment, addition_input, start_row_index);


                typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type
                    T_doubled(var_value(assignment, addition_res.X), var_value(assignment, addition_res.Y));

                std::size_t j = start_row_index + component.add_component_rows_amount;

                for (std::size_t i = j; i < j + component.mul_rows_amount; i = i + 2) {
                    assignment.witness(component.W(0), i) = T.X;
                    assignment.witness(component.W(1), i) = T.Y;
                    if (i == j) {
                        P[0] = T_doubled;
                    } else {
                        P[0] = P[5];
                        n = n_next;
                    }
                    assignment.witness(component.W(2), i) = P[0].X;
                    assignment.witness(component.W(3), i) = P[0].Y;
                    assignment.witness(component.W(4), i) = n;
                    n_next = 32 * n + 16 * bits[((i - j) / 2) * 5] + 8 * bits[((i - j) / 2) * 5 + 1] +
                                4 * bits[((i - j) / 2) * 5 + 2] + 2 * bits[((i - j) / 2) * 5 + 3] +
                                bits[((i - j) / 2) * 5 + 4];
                    assignment.witness(component.W(5), i) = n_next;
                    Q.X = T.X;
                    Q.Y = (2 * bits[((i - j) / 2) * 5] - 1) * T.Y;
                    P[1] = (P[0] + Q) + P[0];
                    assignment.witness(component.W(7), i) = P[1].X;
                    assignment.witness(component.W(8), i) = P[1].Y;
                    assignment.witness(component.W(7), i + 1) = (P[0].Y - Q.Y) * (P[0].X - Q.X).inversed();
                    Q.Y = (2 * bits[((i - j) / 2) * 5 + 1] - 1) * T.Y;
                    P[2] = (P[1] + Q) + P[1];
                    assignment.witness(component.W(9), i) = P[2].X;
                    assignment.witness(component.W(10), i) = P[2].Y;
                    assignment.witness(component.W(8), i + 1) = (P[1].Y - Q.Y) * (P[1].X - Q.X).inversed();
                    Q.Y = (2 * bits[((i - j) / 2) * 5 + 2] - 1) * T.Y;
                    P[3] = (P[2] + Q) + P[2];
                    assignment.witness(component.W(11), i) = P[3].X;
                    assignment.witness(component.W(12), i) = P[3].Y;
                    assignment.witness(component.W(9), i + 1) = (P[2].Y - Q.Y) * (P[2].X - Q.X).inversed();
                    Q.Y = (2 * bits[((i - j) / 2) * 5 + 3] - 1) * T.Y;
                    P[4] = (P[3] + Q) + P[3];
                    assignment.witness(component.W(13), i) = P[4].X;
                    assignment.witness(component.W(14), i) = P[4].Y;
                    assignment.witness(component.W(10), i + 1) = (P[3].Y - Q.Y) * (P[3].X - Q.X).inversed();
                    Q.Y = (2 * bits[((i - j) / 2) * 5 + 4] - 1) * T.Y;
                    P[5] = (P[4] + Q) + P[4];
                    assignment.witness(component.W(0), i + 1) = P[5].X;
                    assignment.witness(component.W(1), i + 1) = P[5].Y;
                    assignment.witness(component.W(11), i + 1) = (P[4].Y - Q.Y) * (P[4].X - Q.X).inversed();
                    assignment.witness(component.W(2), i + 1) = bits[((i - j) / 2) * 5];
                    assignment.witness(component.W(3), i + 1) = bits[((i - j) / 2) * 5 + 1];
                    assignment.witness(component.W(4), i + 1) = bits[((i - j) / 2) * 5 + 2];
                    assignment.witness(component.W(5), i + 1) = bits[((i - j) / 2) * 5 + 3];
                    assignment.witness(component.W(6), i + 1) = bits[((i - j) / 2) * 5 + 4];
                }

                // assign additional bits of aux for the range check (integral_b < q) or (b_high * 2^254 + integral_b < q)
                typename BlueprintFieldType::value_type u_next = 0;
                typename BlueprintFieldType::value_type u0, u1;
                for (std::size_t i = start_row_index + component.aux_bits_start_row; i <= start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 3; i = i + 2) {
                    assignment.witness(component.W(6), i) = u_next;
                    const std::size_t ind = 125 + ((i - component.aux_bits_start_row - start_row_index) / 2) * 6;
                    u0 = 4 * aux_bits[ind] + 2 * aux_bits[ind+1] + aux_bits[ind+2];
                    u1 = 4 * aux_bits[ind+3] + 2 * aux_bits[ind+4] + aux_bits[ind+5];
                    u_next = 64 * u_next + 8 * u0 + u1;
                    assignment.witness(component.W(12), i+1) = u0;
                    assignment.witness(component.W(13), i+1) = u1;
                    assignment.witness(component.W(14), i+1) = u_next;
                }
                assignment.witness(component.W(6), start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 2) = u_next;
                const std::size_t ind = 125 + (component.aux_bits_rows_amount / 2 - 1) * 6;
                u0 = 4 * aux_bits[ind] + 2 * aux_bits[ind+1] + aux_bits[ind+2];
                u1 = aux_bits[ind+3];
                u_next = 16 * u_next + 2 * u0 + u1;
                assignment.witness(component.W(12), start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 1) = u0;
                assignment.witness(component.W(13), start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 1) = u1;
                assignment.witness(component.W(14), start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 1) = u_next;

                assignment.witness(component.W(9), start_row_index + component.rows_amount - 1) = bits[0];
                typename BlueprintFieldType::value_type e2 = 0;
                typename BlueprintFieldType::value_type cur_pow = 1;
                for (std::size_t l = 130; l <= 254; l = l + 1) {
                    e2 += + bits[254-l] * cur_pow;
                    cur_pow = cur_pow * 2;
                }
                assignment.witness(component.W(10), start_row_index + component.rows_amount - 1) = e2;
                assignment.witness(component.W(11), start_row_index + component.rows_amount - 1) = integral_b;
                assignment.witness(component.W(12), start_row_index + component.rows_amount - 1) = aux;

                // assign last 3 rows
                typename BlueprintFieldType::value_type m = ((n_next - component.shifted_minus_one)*
                (n_next - component.shifted_zero)*(n_next - component.shifted_one));
                typename BlueprintFieldType::value_type t0 = ( m == 0 ? 0 : m.inversed());
                typename BlueprintFieldType::value_type t1 = ((n_next - component.shifted_minus_one) == 0) ? 0 : (n_next - component.shifted_minus_one).inversed();
                typename BlueprintFieldType::value_type t2 = ((n_next - component.shifted_one)       == 0) ? 0 : (n_next - component.shifted_one).inversed();
                typename BlueprintFieldType::value_type x;
                typename BlueprintFieldType::value_type y;
                if (n_next == component.shifted_minus_one) {
                    x = T.X;
                    y = -T.Y;
                } else  {
                    if (n_next == component.shifted_zero) {
                        x = 0;
                        y = 0;
                    } else {
                        if (n_next == component.shifted_one) {
                            x = T.X;
                            y = T.Y;
                        } else {
                            x = P[5].X;
                            y = P[5].Y;
                        }
                    }
                }
                assignment.witness(component.W(2), start_row_index + component.rows_amount - 1) = t0;
                assignment.witness(component.W(3), start_row_index + component.rows_amount - 1) = t1;
                assignment.witness(component.W(4), start_row_index + component.rows_amount - 1) = t2;
                assignment.witness(component.W(5), start_row_index + component.rows_amount - 1) = n_next;
                assignment.witness(component.W(6), start_row_index + component.rows_amount - 1) = T.X;
                assignment.witness(component.W(7), start_row_index + component.rows_amount - 1) = T.Y;
                assignment.witness(component.W(8), start_row_index + component.rows_amount - 1) = m;
                assignment.witness(component.W(0), start_row_index + component.rows_amount - 1) = x;
                assignment.witness(component.W(1), start_row_index + component.rows_amount - 1) = y;

                return typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::result_type
                generate_circuit(
                    const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                using add_component = typename plonk_curve_element_variable_base_scalar_mul<
                    BlueprintFieldType, CurveType>::add_component;

                generate_assignments_constants(component, bp, assignment, instance_input, start_row_index);

                auto selectors = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selectors[0], start_row_index + component.add_component_rows_amount,
                                            start_row_index + component.rows_amount - 4, 2);
                assignment.enable_selector(selectors[1], start_row_index + component.rows_amount - 2);
                assignment.enable_selector(selectors[2], start_row_index + component.aux_bits_start_row,
                                            start_row_index + component.aux_bits_start_row + component.aux_bits_rows_amount - 4, 2);

                typename add_component::input_type addition_input = {{instance_input.T.x, instance_input.T.y},
                                                                        {instance_input.T.x, instance_input.T.y}};

                add_component unified_addition_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                     component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                     component.W(10)}, {}, {});

                generate_circuit(unified_addition_instance, bp, assignment, addition_input, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                return typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename CurveType>
                std::array<std::size_t, 3> generate_gates(
                    const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::input_type instance_input) {

                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
                using var = typename curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType>::var;

                auto bit_check_1 = var(component.W(2), +1) * (1 - var(component.W(2), +1));
                auto bit_check_2 = var(component.W(3), +1) * (1 - var(component.W(3), +1));
                auto bit_check_3 = var(component.W(4), +1) * (1 - var(component.W(4), +1));
                auto bit_check_4 = var(component.W(5), +1) * (1 - var(component.W(5), +1));
                auto bit_check_5 = var(component.W(6), +1) * (1 - var(component.W(6), +1));

                auto constraint_1 =
                    (var(component.W(2), 0) - var(component.W(0), 0)) * var(component.W(7), +1) -
                    (var(component.W(3), 0) - (2 * var(component.W(2), +1) - 1) * var(component.W(1), 0));
                auto constraint_2 =
                    (var(component.W(7), 0) - var(component.W(0), 0)) * var(component.W(8), +1) -
                    (var(component.W(8), 0) - (2 * var(component.W(3), +1) - 1) * var(component.W(1), 0));
                auto constraint_3 =
                    (var(component.W(9), 0) - var(component.W(0), 0)) * var(component.W(9), +1) -
                    (var(component.W(10), 0) - (2 * var(component.W(4), +1) - 1) * var(component.W(1), 0));
                auto constraint_4 =
                    (var(component.W(11), 0) - var(component.W(0), 0)) * var(component.W(10), +1) -
                    (var(component.W(12), 0) - (2 * var(component.W(5), +1) - 1) * var(component.W(1), 0));
                auto constraint_5 =
                    (var(component.W(13), 0) - var(component.W(0), 0)) * var(component.W(11), +1) -
                    (var(component.W(14), 0) - (2 * var(component.W(6), +1) - 1) * var(component.W(1), 0));

                auto constraint_6 =
                    (2 * var(component.W(3), 0) - var(component.W(7), 1) * (2 * var(component.W(2), 0) -
                         var(component.W(7), 1).pow(2) + var(component.W(0), 0))) *
                    (2 * var(component.W(3), 0) - var(component.W(7), 1) * (2 * var(component.W(2), 0) -
                         var(component.W(7), 1).pow(2) + var(component.W(0), 0))) -
                    ((2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0)) *
                     (2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0)) *
                     (var(component.W(7), 0) - var(component.W(0), 0) + var(component.W(7), 1).pow(2)));
                auto constraint_7 =
                    (2 * var(component.W(8), 0) - var(component.W(8), 1) * (2 * var(component.W(7), 0) -
                         var(component.W(8), 1).pow(2) + var(component.W(0), 0))) *
                    (2 * var(component.W(8), 0) - var(component.W(8), 1) * (2 * var(component.W(7), 0) -
                         var(component.W(8), 1).pow(2) + var(component.W(0), 0))) -
                    ((2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0)) *
                     (2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0)) *
                     (var(component.W(9), 0) - var(component.W(0), 0) + var(component.W(8), 1).pow(2)));
                auto constraint_8 =
                    (2 * var(component.W(10), 0) - var(component.W(9), 1) * (2 * var(component.W(9), 0) -
                         var(component.W(9), 1).pow(2) + var(component.W(0), 0))) *
                    (2 * var(component.W(10), 0) - var(component.W(9), 1) * (2 * var(component.W(9), 0) -
                         var(component.W(9), 1).pow(2) + var(component.W(0), 0))) -
                    ((2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0)) *
                     (2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0)) *
                     (var(component.W(11), 0) - var(component.W(0), 0) + var(component.W(9), 1).pow(2)));
                auto constraint_9 =
                    (2 * var(component.W(12), 0) - var(component.W(10), +1) * (2 * var(component.W(11), 0) -
                         var(component.W(10), +1).pow(2) + var(component.W(0), 0))) *
                    (2 * var(component.W(12), 0) - var(component.W(10), +1) * (2 * var(component.W(11), 0) -
                          var(component.W(10), +1).pow(2) + var(component.W(0), 0))) -
                    ((2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)) *
                     (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)) *
                     (var(component.W(13), 0) - var(component.W(0), 0) + var(component.W(10), +1).pow(2)));
                auto constraint_10 =
                    (2 * var(component.W(14), 0) - var(component.W(11), +1) * (2 * var(component.W(13), 0) -
                         var(component.W(11), +1).pow(2) + var(component.W(0), 0))) *
                    (2 * var(component.W(14), 0) - var(component.W(11), +1) * (2 * var(component.W(13), 0) -
                         var(component.W(11), +1).pow(2) + var(component.W(0), 0))) -
                    ((2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)) *
                     (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)) *
                     (var(component.W(0), 1) - var(component.W(0), 0) + var(component.W(11), +1).pow(2)));

                auto constraint_11 =
                    (var(component.W(8), 0) + var(component.W(3), 0)) * (2 * var(component.W(2), 0) - var(component.W(7), +1).pow(2) + var(component.W(0), 0)) -
                    ((var(component.W(2), 0) - var(component.W(7), 0)) *
                     (2 * var(component.W(3), 0) - var(component.W(7), +1) * (2 * var(component.W(2), 0) -
                          var(component.W(7), +1).pow(2) + var(component.W(0), 0))));
                auto constraint_12 =
                    (var(component.W(10), 0) + var(component.W(8), 0)) * (2 * var(component.W(7), 0) -
                     var(component.W(8), +1).pow(2) + var(component.W(0), 0)) -
                    ((var(component.W(7), 0) - var(component.W(9), 0)) *
                     (2 * var(component.W(8), 0) - var(component.W(8), +1) *
                     (2 * var(component.W(7), 0) - var(component.W(8), +1).pow(2) + var(component.W(0), 0))));
                auto constraint_13 =
                    (var(component.W(12), 0) + var(component.W(10), 0)) * (2 * var(component.W(9), 0) -
                     var(component.W(9), +1).pow(2) + var(component.W(0), 0)) -
                     ((var(component.W(9), 0) - var(component.W(11), 0)) *
                        (2 * var(component.W(10), 0) - var(component.W(9), +1) * (2 * var(component.W(9), 0) -
                             var(component.W(9), +1).pow(2) + var(component.W(0), 0))));
                auto constraint_14 =
                    (var(component.W(14), 0) + var(component.W(12), 0)) * (2 * var(component.W(11), 0) -
                     var(component.W(10), +1).pow(2) + var(component.W(0), 0)) -
                    ((var(component.W(11), 0) - var(component.W(13), 0)) *
                     (2 * var(component.W(12), 0) - var(component.W(10), +1) *
                     (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0))));
                auto constraint_15 =
                    (var(component.W(1), +1) + var(component.W(14), 0)) * (2 * var(component.W(13), 0) -
                     var(component.W(11), +1).pow(2) + var(component.W(0), 0)) -
                    ((var(component.W(13), 0) - var(component.W(0), +1)) *
                     (2 * var(component.W(14), 0) - var(component.W(11), +1) * (2 * var(component.W(13), 0) -
                          var(component.W(11), +1).pow(2) + var(component.W(0), 0))));

                auto constraint_16 =
                    var(component.W(5), 0) -
                    (32 * (var(component.W(4), 0)) + 16 * var(component.W(2), +1) + 8 * var(component.W(3), +1) +
                     4 * var(component.W(4), +1) + 2 * var(component.W(5), +1) + var(component.W(6), +1));

                std::size_t selector_index_1 = bp.add_gate(
                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                     constraint_16});

                bit_check_1 = var(component.W(2), 0) * (1 - var(component.W(2), 0));
                bit_check_2 = var(component.W(3), 0) * (1 - var(component.W(3), 0));
                bit_check_3 = var(component.W(4), 0) * (1 - var(component.W(4), 0));
                bit_check_4 = var(component.W(5), 0) * (1 - var(component.W(5), 0));
                bit_check_5 = var(component.W(6), 0) * (1 - var(component.W(6), 0));

                constraint_1 =
                    (var(component.W(2), -1) - var(component.W(0), -1)) * var(component.W(7), 0) -
                    (var(component.W(3), -1) - (2 * var(component.W(2), 0) - 1) * var(component.W(1), -1));
                constraint_2 =
                    (var(component.W(7), -1) - var(component.W(0), -1)) * var(component.W(8), 0) -
                    (var(component.W(8), -1) - (2 * var(component.W(3), 0) - 1) * var(component.W(1), -1));
                constraint_3 =
                    (var(component.W(9), -1) - var(component.W(0), -1)) * var(component.W(9), 0) -
                    (var(component.W(10), -1) - (2 * var(component.W(4), 0) - 1) * var(component.W(1), -1));
                constraint_4 =
                    (var(component.W(11), -1) - var(component.W(0), -1)) * var(component.W(10), 0) -
                    (var(component.W(12), -1) - (2 * var(component.W(5), 0) - 1) * var(component.W(1), -1));
                constraint_5 =
                    (var(component.W(13), -1) - var(component.W(0), -1)) * var(component.W(11), 0) -
                    (var(component.W(14), -1) - (2 * var(component.W(6), 0) - 1) * var(component.W(1), -1));

                constraint_6 =
                    (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) -
                         var(component.W(7), 0).pow(2) + var(component.W(0), -1))) *
                    (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) -
                         var(component.W(7), 0).pow(2) + var(component.W(0), -1))) -
                    ((2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) *
                     (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) *
                     (var(component.W(7), -1) - var(component.W(0), -1) + var(component.W(7), 0).pow(2)));
                constraint_7 =
                    (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) -
                         var(component.W(8), 0).pow(2) + var(component.W(0), -1))) *
                    (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) -
                         var(component.W(8), 0).pow(2) + var(component.W(0), -1))) -
                    ((2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)) *
                     (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)) *
                     (var(component.W(9), -1) - var(component.W(0), -1) + var(component.W(8), 0).pow(2)));
                constraint_8 =
                    (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) -
                         var(component.W(9), 0).pow(2) + var(component.W(0), -1))) *
                    (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) -
                         var(component.W(9), 0).pow(2) + var(component.W(0), -1))) -
                    ((2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)) *
                     (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)) *
                     (var(component.W(11), -1) - var(component.W(0), -1) + var(component.W(9), 0).pow(2)));
                constraint_9 =
                    ((2 * var(component.W(12), -1) - var(component.W(10), 0) * (2 * var(component.W(11), -1) -
                          var(component.W(10), 0).pow(2) + var(component.W(0), -1))) *
                     (2 * var(component.W(12), -1) - var(component.W(10), 0) * (2 * var(component.W(11), -1) -
                          var(component.W(10), 0).pow(2) + var(component.W(0), -1))) -
                    ((2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1)) *
                     (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1)) *
                     (var(component.W(13), -1) - var(component.W(0), -1) + var(component.W(10), 0).pow(2)))) *
                      var(component.W(8), +1) * var(component.W(2), +1);
                constraint_10 =
                    ((2 * var(component.W(14), -1) - var(component.W(11), 0) * (2 * var(component.W(13), -1) -
                          var(component.W(11), 0).pow(2) + var(component.W(0), -1))) *
                    (2 * var(component.W(14), -1) - var(component.W(11), 0) * (2 * var(component.W(13), -1) -
                         var(component.W(11), 0).pow(2) + var(component.W(0), -1))) -
                    ((2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) *
                     (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) *
                     (var(component.W(0), 0) - var(component.W(0), -1) + var(component.W(11), 0).pow(2)))) *
                    var(component.W(8), +1) * var(component.W(2), +1);

                constraint_11 =
                    (var(component.W(8), -1) + var(component.W(3), -1)) *
                    (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) -
                    ((var(component.W(2), -1) - var(component.W(7), -1)) *
                     (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) -
                          var(component.W(7), 0).pow(2) + var(component.W(0), -1))));
                constraint_12 =
                    (var(component.W(10), -1) + var(component.W(8), -1)) * (2 * var(component.W(7), -1) -
                     var(component.W(8), 0).pow(2) + var(component.W(0), -1)) -
                    ((var(component.W(7), -1) - var(component.W(9), -1)) *
                     (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) -
                          var(component.W(8), 0).pow(2) + var(component.W(0), -1))));
                constraint_13 =
                    (var(component.W(12), -1) + var(component.W(10), -1)) * (2 * var(component.W(9), -1) -
                     var(component.W(9), 0).pow(2) + var(component.W(0), -1)) -
                    ((var(component.W(9), -1) - var(component.W(11), -1)) *
                     (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) -
                          var(component.W(9), 0).pow(2) + var(component.W(0), -1))));
                constraint_14 =
                    ((var(component.W(14), -1) + var(component.W(12), -1)) * (2 * var(component.W(11), -1) -
                      var(component.W(10), 0).pow(2) + var(component.W(0), -1)) -
                    ((var(component.W(11), -1) - var(component.W(13), -1)) *
                        (2 * var(component.W(12), -1) -
                        var(component.W(10), 0) * (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1))))) *
                    var(component.W(8), +1) * var(component.W(2), +1);
                constraint_15 =
                    ((var(component.W(1), 0) + var(component.W(14), -1)) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) -
                        ((var(component.W(13), -1) - var(component.W(0), 0)) *
                        (2 * var(component.W(14), -1) -
                        var(component.W(11), 0) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1))))) *
                    var(component.W(8), +1) * var(component.W(2), +1);

                constraint_16 =
                    var(component.W(5), -1) - (32 * (var(component.W(4), -1)) + 16 * var(component.W(2), 0) + 8 * var(component.W(3), 0) +
                                                    4 * var(component.W(4), 0) + 2 * var(component.W(5), 0) + var(component.W(6), 0));

                auto constraint_17 = (var(component.W(8), +1)*var(component.W(2), +1) - 1) * var(component.W(8), +1);
                auto constraint_18 = ((var(component.W(5), +1) - component.shifted_minus_one)
                *var(component.W(3), +1) - 1) * (var(component.W(5), +1) - component.shifted_minus_one);
                auto constraint_19 = ((var(component.W(5), +1) - component.shifted_one)
                *var(component.W(4), +1) - 1) * (var(component.W(5), +1) - component.shifted_one);
                auto constraint_20 = (var(component.W(8), +1)*var(component.W(2), +1)*var(component.W(0), 0)) +
                ((var(component.W(5), +1) - component.shifted_minus_one)
                *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                *var(component.W(4), +1))* ((var(component.W(5), +1) - component.shifted_minus_one)
                *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                *var(component.W(4), +1)) * var(component.W(6), +1) - var(component.W(0), +1);
                auto constraint_21 = (var(component.W(8), +1)*var(component.W(2), +1)*var(component.W(1), 0)) +
                ((var(component.W(5), +1) - component.shifted_minus_one)
                *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                *var(component.W(4), +1)) * var(component.W(7), +1) - var(component.W(1), +1);
                auto constraint_22 = var(component.W(8), +1) - ((var(component.W(5), +1) - component.shifted_minus_one)
                *(var(component.W(5), +1) - component.shifted_zero)*
                (var(component.W(5), +1) - component.shifted_one));

                // additional range-check constraints:
                // check   u_0 = 3-bit chunk of aux
                auto constraint_23 =
                    var(component.W(12), 0) * (var(component.W(12), 0) - 1) * (var(component.W(12), 0) - 2) * (var(component.W(12), 0) - 3)
                        * (var(component.W(12), 0) - 4) * (var(component.W(12), 0) - 5)  * (var(component.W(12), 0) - 6) * (var(component.W(12), 0) - 7);
                // check   u_1 = 1-bit chunk of aux
                auto constraint_24 = var(component.W(13), 0) * (var(component.W(13), 0) - 1);
                // check  accumalator(u_i)
                auto constraint_25 =
                    var(component.W(14), 0) - 16 * var(component.W(6), -1) - 2 * var(component.W(12), 0) -
                    var(component.W(13), 0);
                // check   aux = z_{n-2} - t_p + 2^130
                auto constraint_28 = var(component.W(9), 0) - (var(component.W(9), 0));
                if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                    constraint_28 =
                    var(component.W(12), +1) - var(component.W(11), +1) + component.t_q - component.two.pow(130);
                } else {
                    constraint_28 =
                    var(component.W(12), +1) - var(component.W(11), +1) + var(component.W(9), +1) * component.two.pow(254) + component.t_p - component.two.pow(130);
                }
                // check   (bits[0] = 1) => accumalator(u_i) = aux
                auto constraint_26 = var(component.W(9), +1) * (var(component.W(14), 0) - var(component.W(12), +1));
                // check   (bits[0] = 1) =>  V_130 = 2^124
                auto constraint_27 = var(component.W(9), +1) * (var(component.W(10), +1) - component.two.pow(124));

                // check   b_high * 2^254 + b = accamulator(b_i) (mod p)
                //         (b_high = 1) => b < 2^254
                auto constraint_29 = var(component.W(9), 0) - var(component.W(9), 0);
                if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                    constraint_29 =
                        var(component.W(5), -1) - var(component.W(11), +1) -
                        var(component.W(9), +1) * component.two.pow(254);
                }

                std::size_t selector_index_2 = bp.add_gate(
                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                     constraint_16, constraint_17, constraint_18, constraint_19, constraint_20,
                     constraint_21, constraint_22,
                     constraint_23, constraint_24, constraint_25, constraint_26, constraint_27,
                     constraint_28, constraint_29});

                // check   u_0 = 3-bit chunk of aux
                constraint_1 =
                    var(component.W(12), +1) * (var(component.W(12), +1) - 1) * (var(component.W(12), +1) - 2) * (var(component.W(12), +1) - 3)
                        * (var(component.W(12), +1) - 4) * (var(component.W(12), +1) - 5)  * (var(component.W(12), +1) - 6) * (var(component.W(12), +1) - 7);
                // check   u_1 = 3-bit chunk of aux
                constraint_2 =
                    var(component.W(13), +1) * (var(component.W(13), +1) - 1) * (var(component.W(13), +1) - 2) * (var(component.W(13), +1) - 3)
                        * (var(component.W(13), +1) - 4) * (var(component.W(13), +1) - 5)  * (var(component.W(13), +1) - 6) * (var(component.W(13), +1) - 7);
                // check   u_next = intermediate accumalator(u_i)
                constraint_3 =
                    var(component.W(14), +1) - 64 * var(component.W(6), 0) - 8 * var(component.W(12), +1) - var(component.W(13), +1);
                std::size_t selector_index_3 = bp.add_gate({constraint_1, constraint_2, constraint_3});

                return {selector_index_1, selector_index_2, selector_index_3};
            }

            template<typename BlueprintFieldType, typename CurveType>
                void generate_copy_constraints(
                    const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t j = start_row_index + component.add_component_rows_amount;
                using var = typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::var;
                using add_component = typename plonk_curve_element_variable_base_scalar_mul<
                    BlueprintFieldType, CurveType>::add_component;

                add_component unified_addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                component.W(10)},{},{});

                typename add_component::result_type addition_res(unified_addition_instance, start_row_index);

                bp.add_copy_constraint({{component.W(2), (std::int32_t)(j), false}, addition_res.X});
                bp.add_copy_constraint({{component.W(3), (std::int32_t)(j), false}, addition_res.Y});

                // main algorithm

                for (int z = 0; z < component.mul_rows_amount - 2; z += 2) {
                    bp.add_copy_constraint(
                        {{component.W(0), (std::int32_t)(j + z), false}, {component.W(0), (std::int32_t)(j + z + 2), false}});
                    bp.add_copy_constraint(
                        {{component.W(1), (std::int32_t)(j + z), false}, {component.W(1), (std::int32_t)(j + z + 2), false}});
                }

                for (int z = 2; z < component.mul_rows_amount; z += 2) {
                    bp.add_copy_constraint(
                        {{component.W(2), (std::int32_t)(j + z), false}, {component.W(0), (std::int32_t)(j + z - 1), false}});
                    bp.add_copy_constraint(
                        {{component.W(3), (std::int32_t)(j + z), false}, {component.W(1), (std::int32_t)(j + z - 1), false}});
                }

                for (int z = 2; z < component.mul_rows_amount; z += 2) {
                    bp.add_copy_constraint(
                        {{component.W(4), (std::int32_t)(j + z), false}, {component.W(5), (std::int32_t)(j + z - 2), false}});
                }
                bp.add_copy_constraint({{component.W(5), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                        {component.W(5), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});
                bp.add_copy_constraint({{component.W(6), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                        {component.W(0), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});
                bp.add_copy_constraint({{component.W(7), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                        {component.W(1), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});

                bp.add_copy_constraint({{component.W(4), (std::int32_t)(j), false},
                                        {component.W(0), (std::int32_t)(j), false, var::column_type::constant}});

                // bp.add_copy_constraint(
                //     {instance_input.b, {component.W(5), (std::int32_t)(j + component.rows_amount - 4), false}});    // scalar value check

                // additional range-checks copy constraints
                if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                    bp.add_copy_constraint(
                        {instance_input.b_high, {component.W(2), (std::int32_t)(j + 1), false}});
                } else {
                    bp.add_copy_constraint(
                        {instance_input.b, {component.W(5), (std::int32_t)(j + component.rows_amount - 4), false}});    // scalar value check
                }
                bp.add_copy_constraint(
                        {{component.C(0), (std::int32_t)(j), false, var::column_type::constant}, {component.W(6), (std::int32_t)(j + 58), false}});
                for (int z = 0; z < 40; z += 2) {
                    bp.add_copy_constraint(
                        {{component.W(14), (std::int32_t)(j + 58 + z + 1), false}, {component.W(6), (std::int32_t)(j + 58 + z + 2), false}});
                }
                bp.add_copy_constraint(
                        {{component.W(2), (std::int32_t)(j + 1), false}, {component.W(9), (std::int32_t)(j + 102), false}});
                bp.add_copy_constraint(
                        {{component.W(5), (std::int32_t)(j + 48), false}, {component.W(10), (std::int32_t)(j + 102), false}});
                bp.add_copy_constraint(
                        {instance_input.b, {component.W(11), (std::int32_t)(j + 102), false}});

            }

            template<typename BlueprintFieldType, typename CurveType>
                    void generate_assignments_constants(
                        const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                        const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>::input_type instance_input,
                        const std::uint32_t start_row_index) {
                std::size_t row = start_row_index + component.add_component_rows_amount;

                assignment.constant(component.C(0), row) = BlueprintFieldType::value_type::zero();
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename CurveType>
            class input_type_converter<
                plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>> {

                using component_type =
                    plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_assignment) {

                    tmp_assignment.public_input(0, 0) = var_value(assignment, input.T.x);
                    tmp_assignment.public_input(0, 1) = var_value(assignment, input.T.y);
                    tmp_assignment.public_input(0, 2) = var_value(assignment, input.b);
                    if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                        tmp_assignment.public_input(0, 3) = var_value(assignment, input.b_high);
                    }

                    if (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
                        input_type new_input(
                            {var(0, 0, false, var::column_type::public_input),
                            var(0, 1, false, var::column_type::public_input)},
                            var(0, 2, false, var::column_type::public_input),
                            var(0, 3, false, var::column_type::public_input)
                        );
                        return new_input;
                    } else {
                        input_type new_input(
                            {var(0, 0, false, var::column_type::public_input),
                            var(0, 1, false, var::column_type::public_input)},
                            var(0, 2, false, var::column_type::public_input)
                        );
                        return new_input;
                    }
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    var new_var;
                    switch (variable.rotation) {
                    case 0:
                        new_var = input.T.x;
                        break;
                    case 1:
                        new_var = input.T.y;
                        break;
                    case 2:
                        new_var = input.b;
                        break;
                    case 3:
                        new_var = input.b_high;
                        break;
                    default:
                        BOOST_ASSERT_MSG(false, "Incorrect variable passed to deconvert_var");
                    }
                    return new_var;
                }
            };

            template<typename BlueprintFieldType, typename CurveType>
            class result_type_converter<
                plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>> {

                using component_type =
                    plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, CurveType>;
                using input_type = typename component_type::input_type;
                using result_type = typename component_type::result_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    new_result.X = component.move_var(
                        old_result.X,
                        start_row_index + component.line_mapping[old_result.X.rotation],
                        instance_input);
                    new_result.Y = component.move_var(
                        old_result.Y,
                        start_row_index + component.line_mapping[old_result.Y.rotation],
                        instance_input);

                    return new_result;
                }
            };
        }    // namespace components
    }   // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_HPP