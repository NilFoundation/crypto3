//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tablain <d.tabalin@nil.foundation>
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

#pragma once

#include <vector>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/mock/mocked_component_base.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename BlueprintFieldType>
                struct one_var_type {
                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    typename non_native_policy_type::template field<BlueprintFieldType>::value_type a;

                    one_var_type(var _a) : a(_a) {}

                    template<typename ComponentType>
                    one_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : one_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {a};
                    }
                    static constexpr std::size_t result_size = 1;
                };

                template<typename BlueprintFieldType>
                struct two_var_type {
                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    typename non_native_policy_type::template field<BlueprintFieldType>::value_type a, b;

                    two_var_type(var _a, var _b) : a(_a), b(_b) {}

                    template<typename ComponentType>
                    two_var_type(const ComponentType &component, const std::size_t start_row_index)
                       : two_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {a, b};
                    }
                    static constexpr std::size_t result_size = 2;
                };

                template<typename BlueprintFieldType, std::size_t BitsAmount>
                struct signed_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<BitsAmount, BitsAmount,
                                nil::crypto3::multiprecision::signed_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type value;

                    signed_var_type(var sign, var mod) : value({sign, mod}) {}

                    template<typename ComponentType>
                    signed_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : signed_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {value[0], value[1]};
                    }
                    static constexpr std::size_t result_size = non_native_policy_type::ratio;
                };

                template<typename BlueprintFieldType, std::size_t BitsAmount>
                struct two_signed_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<BitsAmount, BitsAmount,
                                nil::crypto3::multiprecision::signed_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type a, b;

                    two_signed_var_type(var a_sign, var a_mod, var b_sign, var b_mod)
                        : a({a_sign, a_mod}), b({b_sign, b_mod}) {}

                    template<typename ComponentType>
                    two_signed_var_type(const ComponentType &component, const std::size_t start_row_index) {
                        return component.result_builder(start_row_index);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {a[0], a[1], b[0], b[1]};
                    }
                    static constexpr std::size_t result_size = 4;
                };


                template<typename BlueprintFieldType>
                struct pair_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<256, 256,
                                nil::crypto3::multiprecision::unsigned_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type value;

                    pair_var_type(var first, var second) : value({first, second}) {}

                    template<typename ComponentType>
                    pair_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : pair_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {value[0], value[1]};
                    }
                    static constexpr std::size_t result_size = 2;
                };

                template<typename BlueprintFieldType>
                struct two_pair_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<256, 256,
                                nil::crypto3::multiprecision::unsigned_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type a, b;

                    two_pair_var_type(var a_first, var a_second, var b_first, var b_second)
                        : a({a_first, a_second}), b({b_first, b_second}) {}

                    template<typename ComponentType>
                    two_pair_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : two_pair_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {a[0], a[1], b[0], b[1]};
                    }
                    static constexpr std::size_t result_size = 4;
                };

                template<typename BlueprintFieldType>
                struct signed_pair_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<256, 256,
                                nil::crypto3::multiprecision::signed_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type value;

                    signed_pair_var_type(var sign, var first, var second)
                        : value({sign, first, second}) {}

                    template<typename ComponentType>
                    signed_pair_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : signed_pair_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {value[0], value[1], value[2]};
                    }
                    static constexpr std::size_t result_size = 3;
                };

                template<typename BlueprintFieldType>
                struct two_signed_pair_var_type {
                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using non_native_policy_type =
                        nil::blueprint::detail::basic_non_native_policy_field_type<BlueprintFieldType,
                            nil::crypto3::multiprecision::number<
                                nil::crypto3::multiprecision::cpp_int_backend<256, 256,
                                nil::crypto3::multiprecision::signed_magnitude,
                                nil::crypto3::multiprecision::unchecked, void>>>;
                    typename non_native_policy_type::non_native_var_type a, b;

                    two_signed_pair_var_type(var a_sign, var a_first, var a_second, var b_sign, var b_first,
                                             var b_second)
                        : a({a_sign, a_first, a_second}), b({b_sign, b_first, b_second}) {}

                    template<typename ComponentType>
                    two_signed_pair_var_type(const ComponentType &component, const std::size_t start_row_index)
                        : two_signed_pair_var_type(component.result_builder(start_row_index)) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {a[0], a[1], a[2], b[0], b[1], b[2]};
                    }
                    static constexpr std::size_t result_size = 6;
                };
            }   // namespace detail

            #define BOILERPLATING(CLASS_NAME) \
                using input_type = typename component_type::input_type; \
                using result_type = typename component_type::result_type; \
                using value_type = typename BlueprintFieldType::value_type; \
                using integral_type = typename BlueprintFieldType::integral_type; \
                using var = typename component_type::var; \
 \
                const std::string component_name = #CLASS_NAME; \
 \
                template<typename ContainerType> \
                explicit CLASS_NAME (ContainerType witness) : \
                    component_type(witness, {}, {}) {}; \
 \
                template<typename WitnessContainerType, typename ConstantContainerType, \
                         typename PublicInputContainerType> \
                CLASS_NAME (WitnessContainerType witness, ConstantContainerType constant, \
                              PublicInputContainerType public_input) : \
                    component_type(witness, constant, public_input) {}; \
 \
                CLASS_NAME ( \
                    std::initializer_list<typename component_type::witness_container_type::value_type> \
                        witnesses, \
                    std::initializer_list<typename component_type::constant_container_type::value_type> \
                        constants, \
                    std::initializer_list<typename component_type::public_input_container_type::value_type> \
                        public_inputs) : \
                        component_type(witnesses, constants, public_inputs) {}; \

            // for BitsAmount < 256
            #define UNSIGNED_SMALL_OP_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t BitsAmount> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType, std::size_t BitsAmount> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType, BitsAmount> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<BitsAmount, BitsAmount, \
                        nil::crypto3::multiprecision::unsigned_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> uint_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        uint_type a = static_cast<uint_type>(var_value(assignment, instance_input.a).data), \
                                  b = static_cast<uint_type>(var_value(assignment, instance_input.b).data); \
                        return {value_type(OP(a, b))}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return var(0, start_row_index, false); \
                    } \
                }; \

            // for BitsAmount < 256
            #define SIGNED_SMALL_OP_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t BitsAmount> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType, std::size_t BitsAmount> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType, BitsAmount> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_var_type<BlueprintFieldType, BitsAmount>, \
                        detail::signed_var_type<BlueprintFieldType, BitsAmount>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_var_type<BlueprintFieldType, BitsAmount>, \
                        detail::signed_var_type<BlueprintFieldType, BitsAmount>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<BitsAmount, BitsAmount, \
                        nil::crypto3::multiprecision::signed_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> int_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        int_type a = static_cast<int_type>(var_value(assignment, instance_input.a[1]).data), \
                                 b = static_cast<int_type>(var_value(assignment, instance_input.b[1]).data); \
                        int_type sign_a = var_value(assignment, instance_input.a[0]) == 0 ? 1 : -1, \
                                 sign_b = var_value(assignment, instance_input.b[0]) == 0 ? 1 : -1; \
                        int_type result = OP((sign_a * a), (sign_b * b)); \
                        return {value_type(result.sign() >= 0 ? 0 : 1), \
                                value_type(nil::crypto3::multiprecision::abs(result))}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return {var(0, start_row_index, false), \
                                var(1, start_row_index, false)}; \
                    } \
                }; \

            template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t BitsAmount>
            class signed_abs_component_small;

            template<typename BlueprintFieldType, std::size_t BitsAmount>
            class signed_abs_component_small<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType, BitsAmount> : public mocked_component_base<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    detail::signed_var_type<BlueprintFieldType, BitsAmount>,
                    detail::signed_var_type<BlueprintFieldType, BitsAmount>> {
            public:
                using component_type = mocked_component_base<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    detail::signed_var_type<BlueprintFieldType, BitsAmount>,
                    detail::signed_var_type<BlueprintFieldType, BitsAmount>>;

                typedef nil::crypto3::multiprecision::number<
                    nil::crypto3::multiprecision::cpp_int_backend<BitsAmount, BitsAmount,
                    nil::crypto3::multiprecision::signed_magnitude,
                    nil::crypto3::multiprecision::unchecked, void>> int_type;

                BOILERPLATING(signed_abs_component_small)

                std::array<value_type, result_type::result_size> result_values_calculator(
                    const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const input_type &instance_input) const override {

                    return {value_type(0), var_value(assignment, instance_input.value[1])};
                }

                result_type result_builder(const std::size_t start_row_index) const override {

                    return {var(0, start_row_index, false),
                            var(1, start_row_index, false)};
                }
            };

            // for BitsAmount == 256
            #define UNSIGNED_BIG_OP_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_pair_var_type<BlueprintFieldType>, \
                        detail::pair_var_type<BlueprintFieldType>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_pair_var_type<BlueprintFieldType>, \
                        detail::pair_var_type<BlueprintFieldType>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<256, 256, \
                        nil::crypto3::multiprecision::unsigned_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> uint_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        static const uint_type two_128 = \
                            nil::crypto3::multiprecision::pow(uint_type(2), 128); \
                        static const uint_type top_mask = ((uint_type(1) << 128) - 1) << 128; \
                        static const uint_type bottom_mask = (uint_type(1) << 128) - 1; \
                        uint_type \
                            a = static_cast<uint_type>(var_value(assignment, instance_input.a[0]).data) * two_128 + \
                                static_cast<uint_type>(var_value(assignment, instance_input.a[1]).data), \
                            b = static_cast<uint_type>(var_value(assignment, instance_input.b[0]).data) * two_128 + \
                                static_cast<uint_type>(var_value(assignment, instance_input.b[1]).data); \
                        uint_type result = OP(a, b); \
                        return {value_type((top_mask & result) >> 128), value_type(bottom_mask & result)}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return {var(0, start_row_index, false), \
                                var(1, start_row_index, false)}; \
                    } \
                }; \

            // for BitsAmount == 256
            #define UNSIGNED_BIG_OP_BOOL_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_pair_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_pair_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<256, 256, \
                        nil::crypto3::multiprecision::unsigned_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> uint_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        static const uint_type two_128 = \
                            nil::crypto3::multiprecision::pow(uint_type(2), 128); \
                        uint_type \
                            a = static_cast<uint_type>(var_value(assignment, instance_input.a[0]).data) * two_128 + \
                                static_cast<uint_type>(var_value(assignment, instance_input.a[1]).data), \
                            b = static_cast<uint_type>(var_value(assignment, instance_input.b[0]).data) * two_128 + \
                                static_cast<uint_type>(var_value(assignment, instance_input.b[1]).data); \
                        uint_type result = OP(a, b); \
                        return {value_type(result)}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return {var(0, start_row_index, false)}; \
                    } \
                }; \

            // for BitsAmount == 256
            #define SIGNED_BIG_OP_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_pair_var_type<BlueprintFieldType>, \
                        detail::signed_pair_var_type<BlueprintFieldType>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_pair_var_type<BlueprintFieldType>, \
                        detail::signed_pair_var_type<BlueprintFieldType>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<256, 256, \
                        nil::crypto3::multiprecision::signed_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> int_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        static const int_type two_128 = \
                            nil::crypto3::multiprecision::pow(int_type(2), 128); \
                        static const int_type top_mask = ((int_type(1) << 128) - 1) << 128; \
                        static const int_type bottom_mask = (int_type(1) << 128) - 1; \
                        int_type \
                            a = (var_value(assignment, instance_input.a[0]) == 0 ? 1 : -1) * \
                                static_cast<int_type>(var_value(assignment, instance_input.a[1]).data) * two_128 + \
                                static_cast<int_type>(var_value(assignment, instance_input.a[2]).data), \
                            b = (var_value(assignment, instance_input.b[0]) == 0 ? 1 : -1) * \
                                static_cast<int_type>(var_value(assignment, instance_input.b[1]).data) * two_128 + \
                                static_cast<int_type>(var_value(assignment, instance_input.b[2]).data); \
                        int_type result = OP(a, b); \
                        return {value_type(result.sign() >= 0 ? 0 : 1), \
                                value_type((top_mask & result) >> 128), value_type(bottom_mask & result)}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return {var(0, start_row_index, false), \
                                var(1, start_row_index, false), \
                                var(2, start_row_index, false)}; \
                    } \
                }; \

            // for BitsAmount == 256
            #define SIGNED_BIG_BOOL_OP_COMPONENT(COMPONENT_NAME, OP) \
                template<typename ArithmetizationType, typename BlueprintFieldType> \
                class COMPONENT_NAME; \
 \
                template<typename BlueprintFieldType> \
                class COMPONENT_NAME< \
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                    BlueprintFieldType> : public mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_pair_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>> { \
                public: \
                    using component_type = mocked_component_base< \
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, \
                        detail::two_signed_pair_var_type<BlueprintFieldType>, \
                        detail::one_var_type<BlueprintFieldType>>; \
 \
                    typedef nil::crypto3::multiprecision::number< \
                        nil::crypto3::multiprecision::cpp_int_backend<256, 256, \
                        nil::crypto3::multiprecision::signed_magnitude, \
                        nil::crypto3::multiprecision::unchecked, void>> int_type; \
 \
                    BOILERPLATING(COMPONENT_NAME) \
 \
                    std::array<value_type, result_type::result_size> result_values_calculator( \
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> \
                            &assignment, \
                        const input_type &instance_input) const override { \
 \
                        static const int_type two_128 = \
                            nil::crypto3::multiprecision::pow(int_type(2), 128); \
                        int_type \
                            a = (var_value(assignment, instance_input.a[0]) == 0 ? 1 : -1) * \
                                static_cast<int_type>(var_value(assignment, instance_input.a[1]).data) * two_128 + \
                                static_cast<int_type>(var_value(assignment, instance_input.a[2]).data), \
                            b = (var_value(assignment, instance_input.b[0]) == 0 ? 1 : -1) * \
                                static_cast<int_type>(var_value(assignment, instance_input.b[1]).data) * two_128 + \
                                static_cast<int_type>(var_value(assignment, instance_input.b[2]).data); \
                        return {OP(a, b)}; \
                    } \
 \
                    result_type result_builder(const std::size_t start_row_index) const override { \
 \
                        return {var(0, start_row_index, false)}; \
                    } \
                }; \

            template<typename ArithmetizationType, typename BlueprintFieldType>
            class signed_abs_component_big;

            template<typename BlueprintFieldType>
            class signed_abs_component_big<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType> : public mocked_component_base<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    detail::signed_pair_var_type<BlueprintFieldType>,
                    detail::signed_pair_var_type<BlueprintFieldType>> {
            public:
                using component_type = mocked_component_base<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    detail::signed_pair_var_type<BlueprintFieldType>,
                    detail::signed_pair_var_type<BlueprintFieldType>>;

                typedef nil::crypto3::multiprecision::number<
                    nil::crypto3::multiprecision::cpp_int_backend<256, 256,
                    nil::crypto3::multiprecision::signed_magnitude,
                    nil::crypto3::multiprecision::unchecked, void>> int_type;

                BOILERPLATING(signed_abs_component_big)

                std::array<value_type, result_type::result_size> result_values_calculator(
                    const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const input_type &instance_input) const override {

                    return {value_type(0),
                            var_value(assignment, instance_input.value[1]),
                            var_value(assignment, instance_input.value[2])};
                }

                result_type result_builder(const std::size_t start_row_index) const override {

                    return {var(0, start_row_index, false),
                            var(1, start_row_index, false),
                            var(2, start_row_index, false)};
                }
            };

            #define OP_ADDITION(a, b) (a + b)
            #define OP_SUBTRACTION(a, b) (a - b)
            #define OP_MULTIPLICATION(a, b) (a * b)
            #define OP_DIVISION(a, b) (a / b)
            #define OP_REMAINDER(a, b) (a % b)
            #define OP_LESS(a, b) (a < b)
            #define OP_GREATER(a, b) (a > b)
            #define OP_GREATER_EQUAL(a, b) (a >= b)
            #define OP_LESS_EQUAL(a, b) (a <= b)

            UNSIGNED_SMALL_OP_COMPONENT(unsigned_addition_component_small, OP_ADDITION)
            UNSIGNED_SMALL_OP_COMPONENT(unsigned_subtraction_component_small, OP_SUBTRACTION)
            UNSIGNED_SMALL_OP_COMPONENT(unsigned_multiplication_component_small, OP_MULTIPLICATION)
            UNSIGNED_SMALL_OP_COMPONENT(unsigned_division_component_small, OP_DIVISION)
            UNSIGNED_SMALL_OP_COMPONENT(unsigned_remainder_component_small, OP_REMAINDER)

            UNSIGNED_BIG_OP_COMPONENT(unsigned_addition_component_big, OP_ADDITION)
            UNSIGNED_BIG_OP_COMPONENT(unsigned_subtraction_component_big, OP_SUBTRACTION)
            UNSIGNED_BIG_OP_COMPONENT(unsigned_multiplication_component_big, OP_MULTIPLICATION)
            UNSIGNED_BIG_OP_COMPONENT(unsigned_division_component_big, OP_DIVISION)
            UNSIGNED_BIG_OP_COMPONENT(unsigned_remainder_component_big, OP_REMAINDER)

            UNSIGNED_BIG_OP_BOOL_COMPONENT(unsinged_less_component_big, OP_LESS)
            UNSIGNED_BIG_OP_BOOL_COMPONENT(unsinged_greater_component_big, OP_GREATER)
            UNSIGNED_BIG_OP_BOOL_COMPONENT(unsinged_greater_equal_component_big, OP_GREATER_EQUAL)
            UNSIGNED_BIG_OP_BOOL_COMPONENT(unsinged_less_equal_component_big, OP_LESS_EQUAL)

            SIGNED_SMALL_OP_COMPONENT(signed_addition_component_small, OP_ADDITION)
            SIGNED_SMALL_OP_COMPONENT(signed_subtraction_component_small, OP_SUBTRACTION)
            SIGNED_SMALL_OP_COMPONENT(signed_multiplication_component_small, OP_MULTIPLICATION)
            SIGNED_SMALL_OP_COMPONENT(signed_division_component_small, OP_DIVISION)
            SIGNED_SMALL_OP_COMPONENT(signed_remainder_component_small, OP_REMAINDER)

            SIGNED_BIG_OP_COMPONENT(signed_addition_component_big, OP_ADDITION)
            SIGNED_BIG_OP_COMPONENT(signed_subtraction_component_big, OP_SUBTRACTION)
            SIGNED_BIG_OP_COMPONENT(signed_multiplication_component_big, OP_MULTIPLICATION)
            SIGNED_BIG_OP_COMPONENT(signed_division_component_big, OP_DIVISION)
            SIGNED_BIG_OP_COMPONENT(signed_remainder_component_big, OP_REMAINDER)

            SIGNED_BIG_BOOL_OP_COMPONENT(signed_less_component_big, OP_LESS)
            SIGNED_BIG_BOOL_OP_COMPONENT(signed_greater_component_big, OP_GREATER)
            SIGNED_BIG_BOOL_OP_COMPONENT(signed_greater_equal_component_big, OP_GREATER_EQUAL)
            SIGNED_BIG_BOOL_OP_COMPONENT(signed_less_equal_component_big, OP_LESS_EQUAL)

            #undef BOILERPLATING
            #undef UNSIGNED_SMALL_OP_COMPONENT
            #undef SIGNED_SMALL_OP_COMPONENT
            #undef UNSIGNED_BIG_OP_COMPONENT
            #undef UNSIGNED_BIG_OP_BOOL_COMPONENT
            #undef SIGNED_BIG_OP_COMPONENT
            #undef SIGNED_BIG_BOOL_OP_COMPONENT

            #undef OP_ADDITION
            #undef OP_SUBTRACTION
            #undef OP_MULTIPLICATION
            #undef OP_DIVISION
            #undef OP_REMAINDER
            #undef OP_LESS
            #undef OP_GREATER
            #undef OP_GREATER_EQUAL
            #undef OP_LESS_EQUAL
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
