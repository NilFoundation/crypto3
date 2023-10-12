//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TEST_PLONK_COMPONENT_HPP
#define CRYPTO3_TEST_PLONK_COMPONENT_HPP

#include <fstream>
#include <random>
#include <functional>
#include <utility>
#include <map>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/padding.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
//#include <nil/blueprint/utils/table_profiling.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/utils/connectedness_check.hpp>

#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

// #include "profiling_plonk_circuit.hpp"

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <functional>
#include <utility>
#include <map>

namespace nil {
    namespace crypto3 {
        namespace detail {
            enum class connectedness_check_type {
                NONE,
                WEAK,
                STRONG
            };
        }   // namespace detail

        inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
            using dist_type = std::uniform_int_distribution<int>;
            static std::random_device random_engine;

            std::vector<std::size_t> step_list;
            std::size_t steps_sum = 0;
            while (steps_sum != r) {
                if (r - steps_sum <= max_step) {
                    while (r - steps_sum != 1) {
                        step_list.emplace_back(r - steps_sum - 1);
                        steps_sum += step_list.back();
                    }
                    step_list.emplace_back(1);
                    steps_sum += step_list.back();
                } else {
                    step_list.emplace_back(dist_type(1, max_step)(random_engine));
                    steps_sum += step_list.back();
                }
            }
            return step_list;
        }

        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
            typename fri_type::params_type params;
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            constexpr std::size_t expand_factor = 0;
            std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
                math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            params.r = r;
            params.D = domain_set;
            params.max_degree = (1 << degree_log) - 1;
            params.step_list = generate_random_step_list(r, max_step);

            return params;
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams>
        class plonk_test_assigner {
        public:
            virtual typename ComponentType::result_type operator()(
                const ComponentType&,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                            ArithmetizationParams>>&,
                const typename ComponentType::input_type&,
                const std::uint32_t) const = 0;
        };

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams>
        class plonk_test_default_assigner :
            public plonk_test_assigner<ComponentType, BlueprintFieldType, ArithmetizationParams> {
        public:
            typename ComponentType::result_type operator()(
                const ComponentType &component,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                            ArithmetizationParams>>
                    &assignment,
                const typename ComponentType::input_type &instance_input,
                const std::uint32_t start_row_index) const override {

                return blueprint::components::generate_assignments<BlueprintFieldType,
                                                                   ArithmetizationParams>(
                            component, assignment, instance_input, start_row_index);
            }
        };

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams>
        class plonk_test_custom_assigner :
            public plonk_test_assigner<ComponentType, BlueprintFieldType, ArithmetizationParams> {

            using assigner_type =
                std::function<typename ComponentType::result_type(
                    const ComponentType&,
                    nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                            ArithmetizationParams>>&,
                    const typename ComponentType::input_type&,
                    const std::uint32_t)>;
            assigner_type assigner;
        public:
            plonk_test_custom_assigner(assigner_type assigner) : assigner(assigner) {};

            typename ComponentType::result_type operator()(
                const ComponentType &component,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                            ArithmetizationParams>>
                    &assignment,
                const typename ComponentType::input_type &instance_input,
                const std::uint32_t start_row_index) const override {

                return this->assigner(component, assignment, instance_input, start_row_index);
            }
        };

        template<
            typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
            std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, bool PrivateInput,
            typename... ComponentStaticInfoArgs>
        auto prepare_component(ComponentType component_instance, const PublicInputContainerType &public_input,
                               const FunctorResultCheck &result_check,
                               const plonk_test_assigner<ComponentType, BlueprintFieldType,
                                                         ArithmetizationParams> &assigner,
                               typename ComponentType::input_type instance_input,
                               bool expected_to_pass,
                               detail::connectedness_check_type connectedness_check,
                               ComponentStaticInfoArgs... component_static_info_args) {

            using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using component_type = ComponentType;

            blueprint::circuit<ArithmetizationType> bp;
            blueprint::assignment<ArithmetizationType> assignment;

            static boost::random::mt19937 gen;
            static boost::random::uniform_int_distribution<> dist(0, 100);
            std::size_t start_row = dist(gen);

            if constexpr (PrivateInput) {
                for (std::size_t i = 0; i < public_input.size(); i++) {
                    assignment.private_storage(i) = public_input[i];
                }
            } else {
                for (std::size_t i = 0; i < public_input.size(); i++) {
                    assignment.public_input(0, i) = public_input[i];
                }
            }

            blueprint::components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                component_instance, bp, assignment, instance_input, start_row);

            auto component_result = boost::get<typename component_type::result_type>(
                assigner(component_instance, assignment, instance_input, start_row));
            result_check(assignment, component_result);

            if constexpr (!PrivateInput) {
                bool is_connected;
                if (connectedness_check == detail::connectedness_check_type::STRONG) {
                    is_connected = check_strong_connectedness(
                        assignment,
                        bp,
                        instance_input.all_vars(),
                        component_result.all_vars(), start_row, component_instance.rows_amount);
                } else if (connectedness_check == detail::connectedness_check_type::WEAK) {
                    is_connected = check_weak_connectedness(
                        assignment,
                        bp,
                        instance_input.all_vars(),
                        component_result.all_vars(), start_row, component_instance.rows_amount);
                } else if (connectedness_check == detail::connectedness_check_type::NONE) {
                    is_connected = true;
                    std::cout << "WARNING: connectedness check disabled" << std::endl;
                }

                // Uncomment the following if you want to output a visual representation of the connectedness graph.
                // I recommend turning off the starting row randomization

                // auto zones = blueprint::detail::generate_connectedness_zones(
                //      assignment, bp, instance_input.all_vars(), start_row, component_instance.rows_amount);
                // blueprint::detail::export_connectedness_zones(
                //      zones, assignment, instance_input.all_vars(), start_row, component_instance.rows_amount, std::cout);

                BOOST_ASSERT_MSG(is_connected,
                    "Component disconnected! See comment above this assert for a way to output a visual representation of the connectedness graph.");
            }

            zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;
            desc.usable_rows_amount = assignment.rows_amount();

            if (start_row + component_instance.rows_amount >= public_input.size()) {
                BOOST_ASSERT_MSG(assignment.rows_amount() - start_row == component_instance.rows_amount,
                                "Component rows amount does not match actual rows amount.");
                // Stretched components do not have a manifest, as they are dynamically generated.
                if constexpr (!blueprint::components::is_component_stretcher<
                                    BlueprintFieldType, ArithmetizationParams, ComponentType>::value) {
                    BOOST_ASSERT_MSG(assignment.rows_amount() - start_row ==
                                    component_type::get_rows_amount(component_instance.witness_amount(), 0,
                                                                    component_static_info_args...),
                                    "Static component rows amount does not match actual rows amount.");
                }
            }
            // Stretched components do not have a manifest, as they are dynamically generated.
            if constexpr (!blueprint::components::is_component_stretcher<
                                    BlueprintFieldType, ArithmetizationParams, ComponentType>::value) {
                BOOST_ASSERT_MSG(bp.num_gates() ==
                                component_type::get_gate_manifest(component_instance.witness_amount(), 0,
                                                                component_static_info_args...).get_gates_amount(),
                                "Component total gates amount does not match actual gates amount.");
            }

            desc.rows_amount = zk::snark::basic_padding(assignment);

#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            profiling(assignment);
#endif

            assert(blueprint::is_satisfied(bp, assignment) == expected_to_pass);

            return std::make_tuple(desc, bp, assignment);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, bool PrivateInput,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_inner(ComponentType component_instance, const PublicInputContainerType &public_input,
                            const FunctorResultCheck &result_check,
                            const plonk_test_assigner<ComponentType, BlueprintFieldType, ArithmetizationParams>
                                &assigner,
                            const typename ComponentType::input_type &instance_input,
                            bool expected_to_pass,
                            detail::connectedness_check_type connectedness_check,
                            ComponentStaticInfoArgs... component_static_info_args) {
            auto [desc, bp, assignments] =
                prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                  PublicInputContainerType, FunctorResultCheck, PrivateInput,
                                  ComponentStaticInfoArgs...>
                                  (component_instance, public_input, result_check, assigner, instance_input,
                                   expected_to_pass, connectedness_check, component_static_info_args...);

#ifdef BLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED
            using placeholder_params =
                zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params>;

            using fri_type =
                typename zk::commitments::fri<BlueprintFieldType, typename placeholder_params::merkle_hash_type,
                                              typename placeholder_params::transcript_hash_type, Lambda, 2, 4>;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

            std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

            typename zk::snark::placeholder_public_preprocessor<
                BlueprintFieldType, placeholder_params>::preprocessed_data_type public_preprocessed_data =
                zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::process(
                    bp, assignments.public_table(), desc, fri_params, permutation_size);
            typename zk::snark::placeholder_private_preprocessor<
                BlueprintFieldType, placeholder_params>::preprocessed_data_type private_preprocessed_data =
                zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::process(
                    bp, assignments.private_table(), desc, fri_params);
            auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
                public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

            bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
                public_preprocessed_data, proof, bp, fri_params);

            if (expected_to_pass) {
                BOOST_CHECK(verifier_res);
            } else {
                BOOST_CHECK(!verifier_res);
            }
#endif
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component(ComponentType component_instance, const PublicInputContainerType &public_input,
                           FunctorResultCheck result_check,
                           typename ComponentType::input_type instance_input,
                           detail::connectedness_check_type connectedness_check =
                            detail::connectedness_check_type::STRONG,
                           ComponentStaticInfoArgs... component_static_info_args) {
            return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false,
                                 ComponentStaticInfoArgs...>(
                                    component_instance, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType,
                                                                ArithmetizationParams>(),
                                    instance_input, true, connectedness_check, component_static_info_args...);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail(ComponentType component_instance, const PublicInputContainerType &public_input,
                           FunctorResultCheck result_check,
                           typename ComponentType::input_type instance_input,
                           detail::connectedness_check_type connectedness_check =
                            detail::connectedness_check_type::STRONG,
                           ComponentStaticInfoArgs... component_static_info_args) {
            return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>(
                                    component_instance, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType,
                                                                ArithmetizationParams>(),
                                    instance_input, false, connectedness_check, component_static_info_args...);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_custom_assignments(ComponentType component_instance,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            const plonk_test_custom_assigner<ComponentType, BlueprintFieldType,
                                                             ArithmetizationParams> &custom_assigner,
                            typename ComponentType::input_type instance_input,
                            detail::connectedness_check_type connectedness_check =
                                detail::connectedness_check_type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>
                                    (component_instance, public_input, result_check, custom_assigner,
                                     instance_input, true, connectedness_check, component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail_custom_assignments(ComponentType component_instance,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            const plonk_test_custom_assigner<ComponentType, BlueprintFieldType,
                                                             ArithmetizationParams> &custom_assigner,
                            typename ComponentType::input_type instance_input,
                            detail::connectedness_check_type connectedness_check =
                                detail::connectedness_check_type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>
                                    (component_instance, public_input, result_check, custom_assigner,
                                     instance_input, false,  connectedness_check,component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_private_input(ComponentType component_instance,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            typename ComponentType::input_type instance_input,
                            detail::connectedness_check_type connectedness_check =
                                detail::connectedness_check_type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, true , ComponentStaticInfoArgs...>
                                    (component_instance, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType,
                                                                ArithmetizationParams>(),
                                    instance_input, true, connectedness_check, component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail_private_input(ComponentType component_instance,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            typename ComponentType::input_type instance_input,
                            detail::connectedness_check_type connectedness_check =
                                detail::connectedness_check_type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, true , ComponentStaticInfoArgs...>
                                    (component_instance, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType,
                                                                ArithmetizationParams>(),
                                    instance_input, false, connectedness_check, component_static_info_args...);
            }

        /*
            Most of the time while testing we do not want to generate an entire set of assignments from scratch.
            This function wraps the generate_assignments call for the component, and patches the passed
            coordinate/value pairs into the result.
        */
        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        std::function<typename ComponentType::result_type(
                const ComponentType&,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                        ArithmetizationParams>>&,
                const typename ComponentType::input_type&,
                const std::uint32_t)>
            generate_patched_assignments(
                const std::map<std::pair<std::size_t, std::size_t>, typename BlueprintFieldType::value_type>
                    &patches) {

            return [&patches]
                    (const ComponentType &component,
                     nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                ArithmetizationParams>>
                         &assignment,
                     const typename ComponentType::input_type &instance_input,
                     const std::uint32_t start_row_index) {
                typename ComponentType::result_type result =
                    blueprint::components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                        component, assignment, instance_input, start_row_index);

                for (const auto &patch : patches) {
                    assignment.witness(component.W(patch.first.second), patch.first.first + start_row_index) =
                        patch.second;
                }

                return result;
            };
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TEST_PLONK_COMPONENT_HPP