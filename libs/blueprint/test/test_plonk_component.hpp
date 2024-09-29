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

#pragma once

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
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>
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
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType>
            std::tuple<
                nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>
                    generate_empty_assignments();
        }
    }

    namespace crypto3 {
        inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const std::size_t max_step) {
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

        template<typename ComponentType, typename BlueprintFieldType>
        class plonk_test_assigner {
        public:
            virtual typename ComponentType::result_type operator()(
                const ComponentType&,
                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&,
                const typename ComponentType::input_type&,
                const std::uint32_t) const = 0;
        };

        template<typename ComponentType, typename BlueprintFieldType>
        class plonk_test_default_assigner :
            public plonk_test_assigner<ComponentType, BlueprintFieldType> {
        public:
            typename ComponentType::result_type operator()(
                const ComponentType &component,
                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename ComponentType::input_type &instance_input,
                const std::uint32_t start_row_index) const override {

                return blueprint::components::generate_assignments<BlueprintFieldType>(
                            component, assignment, instance_input, start_row_index);
            }
        };

        template<typename ComponentType, typename BlueprintFieldType>
        class plonk_test_custom_assigner :
            public plonk_test_assigner<ComponentType, BlueprintFieldType> {

            using assigner_type =
                std::function<typename ComponentType::result_type(
                    const ComponentType&,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&,
                    const typename ComponentType::input_type&,
                    const std::uint32_t)>;
            assigner_type assigner;
        public:
            plonk_test_custom_assigner(assigner_type assigner) : assigner(assigner) {};

            typename ComponentType::result_type operator()(
                const ComponentType &component,
                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename ComponentType::input_type &instance_input,
                const std::uint32_t start_row_index) const override {

                return this->assigner(component, assignment, instance_input, start_row_index);
            }
        };

        template<
            typename ComponentType, typename BlueprintFieldType, typename Hash,
            std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, bool PrivateInput,
            typename... ComponentStaticInfoArgs>
        auto prepare_component(ComponentType component_instance,
                               zk::snark::plonk_table_description<BlueprintFieldType> desc,
                               const PublicInputContainerType &public_input,
                               const FunctorResultCheck &result_check,
                               const plonk_test_assigner<ComponentType, BlueprintFieldType> &assigner,
                               typename ComponentType::input_type instance_input,
                               bool expected_to_pass,
                               blueprint::connectedness_check_type connectedness_check,
                               ComponentStaticInfoArgs... component_static_info_args) {
            using component_type = ComponentType;
            blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> bp;
            blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> assignment(desc);

            if constexpr( nil::blueprint::use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    if( v == 1 )
                        bp.reserve_dynamic_table(k);
                    else
                        bp.reserve_table(k);
                }
            };

            static boost::random::mt19937 gen;
            static boost::random::uniform_int_distribution<> dist(0, 100);
            //std::size_t start_row = 0; //dist(gen);
            std::size_t start_row = dist(gen);
            // resize to ensure that if the component is empty by default (e.g. a component which only uses batching)
            if (start_row != 0) {
                assignment.witness(0, start_row - 1) = 0u;
            }

            if constexpr (PrivateInput) {
                for (std::size_t i = 0; i < public_input.size(); i++) {
                    assignment.private_storage(i) = public_input[i];
                }
            } else {
                for (std::size_t i = 0; i < public_input.size(); i++) {
                    assignment.public_input(0, i) = public_input[i];
                }
            }

            blueprint::components::generate_circuit<BlueprintFieldType>(
                component_instance, bp, assignment, instance_input, start_row);
            auto component_result = boost::get<typename component_type::result_type>(
                assigner(component_instance, assignment, instance_input, start_row));

            // Stretched components do not have a manifest, as they are dynamically generated.
            if constexpr (!blueprint::components::is_component_stretcher<
                                    BlueprintFieldType, ComponentType>::value) {
                BOOST_ASSERT_MSG(bp.num_gates() + bp.num_lookup_gates() ==
                                component_type::get_gate_manifest(component_instance.witness_amount(),
                                                                  component_static_info_args...).get_gates_amount(),
                                "Component total gates amount does not match actual gates amount.");
            }

            if (start_row + component_instance.rows_amount >= public_input.size()) {
                BOOST_ASSERT_MSG(assignment.rows_amount() - start_row == component_instance.rows_amount,
                                "Component rows amount does not match actual rows amount.");
                // Stretched components do not have a manifest, as they are dynamically generated.
                if constexpr (!blueprint::components::is_component_stretcher<
                                    BlueprintFieldType, ComponentType>::value) {
                    BOOST_ASSERT_MSG(assignment.rows_amount() - start_row ==
                                    component_type::get_rows_amount(component_instance.witness_amount(),
                                                                    component_static_info_args...),
                                    "Static component rows amount does not match actual rows amount.");
                }
            }

            const std::size_t rows_after_component_batching =
                assignment.finalize_component_batches(bp, start_row + component_instance.rows_amount);
            const std::size_t rows_after_const_batching =
                assignment.finalize_constant_batches(bp, 0, std::max<std::size_t>(start_row, 1));
            const std::size_t rows_after_batching = std::max(rows_after_component_batching, rows_after_const_batching);
            for (auto variable : component_result.all_vars()) {
                if (assignment.get_batch_variable_map().count(variable)) {
                    variable.get() = assignment.get_batch_variable_map().at(variable);
                }
            }

            result_check(assignment, component_result);

            if constexpr (!PrivateInput) {
                bool is_connected = check_connectedness(
                    assignment,
                    bp,
                    instance_input.all_vars(),
                    component_result.all_vars(), start_row, rows_after_batching - start_row,
                    connectedness_check);
                if (connectedness_check.t == blueprint::connectedness_check_type::type::NONE) {
                    // std::cout << "WARNING: Connectedness check is disabled." << std::endl;
                }

                // Uncomment the following if you want to output a visual representation of the connectedness graph.
                // I recommend turning off the starting row randomization
                // If the whole of public_input isn't shown, increase the end row

                // auto zones = blueprint::detail::generate_connectedness_zones(
                //      assignment, bp, instance_input.all_vars(), start_row, rows_after_batching - start_row);
                // blueprint::detail::export_connectedness_zones(
                //      zones, assignment, instance_input.all_vars(), start_row, rows_after_batching - start_row, std::cout);

                // BOOST_ASSERT_MSG(is_connected,
                //   "Component disconnected! See comment above this assert for a way to output a visual representation of the connectedness graph.");
            }
            desc.usable_rows_amount = assignment.rows_amount();

            if constexpr (nil::blueprint::use_lookups<component_type>()) {
                // Components with lookups may use constant columns.
                // But now all constants are placed in the first column.
                // So we reserve the first column for non-lookup constants.
                // Rather universal for testing
                // We may start from zero if component doesn't use ordinary constants.
                std::vector<size_t> lookup_columns_indices;
                for(std::size_t i = 1; i < assignment.constants_amount(); i++) {
                    lookup_columns_indices.push_back(i);
                }

                std::size_t cur_selector_id = 0;
                for(const auto &gate: bp.gates()){
                    cur_selector_id = std::max(cur_selector_id, gate.selector_index);
                }
                for(const auto &lookup_gate: bp.lookup_gates()){
                    cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
                }
                cur_selector_id++;
                desc.usable_rows_amount = zk::snark::pack_lookup_tables_horizontal(
                    bp.get_reserved_indices(),
                    bp.get_reserved_tables(),
                    bp.get_reserved_dynamic_tables(),
                    bp, assignment, lookup_columns_indices, cur_selector_id,
                    desc.usable_rows_amount,
                    500000
                );
            }
            desc.rows_amount = zk::snark::basic_padding(assignment);

#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            profiling(assignment);
#endif
            // assignment.export_table(std::cout);
            // bp.export_circuit(std::cout);

            assert(blueprint::is_satisfied(bp, assignment) == expected_to_pass);
            return std::make_tuple(desc, bp, assignment);
        }

        template<
            typename ComponentType, typename BlueprintFieldType, typename Hash,
            std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, bool PrivateInput,
            typename... ComponentStaticInfoArgs>
        auto prepare_empty_component(ComponentType component_instance,
                               const zk::snark::plonk_table_description<BlueprintFieldType> &desc,
                               const PublicInputContainerType &public_input,
                               const FunctorResultCheck &result_check,
                               typename ComponentType::input_type instance_input,
                               blueprint::connectedness_check_type connectedness_check,
                               ComponentStaticInfoArgs... component_static_info_args) {
            using component_type = ComponentType;

            blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> bp;
            blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> assignment(desc);

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

            auto component_result = boost::get<typename component_type::result_type>(
                blueprint::components::generate_empty_assignments<BlueprintFieldType>(
                component_instance, assignment, instance_input, start_row));
            // assignment.export_table(std::cout);
            // bp.export_circuit(std::cout);
            result_check(assignment, component_result);

            BOOST_ASSERT(bp.num_gates() == 0);
            BOOST_ASSERT(bp.num_lookup_gates() == 0);

            return std::make_tuple(desc, bp, assignment);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_empty_component(ComponentType component_instance,
                           zk::snark::plonk_table_description<BlueprintFieldType> input_desc,
                           const PublicInputContainerType &public_input,
                           FunctorResultCheck result_check,
                           typename ComponentType::input_type instance_input,
                           blueprint::connectedness_check_type connectedness_check =
                            blueprint::connectedness_check_type::type::STRONG,
                           ComponentStaticInfoArgs... component_static_info_args) {
            auto [desc, bp, assignments] =
                prepare_empty_component<ComponentType, BlueprintFieldType, Hash, Lambda,
                                PublicInputContainerType, FunctorResultCheck, false,
                                ComponentStaticInfoArgs...>
                                (component_instance, input_desc, public_input, result_check, instance_input,
                                connectedness_check, component_static_info_args...);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, bool PrivateInput,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_inner(ComponentType component_instance,
                            zk::snark::plonk_table_description<BlueprintFieldType> input_desc,
                            const PublicInputContainerType &public_input,
                            const FunctorResultCheck &result_check,
                            const plonk_test_assigner<ComponentType, BlueprintFieldType>
                                &assigner,
                            const typename ComponentType::input_type &instance_input,
                            bool expected_to_pass,
                            blueprint::connectedness_check_type connectedness_check,
                            ComponentStaticInfoArgs... component_static_info_args) {
            auto [desc, bp, assignments] =
                prepare_component<ComponentType, BlueprintFieldType, Hash, Lambda,
                                  PublicInputContainerType, FunctorResultCheck, PrivateInput,
                                  ComponentStaticInfoArgs...>
                                  (component_instance, input_desc, public_input, result_check, assigner, instance_input,
                                   expected_to_pass, connectedness_check, component_static_info_args...);

// How to define it from crypto3 cmake?
//#define BLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED
#ifdef BLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED
            using circuit_params = typename nil::crypto3::zk::snark::placeholder_circuit_params<BlueprintFieldType>;
            using lpc_params_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment_params<
                Hash, Hash, 2
            >;

            using commitment_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment<BlueprintFieldType, lpc_params_type>;
            using commitment_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<commitment_type>;
            using placeholder_params_type = typename nil::crypto3::zk::snark::placeholder_params<circuit_params, commitment_scheme_type>;

            using fri_type = typename commitment_type::fri_type;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params(1,table_rows_log, Lambda, 2);
            commitment_scheme_type lpc_scheme(fri_params);

            typename nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::preprocessed_data_type
                preprocessed_public_data = nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
                    bp, assignments.public_table(), desc, lpc_scheme
                );

            typename nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::preprocessed_data_type
                preprocessed_private_data = nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
                    bp, assignments.private_table(), desc
                );

            auto proof = nil::crypto3::zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params_type>::process(
                preprocessed_public_data, preprocessed_private_data, desc, bp, lpc_scheme
            );

            bool verifier_res = nil::crypto3::zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params_type>::process(
                preprocessed_public_data.common_data, proof, desc, bp, lpc_scheme
            );

            if (expected_to_pass) {
                BOOST_ASSERT(verifier_res);
            }
            else {
                BOOST_ASSERT(!verifier_res);
            }
#endif
        }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component(ComponentType component_instance,
                           zk::snark::plonk_table_description<BlueprintFieldType> desc,
                           const PublicInputContainerType &public_input,
                           FunctorResultCheck result_check,
                           typename ComponentType::input_type instance_input,
                           blueprint::connectedness_check_type connectedness_check =
                            blueprint::connectedness_check_type::type::STRONG,
                           ComponentStaticInfoArgs... component_static_info_args) {
            return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false,
                                 ComponentStaticInfoArgs...>(
                                    component_instance, desc, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType>(),
                                    instance_input, true, connectedness_check, component_static_info_args...);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck, typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail(ComponentType component_instance,
                           zk::snark::plonk_table_description<BlueprintFieldType> desc,
                           const PublicInputContainerType &public_input,
                           FunctorResultCheck result_check,
                           typename ComponentType::input_type instance_input,
                           blueprint::connectedness_check_type connectedness_check =
                            blueprint::connectedness_check_type::type::STRONG,
                           ComponentStaticInfoArgs... component_static_info_args) {
            return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>(
                                    component_instance, desc, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType>(),
                                    instance_input, false, connectedness_check, component_static_info_args...);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_custom_assignments(ComponentType component_instance,
                            zk::snark::plonk_table_description<BlueprintFieldType> desc,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            const plonk_test_custom_assigner<ComponentType, BlueprintFieldType> &custom_assigner,
                            typename ComponentType::input_type instance_input,
                            blueprint::connectedness_check_type connectedness_check =
                                blueprint::connectedness_check_type::type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>
                                    (component_instance, desc, public_input, result_check, custom_assigner,
                                     instance_input, true, connectedness_check, component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail_custom_assignments(ComponentType component_instance,
                            zk::snark::plonk_table_description<BlueprintFieldType> desc,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            const plonk_test_custom_assigner<ComponentType, BlueprintFieldType> &custom_assigner,
                            typename ComponentType::input_type instance_input,
                            blueprint::connectedness_check_type connectedness_check =
                                blueprint::connectedness_check_type::type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, false, ComponentStaticInfoArgs...>
                                    (component_instance, desc, public_input, result_check, custom_assigner,
                                     instance_input, false,  connectedness_check,component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_private_input(ComponentType component_instance,
                            zk::snark::plonk_table_description<BlueprintFieldType> desc,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            typename ComponentType::input_type instance_input,
                            blueprint::connectedness_check_type connectedness_check =
                                blueprint::connectedness_check_type::type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, true , ComponentStaticInfoArgs...>
                                    (component_instance, desc, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType>(),
                                    instance_input, true, connectedness_check, component_static_info_args...);
            }

        template<typename ComponentType, typename BlueprintFieldType, typename Hash,
                 std::size_t Lambda, typename PublicInputContainerType, typename FunctorResultCheck,
                 typename... ComponentStaticInfoArgs>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInputContainerType::iterator>::value_type>::value>::type
            test_component_to_fail_private_input(ComponentType component_instance,
                            zk::snark::plonk_table_description<BlueprintFieldType> desc,
                            const PublicInputContainerType &public_input, FunctorResultCheck result_check,
                            typename ComponentType::input_type instance_input,
                            blueprint::connectedness_check_type connectedness_check =
                                blueprint::connectedness_check_type::type::STRONG,
                            ComponentStaticInfoArgs... component_static_info_args) {

                return test_component_inner<ComponentType, BlueprintFieldType, Hash, Lambda,
                                 PublicInputContainerType, FunctorResultCheck, true , ComponentStaticInfoArgs...>
                                    (component_instance, desc, public_input, result_check,
                                    plonk_test_default_assigner<ComponentType, BlueprintFieldType>(),
                                    instance_input, false, connectedness_check, component_static_info_args...);
            }

        /*
            Most of the time while testing we do not want to generate an entire set of assignments from scratch.
            This function wraps the generate_assignments call for the component, and patches the passed
            coordinate/value pairs into the result.
        */
        template<typename BlueprintFieldType, typename ComponentType>
        std::function<typename ComponentType::result_type(
                const ComponentType&,
                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&,
                const typename ComponentType::input_type&,
                const std::uint32_t)>
            generate_patched_assignments(
                const std::map<std::pair<std::size_t, std::size_t>, typename BlueprintFieldType::value_type>
                    &patches) {

            return [&patches]
                    (const ComponentType &component,
                     nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                     const typename ComponentType::input_type &instance_input,
                     const std::uint32_t start_row_index) {
                typename ComponentType::result_type result =
                    blueprint::components::generate_assignments<BlueprintFieldType>(
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
