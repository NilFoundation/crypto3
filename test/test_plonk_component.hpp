//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/allocate.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include "profiling_plonk_circuit.hpp"
#include "profiling.hpp"

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

namespace nil {
    namespace crypto3 {
        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(std::size_t degree_log) {
            typename fri_type::params_type params;
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            constexpr std::size_t expand_factor = 0;
            std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
                math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            params.r = r;
            params.D = domain_set;
            params.max_degree = (1 << degree_log) - 1;

            return params;
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename FunctorResultCheck, typename PublicInput,
                 typename std::enable_if<
                     std::is_same<typename BlueprintFieldType::value_type,
                                  typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
                     bool>::type = true>
        auto prepare_component(typename ComponentType::params_type params, const PublicInput &public_input,
                               const FunctorResultCheck &result_check) {

            using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using component_type = ComponentType;

            zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

            zk::blueprint<ArithmetizationType> bp(desc);
            zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
            zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
            zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

            std::size_t start_row = zk::components::allocate<component_type>(bp);
            if (public_input.size() > component_type::rows_amount) {
                bp.allocate_rows(public_input.size() - component_type::rows_amount);
            }

            for (std::size_t i = 0; i < public_input.size(); i++) {
                auto allocated_pi = assignment_bp.allocate_public_input(public_input[i]);
            }

            zk::components::generate_circuit<component_type>(bp, public_assignment, params, start_row);
            typename component_type::result_type component_result =
                component_type::generate_assignments(assignment_bp, params, start_row);
            result_check(assignment_bp, component_result);

            assignment_bp.padding();
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                                     public_assignment);

            using placeholder_params =
                zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params>;

            using fri_type =
                typename zk::commitments::fri<BlueprintFieldType, typename placeholder_params::merkle_hash_type,
                                              typename placeholder_params::transcript_hash_type, 2>;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

            std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

            typename zk::snark::placeholder_public_preprocessor<
                BlueprintFieldType, placeholder_params>::preprocessed_data_type public_preprocessed_data =
                zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::process(
                    bp, public_assignment, desc, fri_params, permutation_size);
            typename zk::snark::placeholder_private_preprocessor<
                BlueprintFieldType, placeholder_params>::preprocessed_data_type private_preprocessed_data =
                zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::process(
                    bp, private_assignment, desc, fri_params);

            return std::make_tuple(desc, bp, fri_params, assignments, public_preprocessed_data,
                                   private_preprocessed_data);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInput, typename FunctorResultCheck>
        typename std::enable_if<
            std::is_same<typename BlueprintFieldType::value_type,
                         typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value>::type
            test_component(typename ComponentType::params_type params, const PublicInput &public_input,
                           FunctorResultCheck result_check) {

            using placeholder_params =
                zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;

            auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
                prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                                  FunctorResultCheck>(params, public_input, result_check);

            auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
                public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

//            bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
//                public_preprocessed_data, proof, bp, fri_params);
//            profiling(assignments);
//            BOOST_CHECK(verifier_res);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                 std::size_t Lambda, typename PublicInput, typename FunctorResultCheck,
                 typename std::enable_if<
                     std::is_same<typename BlueprintFieldType::value_type,
                                  typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
                     bool>::type = true>
        auto create_component_proof(typename ComponentType::params_type params, const PublicInput &public_input,
                                    const FunctorResultCheck &result_check) {

            using placeholder_params =
                zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;

            auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
                prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda>(
                    params, public_input, result_check);

            auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
                public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

//            bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
//                public_preprocessed_data, proof, bp, fri_params);
//            BOOST_CHECK(verifier_res);
            return std::make_tuple(proof, fri_params, public_preprocessed_data, bp);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TEST_PLONK_COMPONENT_HPP
