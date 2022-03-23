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

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include "profiling.hpp"

namespace nil {
    namespace crypto3 {

        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(std::size_t degree_log) {
            typename fri_type::params_type params;
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            constexpr std::size_t expand_factor = 4;
            std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
                zk::commitments::detail::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            params.r = r;
            params.D = domain_set;
            params.q = q;
            params.max_degree = (1 << degree_log) - 1;

            return params;
        }
        
        template <typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams>
        void test_component(
            typename ComponentType::public_params_type init_params,
            typename ComponentType::private_params_type assignment_params){

            using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
            using component_type = ComponentType;

            zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

            zk::blueprint<ArithmetizationType> bp(desc);
            zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
            zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);

            std::size_t start_row = component_type::allocate_rows(bp);
            component_type::generate_gates(bp, public_assignment, init_params, start_row);
            component_type::generate_copy_constraints(bp, public_assignment, init_params, start_row);
            component_type::generate_assignments(private_assignment, public_assignment,
                init_params, assignment_params, start_row);

            // bp.fix_usable_rows();
            private_assignment.padding();
            public_assignment.padding();
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(
                private_assignment, public_assignment);

            using params = zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams>;
            using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

            using fri_type = typename zk::commitments::fri<BlueprintFieldType,
                typename params::merkle_hash_type,
                typename params::transcript_hash_type,
                2>;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

            std::size_t permutation_size = 12;

            typename types::preprocessed_public_data_type public_preprocessed_data =
                 zk::snark::redshift_public_preprocessor<BlueprintFieldType, params>::process(bp, public_assignment, 
                    desc, fri_params, permutation_size);
            typename types::preprocessed_private_data_type private_preprocessed_data =
                 zk::snark::redshift_private_preprocessor<BlueprintFieldType, params>::process(bp, private_assignment,
                    desc);

            auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(public_preprocessed_data,
                                                                               private_preprocessed_data,
                                                                               desc,
                                                                               bp,
                                                                               assignments, fri_params);

            bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data, proof, 
                                                                                bp, fri_params);
            profiling(assignments);
            BOOST_CHECK(verifier_res);
        }

    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TEST_PLONK_COMPONENT_HPP
