//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/oracles_cip.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_instances/ec_index_terms.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_verifiers_kimchi_detail_oracles_cip_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t eval_points_amount = 2;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type =
        zk::components::oracles_cip<ArithmetizationType, kimchi_params, 0, 1, 2, 3, 4,
                                       5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    // component input
    var v;
    var u;
    var ft_eval0;
    var ft_eval1;
    std::array<
        std::array<
        std::array<var, commitment_params::split_poly_eval_size>, 
        eval_points_amount>,
        kimchi_params::prev_challenges_size> polys;
    std::array<var, eval_points_amount> p_eval;
    std::array<zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>,
        eval_points_amount> evals;

    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    v = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    u = var(0, public_input.size() - 1, false, var::column_type::public_input);
    
    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    ft_eval0 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    ft_eval1 = var(0, public_input.size() - 1, false, var::column_type::public_input);

    for (std::size_t i = 0; i < kimchi_params::prev_challenges_size; i++) {
        for (std::size_t j = 0; j < eval_points_amount; j++) {
            for (std::size_t k = 0; k < commitment_params::split_poly_eval_size; k++) {
                public_input.push_back(algebra::random_element<BlueprintFieldType>());
                polys[i][j][k] = var(0, public_input.size() - 1, false, var::column_type::public_input);
            }
        }
    }

    for (std::size_t i = 0; i < eval_points_amount; i++) {
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        p_eval[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < eval_points_amount; i++) {
        for (std::size_t j = 0; j < kimchi_params::witness_columns; j++) {
            public_input.push_back(algebra::random_element<BlueprintFieldType>());
            evals[i].w[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        evals[i].z = var(0, public_input.size() - 1, false, var::column_type::public_input);

        for (std::size_t j = 0; j < kimchi_params::permut_size - 1; j++) {
            public_input.push_back(algebra::random_element<BlueprintFieldType>());
            evals[i].s[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }

        // TODO: lookups

        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        evals[i].generic_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);

        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        evals[i].poseidon_selector = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    

    typename component_type::params_type params = {
        v,
        u,
        ft_eval0,
        ft_eval1,
        polys,
        p_eval,
        evals
    };

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()