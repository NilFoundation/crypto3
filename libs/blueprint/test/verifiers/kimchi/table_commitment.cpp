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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_batch_verify_base_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/table_commitment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/lookup_test.hpp"

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_table_commitment_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_table_commitment_test) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using ScalarFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t eval_rounds = 1;
    constexpr static const std::size_t comm_size = 1;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;

    constexpr static std::size_t witness_columns = 5;
    constexpr static std::size_t perm_size = 5;

    constexpr static std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_lookup_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using KimchiParamsType = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using commitment_type = typename
                        zk::components::kimchi_commitment_type<BlueprintFieldType,
                            KimchiParamsType::commitment_params_type::shifted_commitment_split>;
    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

    using component_type = zk::components::table_commitment<ArithmetizationType,
                                                                   KimchiParamsType,
                                                                   curve_type,
                                                                   0,
                                                                   1,
                                                                   2,
                                                                   3,
                                                                   4,
                                                                   5,
                                                                   6,
                                                                   7,
                                                                   8,
                                                                   9,
                                                                   10,
                                                                   11,
                                                                   12,
                                                                   13,
                                                                   14>;
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static const std::size_t lookup_columns = KimchiParamsType::circuit_params::lookup_columns;

    constexpr std::size_t use_lookup_runtime = KimchiParamsType::circuit_params::lookup_runtime ? 1 : 0;

    // zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::vector<typename BlueprintFieldType::value_type> public_input;
    std::vector<commitment_type> lookup_columns_var;
    std::array<var, lookup_columns> lookup_scalars_var;
    commitment_type runtime_var;
    std::size_t j = 0;
    std::size_t size = KimchiParamsType::commitment_params_type::shifted_commitment_split;
    for (std::size_t i = j; i < lookup_columns; i++){
        commitment_type column_var;
        for (std::size_t k = 0; k < size; k++) {
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().X);
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().Y);
            column_var.parts[k] = {var(0, i*k*2 + k*2, false, var::column_type::public_input),
            var(0, i*k*2 + k*2 + 1, false, var::column_type::public_input)};
            j+=2;
        }
        lookup_columns_var.push_back(column_var);
    }

    if (KimchiParamsType::circuit_params::lookup_runtime){
        for (std::size_t k = 0; k < size; k++) {
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().X);
            public_input.push_back(algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>().Y);
            runtime_var.parts[k] = {var(0, j + k*2, false, var::column_type::public_input),
            var(0, j + k*2 + 1, false, var::column_type::public_input)};
            j+=2;
        }
    }
    std::size_t s = lookup_columns + j;
    for (std::size_t i = j; i < s; i++){
        for (std::size_t k = 0; k < size; k++) {
            public_input.push_back(algebra::random_element<curve_type::base_field_type>());
            lookup_scalars_var[i - j] = (var(0, i, false, var::column_type::public_input));
            j++;
        }
    }

    typename component_type::params_type params = {lookup_columns_var, lookup_scalars_var, runtime_var};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        params, public_input, result_check);
};
BOOST_AUTO_TEST_SUITE_END()