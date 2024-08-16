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
//#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verify_base_field_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 25;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t eval_rounds = 1;
    constexpr static const std::size_t comm_size = 1;
    // constexpr static const std::size_t n_2 = ceil(log2(n));
    // constexpr static const std::size_t padding = (1 << n_2) - n;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;

    constexpr static std::size_t witness_columns = 5;
    constexpr static std::size_t perm_size = 5;

    constexpr static std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType,
                                                                   curve_type,
                                                                   kimchi_params,
                                                                   commitment_params,
                                                                   batch_size,
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

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    // using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType,
    //                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
    //                                 W11, W12, W13, W14>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using batch_proof_type = typename zk::components::
        batch_evaluation_proof_base<BlueprintFieldType, ArithmetizationType, kimchi_params, commitment_params>;

    // zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::vector<typename BlueprintFieldType::value_type> public_input;

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type shifted =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(shifted.X);
    public_input.push_back(shifted.Y);

    var_ec_point shifted_var = {var(0, 0, false, var::column_type::public_input),
                                var(0, 1, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type unshifted =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(unshifted.X);
    public_input.push_back(unshifted.Y);

    var_ec_point unshifted_var = {var(0, 2, false, var::column_type::public_input),
                                  var(0, 3, false, var::column_type::public_input)};

    curve_type::base_field_type::value_type f_zeta = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(f_zeta);

    var f_zeta_var = var(0, 4, false, var::column_type::public_input);

    curve_type::base_field_type::value_type f_zeta_w = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(f_zeta_w);

    var f_zeta_w_var = var(0, 5, false, var::column_type::public_input);

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type L =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(L.X);
    public_input.push_back(L.Y);

    var_ec_point L_var = {var(0, 6, false, var::column_type::public_input),
                          var(0, 7, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type R =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(R.X);
    public_input.push_back(R.Y);

    var_ec_point R_var = {var(0, 8, false, var::column_type::public_input),
                          var(0, 9, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type delta =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(delta.X);
    public_input.push_back(delta.Y);

    var_ec_point delta_var = {var(0, 10, false, var::column_type::public_input),
                              var(0, 11, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(G.X);
    public_input.push_back(G.Y);

    var_ec_point G_var = {var(0, 12, false, var::column_type::public_input),
                          var(0, 13, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    var_ec_point H_var = {var(0, 20, false, var::column_type::public_input),
                          var(0, 21, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type PI_G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(PI_G.X);
    public_input.push_back(PI_G.Y);

    var_ec_point PI_G_var = {var(0, 22, false, var::column_type::public_input),
                             var(0, 23, false, var::column_type::public_input)};

    std::array<curve_type::base_field_type::value_type, bases_size> scalars;

    std::array<var, bases_size> scalars_var;

    for (std::size_t i = 0; i < bases_size; i++) {
        scalars[i] = algebra::random_element<curve_type::base_field_type>();
        public_input.push_back(scalars[i]);
        scalars_var[i] = var(0, 24 + i, false, var::column_type::public_input);
    }
    curve_type::base_field_type::value_type cip = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(cip);

    var cip_var = var(0, 24 + bases_size, false, var::column_type::public_input);

    commitment_type comm_var = {{unshifted_var}};

    opening_proof_type o_var = {{L_var}, {R_var}, delta_var, G_var};
    //transcript_type transcript;

    typename binding::fr_data<var, batch_size> fr_data = {scalars_var, {cip_var}};

    std::array<batch_proof_type, batch_size> prepared_proofs = {{{{comm_var}, o_var}}};

    typename component_type::params_type params = {prepared_proofs, {H_var, {PI_G_var}, {PI_G_var}}, fr_data};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        params, public_input, result_check);
};
BOOST_AUTO_TEST_SUITE_END()