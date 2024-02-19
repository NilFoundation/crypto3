//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_oracles_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/verify_scalar.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

#include <nil/blueprint/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_oracles_test_suite)

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvelRounds>
void prepare_proof(zk::snark::pickles_proof<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvelRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            // TODO
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // ft_eval
    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

BOOST_AUTO_TEST_CASE(blueprint_verifiers_kimchi_basic_verifier_test) {

    // PARAMS
    using curve_type = algebra::curves::vesta;
    using ScalarFieldType = typename curve_type::scalar_field_type;
    using BaseFieldType = typename curve_type::base_field_type;

    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var_scalar = zk::snark::plonk_variable<ScalarFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static std::size_t batch_size = 2;

    constexpr static const std::size_t prev_chal_size = 1;

    constexpr static const std::size_t domain_size = 128;

    constexpr std::size_t WitnessColumnsScalar = 15;
    constexpr std::size_t PublicInputColumnsScalar = 1;
    constexpr std::size_t ConstantColumnsScalar = 1;
    constexpr std::size_t SelectorColumnsScalar = 30;

    using ArithmetizationParamsScalar =
        zk::snark::plonk_arithmetization_params<WitnessColumnsScalar, PublicInputColumnsScalar, ConstantColumnsScalar,
                                                SelectorColumnsScalar>;
    using ArithmetizationTypeScalar = zk::snark::plonk_constraint_system<ScalarFieldTypeScalar>;
    using AssignmentTypeScalar = blueprint::assignment<ArithmetizationTypeScalar>;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<AssignmentTypeScalar>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;
    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    // COMMON DATA
    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);
    std::array<ScalarFieldType::value_type, bases_size> batch_scalars;
    std::array<ScalarFieldType::value_type, batch_size> cips_shifted;
    std::array<ScalarFieldType::value_type, public_input_size> pi;
    ScalarFieldType::value_type zeta = 0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    std::array<ScalarFieldType::value_type, batch_size> zeta_to_srs_len;
    ScalarFieldType::value_type zeta_to_domain_size_minus_1 = zeta.pow(domain_size) - 1;

    for (std::size_t i = 0; i < bases_size; i++) {
        batch_scalars[i] = algebra::random_element<ScalarFieldType>();
    }

    for (std::size_t i = 0; i < batch_size; i++) {
        cips_shifted[i] = algebra::random_element<ScalarFieldType>();
        zeta_to_srs_len[i] = zeta.pow(srs_len);
    }

    // SCALAR FIELD

    using fq_output_type_scalar =
        typename zk::components::binding<ArithmetizationTypeScalar, ScalarFieldType, kimchi_params>::fq_sponge_output;

    using fr_data_type_scalar = typename zk::components::binding<ArithmetizationTypeScalar, ScalarFieldType,
                                                                 kimchi_params>::fr_data<var_scalar, batch_size>;

    using fq_data_type_scalar = typename zk::components::binding<ArithmetizationTypeScalar, ScalarFieldType,
                                                                 kimchi_params>::fq_data<var_scalar>;

    zk::components::kimchi_verifier_index_scalar<ScalarFieldType> verifier_index_scalar;
    typename ScalarFieldType::value_type omega =
        0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
    verifier_index_scalar.domain_size = domain_size;
    verifier_index_scalar.omega = var_scalar(0, 0, false, var_scalar::column_type::public_input);

    using verify_scalar_component =
        zk::components::verify_scalar<ArithmetizationTypeScalar, curve_type, kimchi_params, commitment_params,
                                      batch_size, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename ScalarFieldType::value_type joint_combiner = 0;
    typename ScalarFieldType::value_type beta = 0;
    typename ScalarFieldType::value_type gamma = 0;
    typename ScalarFieldType::value_type alpha =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename ScalarFieldType::value_type fq_digest =
        0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;

    std::vector<typename ScalarFieldType::value_type> public_input_scalar = {omega};

    std::array<zk::components::kimchi_proof_scalar<ScalarFieldType, kimchi_params, eval_rounds>, batch_size> proofs;

    std::array<fq_output_type_scalar, batch_size> fq_outputs;

    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
        zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

        zk::components::kimchi_proof_scalar<ScalarFieldType, kimchi_params, eval_rounds> proof;

        prepare_proof<curve_type, ScalarFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof,
                                                                               public_input_scalar);

        fq_output_type_scalar fq_output;
        std::array<var_scalar, eval_rounds> challenges;
        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input_scalar.emplace_back(10);
            challenges[j] = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        }
        fq_output.challenges = challenges;

        // joint_combiner
        public_input_scalar.push_back(algebra::random_element<ScalarFieldType>());
        fq_output.joint_combiner =
            var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // beta
        public_input_scalar.push_back(algebra::random_element<ScalarFieldType>());
        fq_output.beta = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // gamma
        public_input_scalar.push_back(algebra::random_element<ScalarFieldType>());
        fq_output.gamma = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // alpha
        public_input_scalar.push_back(alpha);
        fq_output.alpha = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // zeta
        public_input_scalar.push_back(zeta);
        fq_output.zeta = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // fq_digest
        public_input_scalar.push_back(fq_digest);
        fq_output.fq_digest =
            var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);
        // c
        public_input_scalar.emplace_back(250);
        fq_output.c = var_scalar(0, public_input_scalar.size() - 1, false, var_scalar::column_type::public_input);

        fq_outputs[batch_id] = fq_output;
    }

    fr_data_type_scalar fr_data_public;
    fq_data_type_scalar fq_data_public;

    typename verify_scalar_component::params_type params_scalar = {fr_data_public, fq_data_public,
                                                                   verifier_index_scalar, proofs, fq_outputs};

    auto result_check_scalar = [](AssignmentTypeScalar &assignment, verify_scalar_component::result_type &real_res) {};

    test_component<verify_scalar_component, ScalarFieldTypeScalar, hash_type, Lambda>(
        params_scalar, public_input_scalar, result_check_scalar);

    //////////////////////////////////////////////////
    // BASE FIELD
    //////////////////////////////////////////////////
    constexpr std::size_t WitnessColumnsBase = 15;
    constexpr std::size_t PublicInputColumnsBase = 1;
    constexpr std::size_t ConstantColumnsBase = 1;
    constexpr std::size_t SelectorColumnsBase = 10;

    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumnsBase, PublicInputColumnsBase,
                                                                          ConstantColumnsBase, SelectorColumnsBase>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BaseFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    using var_ec_point = typename zk::components::var_ec_point<BaseFieldType>;

    using verify_base_component =
        zk::components::base_field<ArithmetizationType, curve_type, kimchi_params, commitment_params, batch_size, 0, 1,
                                   2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    using shifted_commitment_type =
        typename zk::components::kimchi_shifted_commitment_type<BaseFieldType,
                                                                commitment_params::shifted_commitment_split>;

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BaseFieldType, commitment_params::eval_rounds>;
    using var = zk::snark::plonk_variable<BaseFieldType>;

    using binding = typename zk::components::binding<ArithmetizationType, BaseFieldType, kimchi_params>;

    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;

    using proof_type = zk::components::kimchi_proof_base<BaseFieldType, kimchi_params>;

    std::vector<typename BaseFieldType::value_type> public_input;
    std::vector<var_ec_point> shifted_var;
    std::vector<var_ec_point> unshifted_var;
    for (std::size_t i = 0; i < 14; i++) {
        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type shifted =
            algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

        public_input.push_back(shifted.X);
        public_input.push_back(shifted.Y);

        shifted_var.push_back({var(0, i * 4, false, var::column_type::public_input),
                               var(0, i * 4 + 1, false, var::column_type::public_input)});

        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type unshifted =
            algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

        public_input.push_back(unshifted.X);
        public_input.push_back(unshifted.Y);

        unshifted_var.push_back({var(0, i * 4 + 2, false, var::column_type::public_input),
                                 var(0, i * 4 + 3, false, var::column_type::public_input)});
    }
    std::array<shifted_commitment_type, witness_columns> witness_comm;
    for (std::size_t i = 0; i < witness_columns; i++) {
        witness_comm[i] = {{shifted_var[0]}, {unshifted_var[0]}};
    }

    std::array<shifted_commitment_type, perm_size> sigma_comm;
    for (std::size_t i = 0; i < perm_size; i++) {
        witness_comm[i] = {{shifted_var[1]}, {unshifted_var[1]}};
    }
    std::vector<shifted_commitment_type> coefficient_comm = {{{shifted_var[2]}, {unshifted_var[2]}}};
    std::vector<shifted_commitment_type> oracles_poly_comm = {
        {{shifted_var[3]}, {unshifted_var[3]}}};    // to-do: get in the component from oracles
    shifted_commitment_type lookup_runtime_comm = {{shifted_var[4]}, {unshifted_var[4]}};
    shifted_commitment_type table_comm = {{shifted_var[5]}, {unshifted_var[5]}};
    std::vector<shifted_commitment_type> lookup_sorted_comm {{{shifted_var[6]}, {unshifted_var[6]}}};
    std::vector<shifted_commitment_type> lookup_selectors_comm = {{{shifted_var[7]}, {unshifted_var[7]}}};
    std::vector<shifted_commitment_type> selectors_comm = {{{shifted_var[8]}, {unshifted_var[8]}}};
    shifted_commitment_type lookup_agg_comm = {{shifted_var[9]}, {unshifted_var[9]}};
    shifted_commitment_type z_comm = {{shifted_var[10]}, {unshifted_var[10]}};
    shifted_commitment_type t_comm = {{shifted_var[11]}, {unshifted_var[11]}};
    shifted_commitment_type generic_comm = {{shifted_var[12]}, {unshifted_var[12]}};
    shifted_commitment_type psm_comm = {{shifted_var[13]}, {unshifted_var[13]}};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type L =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(L.X);
    public_input.push_back(L.Y);

    var_ec_point L_var = {var(0, 56, false, var::column_type::public_input),
                          var(0, 57, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type R =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(R.X);
    public_input.push_back(R.Y);

    var_ec_point R_var = {var(0, 58, false, var::column_type::public_input),
                          var(0, 59, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type delta =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(delta.X);
    public_input.push_back(delta.Y);

    var_ec_point delta_var = {var(0, 60, false, var::column_type::public_input),
                              var(0, 61, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(G.X);
    public_input.push_back(G.Y);

    var_ec_point G_var = {var(0, 62, false, var::column_type::public_input),
                          var(0, 63, false, var::column_type::public_input)};

    opening_proof_type o_var = {{L_var}, {R_var}, delta_var, G_var};

    std::array<curve_type::base_field_type::value_type, kimchi_constants::f_comm_msm_size> scalars;

    std::array<var, kimchi_constants::f_comm_msm_size> scalars_var;

    for (std::size_t i = 0; i < kimchi_constants::f_comm_msm_size; i++) {
        scalars[i] = algebra::random_element<curve_type::base_field_type>();
        public_input.push_back(scalars[i]);
        scalars_var[i] = var(0, 74 + i, false, var::column_type::public_input);
    }

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type lagrange_bases =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(lagrange_bases.X);
    public_input.push_back(lagrange_bases.Y);

    var_ec_point lagrange_bases_var = {var(0, 65, false, var::column_type::public_input),
                                       var(0, 66, false, var::column_type::public_input)};

    std::array<typename curve_type::base_field_type::value_type, public_input_size> Pub;
    std::array<var, public_input_size> Pub_var;
    for (std::size_t i = 0; i < public_input_size; i++) {
        Pub[i] = typename BaseFieldType::value_type(typename BaseFieldType::integral_type(pi[i].data));
        public_input.push_back(Pub[i]);
        Pub_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<var, batch_size> zeta_to_srs_len_var;
    for (std::size_t i = 0; i < batch_size; i++) {
        public_input.emplace_back(typename BaseFieldType::integral_type(zeta_to_srs_len[i].data));
        zeta_to_srs_len_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    public_input.emplace_back(typename BaseFieldType::integral_type(zeta_to_domain_size_minus_1.data));
    var zeta_to_domain_size_minus_1_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    var_ec_point H_var = {var(0, public_input.size() - 1, false, var::column_type::public_input),
                          var(0, public_input.size() - 1, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type PI_G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(PI_G.X);
    public_input.push_back(PI_G.Y);

    var_ec_point PI_G_var = {var(0, public_input.size() - 1, false, var::column_type::public_input),
                             var(0, public_input.size() - 1, false, var::column_type::public_input)};

    std::array<var, bases_size> batch_scalars_var;

    for (std::size_t i = 0; i < bases_size; i++) {
        public_input.emplace_back(typename BaseFieldType::integral_type(batch_scalars[i].data));
        batch_scalars_var[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
    curve_type::base_field_type::value_type cip = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(cip);

    var cip_var = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename proof_type::commitments_type commitments = {
        {witness_comm}, lookup_runtime_comm,   table_comm, {lookup_sorted_comm}, lookup_agg_comm, z_comm,
        t_comm,         {oracles_poly_comm[0]}    // to-do: get in the component from oracles
    };

    proof_type proof_var = {commitments, o_var, {scalars_var}};
    verifier_index_type verifier_index = {
        H_var,
        {PI_G_var},
        {lagrange_bases_var},
        {{sigma_comm}, {coefficient_comm}, generic_comm, psm_comm, {selectors_comm}, {lookup_selectors_comm}}};

    typename binding::fr_data<var, batch_size> fr_data = {
        batch_scalars_var, {cip_var}, {Pub_var[0]}, zeta_to_srs_len_var[0], zeta_to_domain_size_minus_1_var};
    typename binding::fq_data<var> fq_data;

    typename verify_base_component::params_type params = {{proof_var}, verifier_index, fr_data, fq_data};

    auto result_check = [](AssignmentType &assignment, verify_base_component::result_type &real_res) {};

    test_component<verify_base_component, BaseFieldType, hash_type, Lambda>(params, public_input,
                                                                                                   result_check);
}

BOOST_AUTO_TEST_SUITE_END()