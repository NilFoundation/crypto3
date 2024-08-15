//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_base_field_test

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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>

#include "test_plonk_component.hpp"
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_base_field_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_base_field_test_suite) {

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
    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
    constexpr std::size_t Lambda = 40;
    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t lr_rounds = 1;
    constexpr static const std::size_t comm_size = 1;
    // constexpr static const std::size_t n_2 = ceil(log2(n));
    // constexpr static const std::size_t padding = (1 << n_2) - n;

    constexpr static std::size_t public_input_size = 1;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type = zk::components::base_field<ArithmetizationType,
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

    using commitment_type =
        typename zk::components::kimchi_commitment_type<BlueprintFieldType,
                                                                commitment_params::shifted_commitment_split>;

    using opening_proof_type =
        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType, commitment_params::eval_rounds>;
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using binding = typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>;

    using verifier_index_type = zk::components::kimchi_verifier_index_base<curve_type, kimchi_params>;

    using proof_type = zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>;

    using kimchi_constants = zk::components::kimchi_inner_constants<kimchi_params>;

    // zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::vector<typename BlueprintFieldType::value_type> public_input;
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
    std::array<commitment_type, witness_columns> witness_comm;
    for (std::size_t i = 0; i < witness_columns; i++) {
        witness_comm[i] = {{unshifted_var[0]}};
    }

    std::array<commitment_type, perm_size> sigma_comm;
    for (std::size_t i = 0; i < perm_size; i++) {
        witness_comm[i] = {{unshifted_var[1]}};
    }
    std::array<commitment_type, kimchi_params::witness_columns>
        coefficient_comm;
    for (std::size_t i = 0; i < coefficient_comm.size(); i++) {
        coefficient_comm[i] = {{unshifted_var[2]}};
    }
    std::vector<commitment_type> oracles_poly_comm = {
        {{unshifted_var[3]}}};    // to-do: get in the component from oracles
    commitment_type lookup_runtime_comm = {{unshifted_var[4]}};
    commitment_type table_comm = {{unshifted_var[5]}};
    std::vector<commitment_type> lookup_sorted_comm {{{unshifted_var[6]}}};
    std::vector<commitment_type> lookup_selectors_comm = {{{unshifted_var[7]}}};
    std::vector<commitment_type> selectors_comm = {{{unshifted_var[8]}}};
    commitment_type lookup_agg_comm = {{unshifted_var[9]}};
    commitment_type z_comm = {{unshifted_var[10]}};
    commitment_type t_comm = {{unshifted_var[11]}};
    commitment_type generic_comm = {{unshifted_var[12]}};
    commitment_type psm_comm = {{unshifted_var[13]}};

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

    typename curve_type::base_field_type::value_type Pub = algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(Pub);
    var Pub_var = var(0, 67, false, var::column_type::public_input);

    typename curve_type::base_field_type::value_type zeta_to_srs_len =
        algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(zeta_to_srs_len);
    var zeta_to_srs_len_var = var(0, 68, false, var::column_type::public_input);

    typename curve_type::base_field_type::value_type zeta_to_domain_size_minus_1 =
        algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(zeta_to_domain_size_minus_1);
    var zeta_to_domain_size_minus_1_var = var(0, 69, false, var::column_type::public_input);

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    var_ec_point H_var = {var(0, 70, false, var::column_type::public_input),
                          var(0, 71, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type PI_G =
        algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(PI_G.X);
    public_input.push_back(PI_G.Y);

    var_ec_point PI_G_var = {var(0, 72, false, var::column_type::public_input),
                             var(0, 73, false, var::column_type::public_input)};

    constexpr static const std::size_t bases_size = kimchi_constants::final_msm_size(batch_size);
    std::array<curve_type::base_field_type::value_type, bases_size> batch_scalars;

    std::array<var, bases_size> batch_scalars_var;

    for (std::size_t i = 0; i < bases_size; i++) {
        batch_scalars[i] = algebra::random_element<curve_type::base_field_type>();
        public_input.push_back(batch_scalars[i]);
        batch_scalars_var[i] = var(0, 74 + i, false, var::column_type::public_input);
    }
    curve_type::base_field_type::value_type cip = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(cip);

    var cip_var = var(0, 74 + bases_size, false, var::column_type::public_input);

    typename proof_type::commitments_type commitments = {
        {witness_comm}, lookup_runtime_comm,   table_comm, {lookup_sorted_comm}, lookup_agg_comm, z_comm,
        t_comm,         {oracles_poly_comm[0]}    // to-do: get in the component from oracles
    };
    /*zk::components::kimchi_transcript_fq<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14> transcript;*/
    proof_type proof_var = {/*transcript, */ commitments, o_var, {scalars_var}};
    verifier_index_type verifier_index = {
        H_var,
        {PI_G_var},
        {lagrange_bases_var},
        {{sigma_comm}, {coefficient_comm}, generic_comm, psm_comm, {selectors_comm}, {lookup_selectors_comm},
        psm_comm, // runtime_tables_selector
        {psm_comm}, // table
        psm_comm, // complete_add
        psm_comm, // var_base_mmul
        psm_comm, // endo_mul
        psm_comm, // endo_mul_scalar
        }};

    typename binding::fr_data<var, batch_size> fr_data = {
        batch_scalars_var, {cip_var}, {Pub_var}, zeta_to_srs_len_var, zeta_to_domain_size_minus_1_var};
    typename binding::fq_data<var> fq_data;

    typename component_type::params_type params = {{proof_var}, verifier_index, fr_data, fq_data};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()