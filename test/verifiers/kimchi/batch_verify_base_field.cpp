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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>

#include "test_plonk_component.hpp"
#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_batch_verify_base_field_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_batch_verify_base_field_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    constexpr static const std::size_t batch_size = 1;
    constexpr static const std::size_t lr_rounds = 1;
    constexpr static const std::size_t n = 1;
    constexpr static const std::size_t comm_size = 1;
    constexpr static const std::size_t n_2 = ceil(log2(n));
    constexpr static const std::size_t padding = (1 << n_2) - n;
    constexpr static const std::size_t f_comm_size = 2;
    constexpr static const std::size_t bases_size = n + padding + 1 + (1 + 1 + 2*lr_rounds + f_comm_size + 1)* batch_size;

    using component_type = zk::components::batch_verify_base_field<ArithmetizationType, curve_type, batch_size, lr_rounds, n, comm_size, bases_size,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    //zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    std::vector<typename BlueprintFieldType::value_type> public_input;

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type shifted = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(shifted.X);
    public_input.push_back(shifted.Y);

    typename component_type::params_type::var_ec_point shifted_var = {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type unshifted = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(unshifted.X);
    public_input.push_back(unshifted.Y);

    typename component_type::params_type::var_ec_point unshifted_var = {var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

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

    typename component_type::params_type::var_ec_point L_var = {var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(R.X);
    public_input.push_back(R.Y);

    typename component_type::params_type::var_ec_point R_var = {var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type delta = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(delta.X);
    public_input.push_back(delta.Y);

    typename component_type::params_type::var_ec_point delta_var = {var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type G = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(G.X);
    public_input.push_back(G.Y);

    typename component_type::params_type::var_ec_point G_var = {var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input)};

    curve_type::base_field_type::value_type z1 = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(z1);

    var z1_var = var(0, 14, false, var::column_type::public_input);

    curve_type::base_field_type::value_type z2 = algebra::random_element<curve_type::base_field_type>();

    public_input.push_back(z2);

    var z2_var = var(0, 15, false, var::column_type::public_input);

    curve_type::base_field_type::value_type u = algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(u);
    var u_var = var(0, 16, false, var::column_type::public_input);
    curve_type::base_field_type::value_type v = algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(v);
    var v_var = var(0, 17, false, var::column_type::public_input);
    curve_type::base_field_type::value_type zeta = algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(zeta);
    var zeta_var = var(0, 18, false, var::column_type::public_input);
    curve_type::base_field_type::value_type zeta_w = algebra::random_element<curve_type::base_field_type>();
    public_input.push_back(zeta_w);
    var zeta_w_var = var(0, 19, false, var::column_type::public_input);

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type H = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(H.X);
    public_input.push_back(H.Y);

    typename component_type::params_type::var_ec_point H_var = {var(0, 20, false, var::column_type::public_input), var(0, 21, false, var::column_type::public_input)};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type PI_G = 
    algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();

    public_input.push_back(PI_G.X);
    public_input.push_back(PI_G.Y);

    typename component_type::params_type::var_ec_point PI_G_var = {var(0, 22, false, var::column_type::public_input), var(0, 23, false, var::column_type::public_input)};

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

    typename component_type::params_type::f_comm comm_var = {{shifted_var}, {unshifted_var}};

    typename component_type::params_type::PE pe_var = {comm_var, {f_zeta_var}, {f_zeta_w_var}};
    typename component_type::params_type::opening_proof o_var = {{L_var}, {R_var}, delta_var, G_var, z1_var, z2_var};
    zk::components::kimchi_transcript<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                        11, 12, 13, 14> transcript;
    typename component_type::params_type::var_proof proof_var = {transcript, zeta_var, zeta_w_var, u_var, v_var, pe_var, o_var}; 
    typename component_type::params_type::public_input PI_var = {H_var, PI_G_var, scalars_var};
    typename component_type::params_type::result input = {{proof_var}, PI_var, cip_var};
    typename component_type::params_type params = {input};

    auto result_check = [](AssignmentType &assignment, 
        component_type::result_type &real_res) {
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

};
BOOST_AUTO_TEST_SUITE_END()