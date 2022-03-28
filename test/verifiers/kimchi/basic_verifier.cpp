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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_basic_verifier_test

#include <assert.h>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_scalar_field.hpp>

#include "test_plonk_component.hpp"
#include "basic_verifier_types.hpp"
//#include "proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_basic_verifier_test_suite)

template <typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams,
    typename ProofType>
std::pair<proof_generator_result_type<BlueprintFieldType, ArithmetizationParams, ProofType>, 
    zk::blueprint_private_assignment_table<zk::snark::plonk_constraint_system<BlueprintFieldType,
        ArithmetizationParams>>> proof_generator(
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

    private_assignment.padding();
    public_assignment.padding();

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

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

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

    proof_generator_result_type<BlueprintFieldType, ArithmetizationParams, ProofType> generator_res =
         {proof, fri_params, bp, public_preprocessed_data};
    return std::make_pair(generator_res, private_assignment);
}

template<typename CurveType, typename ProofType>
proof_generator_result_type_base base_field_prover(nil::crypto3::zk::snark::pickles_proof<CurveType> &pickles_proof,
 typename curve_type::scalar_field_type::integral_type out_scalar) {
    using component_type = zk::components::pickles_verifier_base_field<ArithmetizationTypeBase, CurveType,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename component_type::private_params_type private_params = {};

    typename component_type::public_params_type public_params = {pickles_proof.commitments.z_comm.unshifted[0].to_affine(), out_scalar};

    auto generator_res = proof_generator<component_type, FpType, ArithmetizationParamsBase,
        ProofType>(public_params, private_params);

    return generator_res.first;
}

template<typename CurveType, typename ProofType>
proof_generator_result_type_scalar scalar_field_prover(nil::crypto3::zk::snark::pickles_proof<CurveType> &pickles_proof) {
    using component_type = zk::components::pickles_verifier_scalar_field<ArithmetizationTypeScalar, CurveType,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;


    typename component_type::private_params_type private_params = {};
    std::array<typename ArithmetizationTypeScalar::field_type::value_type, 3> input_data = {0, pickles_proof.ft_eval1, 1};
    typename component_type::public_params_type public_params = {input_data};
    auto generator_res = proof_generator<component_type, FrType, ArithmetizationParamsScalar,
    ProofType>(public_params, private_params);
    zk::blueprint_private_assignment_table<ArithmetizationTypeScalar> private_assignment = generator_res.second;
    std::size_t W = 1;
    std::size_t row = 12;
    typename ArithmetizationTypeScalar::field_type::value_type out = private_assignment.witness(W)[row];
    std::cout<<"expected scalar "<< out.data<<std::endl;
    typename CurveType::scalar_field_type::integral_type integral_out = typename CurveType::scalar_field_type::integral_type(out.data);
    generator_res.first.out = integral_out;
    return generator_res.first;
}



BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_basic_verifier_test_suite) {
    //nil::crypto3::zk::snark::pickles_proof<curve_type> proof = test_proof();
    nil::crypto3::zk::snark::pickles_proof<curve_type> kimchi_proof;
    kimchi_proof.ft_eval1 = 2;
    kimchi_proof.commitments.z_comm.unshifted.push_back(algebra::random_element<curve_type::template g1_type<>>());

    auto scalar_field_result = scalar_field_prover<curve_type, proof_type_scalar>(kimchi_proof);

    bool scalar_verifier_res = zk::snark::redshift_verifier<FrType, params_scalar>::process(scalar_field_result.public_preprocessed_data, scalar_field_result.redshift_proof, 
                                                                                scalar_field_result.bp,scalar_field_result.fri_params);

    auto base_field_result = base_field_prover<curve_type, proof_type_base>(kimchi_proof, scalar_field_result.out);

    bool verifier_res = zk::snark::redshift_verifier<FpType, params_base>::process(base_field_result.public_preprocessed_data, base_field_result.redshift_proof, 
                                                                                base_field_result.bp, base_field_result.fri_params);
                        
}

BOOST_AUTO_TEST_SUITE_END()