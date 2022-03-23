//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_unified_addition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

/*BOOST_AUTO_TEST_CASE(blueprint_plonk_unified_addition_double) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType, PublicInputColumns, ConstantColumns,
        SelectorColumns> public_assignment;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10>;
    typename component_type::assignment_params a_params = {2 * curve_type::template g1_type<>::value_type::one(), 2 * curve_type::template g1_type<>::value_type::one()};
    component_type unified_addition_component(bp, {});

    component_type::generate_gates(bp, public_assignment);
    component_type::generate_copy_constraints(bp, public_assignment);
    component_type::generate_assignments(bp, private_assignment, public_assignment, a_params);

    private_assignment.allocate_rows(4);
    public_assignment.allocate_rows(4);
    bp.fix_usable_rows();
    bp.allocate_rows(3);

    zk::snark::plonk_assignment_table<BlueprintFieldType, WitnessColumns, PublicInputColumns, 
        ConstantColumns, SelectorColumns> assignments(
        private_assignment, public_assignment);

    using params = zk::snark::redshift_params<BlueprintFieldType, WitnessColumns,
         PublicInputColumns, ConstantColumns, SelectorColumns>;
    using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, params::merkle_hash_type,
                              params::transcript_hash_type, 2>;
    std::size_t table_rows_log = 2;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = 12;

    typename types::preprocessed_public_data_type public_preprocessed_data =
         zk::snark::redshift_public_preprocessor<BlueprintFieldType, params>::process(bp, public_assignment, 
            assignments.table_description(), fri_params, permutation_size);
    typename types::preprocessed_private_data_type private_preprocessed_data =
         zk::snark::redshift_private_preprocessor<BlueprintFieldType, params>::process(bp, private_assignment);

    auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(public_preprocessed_data,
                                                                       private_preprocessed_data, bp,
                                                                       assignments, fri_params);

    bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data, proof, 
                                                                        bp, fri_params);
    profiling(assignments);
    BOOST_CHECK(verifier_res);
}*/

BOOST_AUTO_TEST_CASE(blueprint_plonk_unified_addition_addition) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10>;

    typename component_type::init_params_type init_params = {};
    typename component_type::assignment_params_type assignment_params = {
        algebra::random_element<curve_type::template g1_type<>>(),
        algebra::random_element<curve_type::template g1_type<>>()};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams> (init_params, assignment_params);
}

BOOST_AUTO_TEST_SUITE_END()