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

#define BOOST_TEST_MODULE blueprint_plonk_variable_base_endo_scalar_mul_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/edwards/plonk/variable_base_endo_scalar_mul_15_wires.hpp>

#include "profiling.hpp"

using namespace nil::crypto3;

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        zk::commitments::detail::calculate_domain_set<FieldType>(degree_log, degree_log - 1);

    params.r = degree_log - 1;
    params.D = domain_set;
    params.q = q;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_allocat_rows_test_case) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType, PublicInputColumns, ConstantColumns,
        SelectorColumns> public_assignment;

    using component_type = zk::components::curve_element_variable_base_endo_scalar_mul<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    typename component_type::assignment_params a_params = {algebra::random_element<
        curve_type::template g1_type<algebra::curves::coordinates::affine>>(), algebra::random_element<BlueprintScalarType>()};
    component_type variable_base_endo_scalar_mul_component(bp, {});

    variable_base_endo_scalar_mul_component.generate_gates(public_assignment);
    variable_base_endo_scalar_mul_component.generate_copy_constraints(public_assignment);
    variable_base_endo_scalar_mul_component.generate_assignments(private_assignment, public_assignment, a_params);

    private_assignment.allocate_rows(128);
    public_assignment.allocate_rows(128);
    bp.fix_usable_rows();
    bp.allocate_rows(128 - 65);

    zk::snark::plonk_assignment_table<BlueprintFieldType, WitnessColumns, PublicInputColumns, 
        ConstantColumns, SelectorColumns> assignments(
    	private_assignment, public_assignment);

    using params = zk::snark::redshift_params<BlueprintFieldType, WitnessColumns,
         PublicInputColumns, ConstantColumns, SelectorColumns>;
    using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, params::merkle_hash_type,
                              params::transcript_hash_type, 2>;
    std::size_t table_rows_log = 7;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = 15;

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
}

BOOST_AUTO_TEST_SUITE_END()