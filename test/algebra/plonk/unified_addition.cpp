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

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
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
#include <nil/crypto3/zk/components/algebra/curves/edwards/plonk/unified_addition.hpp>

#include "profiling.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_allocat_rows_test_case) {

    using curve_type = algebra::curves::bls12<381>;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t SelectorColumns = 15;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 5;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType, SelectorColumns,
    	PublicInputColumns, ConstantColumns> public_assignment;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10>;
    typename component_type::assignment_params a_params = {algebra::random_element<
        curve_type::template g1_type<>>(), algebra::random_element<
        curve_type::template g1_type<>>()};
    component_type unified_addition_component(bp, {});

    // unified_addition_component.generate_gates(public_assignment);
    // unified_addition_component.generate_copy_constraints(public_assignment);
    unified_addition_component.generate_assignments(private_assignment, public_assignment, a_params);

    zk::snark::plonk_assignment_table<BlueprintFieldType, WitnessColumns, SelectorColumns,
    	PublicInputColumns, ConstantColumns> assignments(
    	private_assignment, public_assignment);

    // using params = zk::snark::redshift_params<BlueprintFieldType, WitnessColumns, SelectorColumns,
    //     PublicInputColumns, ConstantColumns>;
    // using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    // typename types::preprocessed_public_data_type public_preprocessed_data =
    //     zk::snark::redshift_public_preprocessor<BlueprintFieldType, params, 5>::process(bp, public_assignment, {});
    // typename types::preprocessed_private_data_type private_preprocessed_data =
    //     zk::snark::redshift_private_preprocessor<BlueprintFieldType, params, 5>::process(bp, private_assignment);

    // auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(public_preprocessed_data, private_preprocessed_data,
    //     bp, assignments, {});

    // bool verified = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data,
    //     proof, bp, {});

    profiling(assignments);

    BOOST_CHECK_EQUAL(component_type::required_rows_amount + 0, bp.allocate_rows());
    BOOST_CHECK_EQUAL(component_type::required_rows_amount + 1, bp.allocate_rows(5));
    BOOST_CHECK_EQUAL(component_type::required_rows_amount + 6, bp.allocate_row());
}

BOOST_AUTO_TEST_SUITE_END()