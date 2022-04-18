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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/multiplication.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_allocat_rows_test_case) {

    using curve_type = algebra::curves::bls12<381>;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 5;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment;

    zk::components::non_native_field_element_multiplication<ArithmetizationType, typename curve_type::base_field_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8>
        mul_component(bp, {});

    mul_component.generate_gates(public_assignment);
    mul_component.generate_copy_constraints();

    zk::snark::plonk_assignment_table<BlueprintFieldType, WitnessColumns> assignments(
    	private_assignment, public_assignment);
    
    BOOST_CHECK_EQUAL(0, bp.allocate_rows());
    BOOST_CHECK_EQUAL(1, bp.allocate_rows(5));
    BOOST_CHECK_EQUAL(6, bp.allocate_row());
}

BOOST_AUTO_TEST_SUITE_END()