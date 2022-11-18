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

#define BOOST_TEST_MODULE blueprint_plonk_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_allocat_rows_test_case) {

    using curve_type = algebra::curves::bls12<381>;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 0;
    constexpr static const std::size_t constant_columns = 3;
    constexpr static const std::size_t selector_columns = 1;

    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<witness_columns, public_input_columns,
                                                                           constant_columns, selector_columns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
    zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

    BOOST_CHECK_EQUAL(0, bp.allocate_rows());
    BOOST_CHECK_EQUAL(1, bp.allocate_rows(5));
    BOOST_CHECK_EQUAL(6, bp.allocate_row());
}

BOOST_AUTO_TEST_SUITE_END()