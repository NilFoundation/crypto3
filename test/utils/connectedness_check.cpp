//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <algorithm>
#define BOOST_TEST_MODULE gate_merger_test

#include <vector>
#include <iostream>
#include <map>

#include <boost/test/unit_test.hpp>
#include <boost/random.hpp>
#include <boost/pending/disjoint_sets.hpp>
#include <boost/range/algorithm/random_shuffle.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/blueprint/utils/connectedness_check.hpp>

using namespace nil::blueprint;
using namespace nil::crypto3;
using nil::blueprint::check_strong_connectedness;
using nil::blueprint::check_weak_connectedness;

//constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(connectedness_check_test_suite)

BOOST_AUTO_TEST_CASE(connectedness_check_sanity_tests) {
    using field_type = algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;
    constexpr std::size_t WitnessesAmount = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using var = zk::snark::plonk_variable<value_type>;
    using gate_type = zk::snark::plonk_gate<field_type, zk::snark::plonk_constraint<field_type>>;


    assignment<zk::snark::plonk_constraint_system<field_type, ArithmetizationParams>> assignment;
    circuit<zk::snark::plonk_constraint_system<field_type, ArithmetizationParams>> bp;

    std::size_t start_row_index = 4;

    std::vector<var> public_input = {var(0, 0, false, var::column_type::public_input)};
    std::vector<var> output_variables = {var(4, start_row_index, false, var::column_type::witness)};
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));

    bp.add_copy_constraint({public_input[0], output_variables[0]});
    BOOST_ASSERT(check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));
    BOOST_ASSERT(check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));

    public_input.push_back(var(0, 1, false, var::column_type::public_input));
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));

    const std::size_t intermediate_var_index = 5;
    var intermediate_var = var(intermediate_var_index, start_row_index, false, var::column_type::witness);
    bp.add_copy_constraint({public_input[1], intermediate_var});
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));

    bp.add_copy_constraint({intermediate_var, output_variables[0]});
    BOOST_ASSERT(check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));
    BOOST_ASSERT(check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 1));

    var another_intermediate_var = var(0, start_row_index + 2, false, var::column_type::constant);
    output_variables.push_back(another_intermediate_var);
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 3));

    std::size_t selector_idx = bp.add_gate({
        var(intermediate_var_index, -1, true, var::column_type::witness),
        var(0, +1, true, var::column_type::constant),
        var(0, -1, true, var::column_type::witness),
        var(1, -1, true, var::column_type::witness),
        var(2, -1, true, var::column_type::witness)});
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 3));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 3));

    assignment.enable_selector(selector_idx, start_row_index + 1);
    BOOST_ASSERT(check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 3));
    BOOST_ASSERT(check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 3));

    var lookup_test_var = var(0, start_row_index + 3, false, var::column_type::constant);
    output_variables.push_back(lookup_test_var);
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));

    std::size_t lookup_selector_idx = bp.add_lookup_gate(
        {{0, {var(0, -1, true, var::column_type::constant)}},
         {1, {var(0, 0, true, var::column_type::constant)}}});
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));
    BOOST_ASSERT(!check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));

    assignment.enable_selector(lookup_selector_idx, start_row_index + 3);
    BOOST_ASSERT(check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));
    BOOST_ASSERT(check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));

    public_input.push_back(var(0, 2, false, var::column_type::public_input));
    output_variables.push_back(var(0, 2, false, var::column_type::public_input));
    BOOST_ASSERT(!check_strong_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));
    BOOST_ASSERT(check_weak_connectedness(assignment, bp, public_input, output_variables, start_row_index, 4));
}

BOOST_AUTO_TEST_SUITE_END()
