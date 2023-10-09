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

#define BOOST_TEST_MODULE gate_id_test

#include <list>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/random.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/blueprint/gate_id.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;
using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(gate_id_tests_suite)

BOOST_AUTO_TEST_CASE(gate_id_sanity_tests) {
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using value_type = typename field_type::value_type;
    using var = typename nil::crypto3::zk::snark::plonk_variable<value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<field_type>;
    using gate_type = nil::crypto3::zk::snark::plonk_gate<field_type, constraint_type>;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using gate_id_type = nil::blueprint::gate_id<field_type, ArithmetizationParams>;

    value_set<field_type, ArithmetizationParams> values = value_set<field_type, ArithmetizationParams>::get_value_set();
    std::vector<constraint_type> constraints;
    constraints.reserve(3);
    constraints.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(1, 3, true, var::column_type::witness) -
        var(2, 0, true, var::column_type::witness));
    constraints.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(5, 1, true, var::column_type::witness) -
        var(6, 0, true, var::column_type::witness));
    constraints.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(9, 2, true, var::column_type::witness) +
        var(10, 0, true, var::column_type::witness));
    gate_type gate(0, constraints);

    gate_id_type id(gate);
    BOOST_ASSERT(id == id);
    BOOST_ASSERT(!(id < id));
    std::vector<constraint_type> constraints_2;
    constraints_2.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(1, 3, true, var::column_type::witness) -
        var(2, 0, true, var::column_type::witness));
    gate_id_type id_2(gate_type(0, constraints_2));
    BOOST_ASSERT(id != id_2);
    BOOST_ASSERT(id < id_2 || id_2 < id);

    std::vector<constraint_type> constraints_3;
    std::vector<constraint_type> constraints_4;
    constraints_3.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(0, 1, true, var::column_type::witness));
    constraints_3.emplace_back(
        var(0, 0, true, var::column_type::witness));
    constraints_4.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(0, 0, true, var::column_type::witness));
    constraints_4.emplace_back(
        var(0, 1, true, var::column_type::witness));
    gate_id_type id_3(constraints_3);
    gate_id_type id_4(constraints_4);
    BOOST_ASSERT(id_3 != id_4);

    value_type power_100 = values.get_power(100);
    value_type power_101 = values.get_power(101);
    BOOST_ASSERT(power_100 != power_101);

    // gate_id should be unordered -- order of constraints inside the gate should not matter
    std::vector<constraint_type> constraints_5;
    auto first_constraint =
        var(0, -1, true, var::column_type::witness) * var(1, 3, true, var::column_type::witness) -
        var(2, 0, true, var::column_type::witness);
    auto second_constraint =
        var(0, -1, true, var::column_type::witness) * var(5, 1, true, var::column_type::witness) -
        var(6, 0, true, var::column_type::witness);
    constraints_5.push_back(first_constraint);
    constraints_5.push_back(second_constraint);
    std::vector<constraint_type> constraints_6;
    constraints_6.push_back(second_constraint);
    constraints_6.push_back(first_constraint);

    gate_id_type id_5(constraints_5),
                 id_6(constraints_6);
    BOOST_ASSERT(id_5 == id_6);

    std::vector<constraint_type> constraints_7;
    constraints_7.emplace_back(var(0, 0, true, var::column_type::witness));
    std::vector<constraint_type> constraints_8;
    constraints_8.emplace_back(var(0, 0, true, var::column_type::constant));
    gate_id_type id_7(constraints_7),
                 id_8(constraints_8);
    BOOST_ASSERT(id_7 != id_8);
}

BOOST_AUTO_TEST_CASE(lookup_gate_id_sanity_tests) {
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::scalar_field_type;
    using value_type = typename field_type::value_type;
    using var = typename nil::crypto3::zk::snark::plonk_variable<value_type>;
    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<field_type>;
    using gate_type = nil::crypto3::zk::snark::plonk_gate<field_type, constraint_type>;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using lookup_constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<field_type>;
    using lookup_gate_type = nil::crypto3::zk::snark::plonk_lookup_gate<field_type, lookup_constraint_type>;
    using lookup_gate_id_type = nil::blueprint::lookup_gate_id<field_type, ArithmetizationParams>;

    std::vector<lookup_constraint_type> constraints_1, constraints_2;

    constraints_1.reserve(2);
    lookup_constraint_type constraint_1, constraint_2;
    constraint_1.table_id = 0;
    constraint_1.lookup_input.emplace_back(
        var(0, -1, true, var::column_type::witness) * var(1, 3, true, var::column_type::witness) -
        var(2, 0, true, var::column_type::witness));
    constraint_1.lookup_input.emplace_back(var(1, 3, true, var::column_type::witness));
    constraints_1.push_back(constraint_1);
    constraint_2 = constraint_1;
    constraint_2.table_id = 1;
    constraints_1.push_back(constraint_2);

    constraints_2.resize(2);
    std::copy(constraints_1.rbegin(), constraints_1.rend(), constraints_2.begin());

    // Order of constraints should not matter
    lookup_gate_type gate_1(0, constraints_1),
                     gate_2(1, constraints_2);
    lookup_gate_id_type id_1 = lookup_gate_id_type(gate_1),
                        id_2 = lookup_gate_id_type(gate_2);
    BOOST_ASSERT(id_1 == id_2);
    BOOST_ASSERT(!(id_1 < id_2) && !(id_2 < id_1));
    // Order of variables inside constraints should matter
    auto var_1 = var(0, -1, true, var::column_type::witness),
         var_2 = var(1, 3, true, var::column_type::witness);
    lookup_constraint_type constraint_3({0, {var_1, var_2}}),
                           constraint_4({0, {var_2, var_1}});
    lookup_gate_id_type id_3(constraint_3),
                        id_4(constraint_4);
    BOOST_ASSERT(id_3 != id_4);
    // Table ids should matter
    lookup_constraint_type constraint_5({0, {var_1, var_2}}),
                           constraint_6({1, {var_1, var_2}});
    lookup_gate_id_type id_5(constraint_5),
                        id_6(constraint_6);
    BOOST_ASSERT(id_5 != id_6);
}

BOOST_AUTO_TEST_SUITE_END()
