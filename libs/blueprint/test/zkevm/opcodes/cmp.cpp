//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"
#define BOOST_TEST_MODULE zkevm_cmp_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include "nil/blueprint/zkevm/zkevm_word.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include "../opcode_tester.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(zkevm_cmp_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_cmp_test) {
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> zkevm_circuit(assignment, circuit);
    zkevm_machine_type machine = get_empty_machine();
    // incorrect test logic, but we have no memory operations so
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::GT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::LT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::EQ, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SGT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SLT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::GT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::LT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::EQ, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SGT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SLT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::GT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::LT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::EQ, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SGT, machine);
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
    zkevm_circuit.assign_opcode(zkevm_opcode::SLT, machine);
    zkevm_circuit.finalize_test();
    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE_END()
