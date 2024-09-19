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

#define BOOST_TEST_MODULE zkevm_pushx_test

#include <boost/test/unit_test.hpp>

//#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>
#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include "../opcode_tester.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(zkevm_pushx_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_pushx_test) {
    // using field_type = fields::goldilocks64;
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> zkevm_circuit(assignment, circuit, 79);
    zkevm_table<field_type> zkevm_table(zkevm_circuit, assignment);
    zkevm_machine_type machine = get_empty_machine();

    machine.apply_opcode(zkevm_opcode::PUSH0, 1234567890); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH1, 1234567890); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH2, 1234567890); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH3, 1234567890); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH4, 1234567890); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH5, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH6, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH7, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH8, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH9, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH10, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH11, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH12, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH13, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH14, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH15, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH16, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH17, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH18, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH19, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH20, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH21, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH22, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH23, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH24, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH25, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH26, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH27, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH28, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH29, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH30, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH31, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::PUSH32, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257)); zkevm_table.assign_opcode(machine);
    machine.apply_opcode(zkevm_opcode::RETURN); zkevm_table.assign_opcode(machine);
    zkevm_table.finalize_test();
/*
    std::ofstream myfile;
    myfile.open("test_assignment.txt");
    assignment.export_table(myfile);
    myfile.close();
*/
    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE_END()
