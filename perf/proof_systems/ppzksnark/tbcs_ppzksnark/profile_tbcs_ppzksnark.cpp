//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <cstdio>

#include <nil/algebra/common/profiling.hpp>
#include <nil/algebra/common/utils.hpp>

#include <nil/crypto3/zk/snark/default_types/tbcs_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs/examples/tbcs_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/examples/run_tbcs_ppzksnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
    default_tbcs_ppzksnark_pp::init_public_params();
    algebra::start_profiling();

    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        algebra::print_compilation_info();
        return 0;
    }

    if (argc != 3) {
        printf("usage: %s num_gates primary_input_size\n", argv[0]);
        return 1;
    }
    const int num_gates = atoi(argv[1]);
    int primary_input_size = atoi(argv[2]);

    const size_t auxiliary_input_size = 0;
    const size_t num_outputs = num_gates / 2;

    algebra::enter_block("Generate TBCS example");
    tbcs_example example = generate_tbcs_example(primary_input_size, auxiliary_input_size, num_gates, num_outputs);
    algebra::leave_block("Generate TBCS example");

    algebra::print_header("(enter) Profile TBCS ppzkSNARK");
    const bool test_serialization = true;
    run_tbcs_ppzksnark<default_tbcs_ppzksnark_pp>(example, test_serialization);
    algebra::print_header("(leave) Profile TBCS ppzkSNARK");
}
