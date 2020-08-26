//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <cstdio>

#include <nil/crypto3/zk/snark/default_types/bacs_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/examples/bacs_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/bacs_ppzksnark/examples/run_bacs_ppzksnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
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

    const std::size_t auxiliary_input_size = 0;
    const std::size_t num_outputs = num_gates / 2;

    std::cout << "Generate BACS example" << std::endl;
    bacs_example<typename default_bacs_ppzksnark_pp::scalar_field_type> example = generate_bacs_example<typename default_bacs_ppzksnark_pp::scalar_field_type>(
        primary_input_size, auxiliary_input_size, num_gates, num_outputs);

    std::cout << "(enter) Profile BACS ppzkSNARK" << std::endl;
    run_bacs_ppzksnark<default_bacs_ppzksnark_pp>(example);
}
