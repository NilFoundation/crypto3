//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <cassert>
#include <cstdio>

#include <nil/crypto3/zk/snark/default_types/uscs_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/examples/uscs_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/examples/run_uscs_ppzksnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        algebra::print_compilation_info();
        return 0;
    }

    if (argc != 3) {
        printf("usage: %s num_constraints input_size\n", argv[0]);
        return 1;
    }

    const int num_constraints = atoi(argv[1]);
    const int input_size = atoi(argv[2]);

    std::cout << "Generate USCS example" << std::endl;
    uscs_example<typename default_uscs_ppzksnark_pp::scalar_field_type> example =
        generate_uscs_example_with_field_input<typename default_uscs_ppzksnark_pp::scalar_field_type>(num_constraints, input_size);

    std::cout << "Profile USCS ppzkSNARK" << std::endl;
    run_uscs_ppzksnark<default_uscs_ppzksnark_pp>(example);
}
