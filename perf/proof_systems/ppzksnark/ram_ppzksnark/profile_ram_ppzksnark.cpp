//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <nil/crypto3/zk/snark/default_types/ram_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/ram_ppzksnark/examples/run_ram_ppzksnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        algebra::print_compilation_info();
        return 0;
    }

    if (argc != 6) {
        printf("usage: %s word_size reg_count program_size input_size time_bound\n", argv[0]);
        return 1;
    }

    const std::size_t w = atoi(argv[1]), k = atoi(argv[2]), program_size = atoi(argv[3]), input_size = atoi(argv[4]),
                 time_bound = atoi(argv[5]);

    typedef ram_ppzksnark_machine_pp<default_ram_ppzksnark_pp> machine_ppT;

    const ram_ppzksnark_architecture_params<default_ram_ppzksnark_pp> ap(w, k);

    std::cout << "Generate RAM example" << std::endl;
    const std::size_t boot_trace_size_bound = program_size + input_size;
    const bool satisfiable = true;
    ram_example<machine_ppT> example =
        gen_ram_example_complex<machine_ppT>(ap, boot_trace_size_bound, time_bound, satisfiable);

    std::cout << "Profile RAM ppzkSNARK" << std::endl;
    run_ram_ppzksnark<default_ram_ppzksnark_pp>(example);
}
