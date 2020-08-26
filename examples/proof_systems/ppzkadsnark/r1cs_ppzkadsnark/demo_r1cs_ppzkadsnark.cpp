//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/default_types/r1cs_ppzkadsnark_pp.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/run_r1cs_ppzkadsnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        algebra::print_compilation_info();
        return 0;
    }

    if (argc != 3 && argc != 4) {
        printf("usage: %s num_constraints input_size [Fr|bytes]\n", argv[0]);
        return 1;
    }
    const int num_constraints = atoi(argv[1]);
    int input_size = atoi(argv[2]);
    if (argc == 4) {
        assert(strcmp(argv[3], "Fr") == 0 || strcmp(argv[3], "bytes") == 0);
        if (strcmp(argv[3], "bytes") == 0) {
            input_size = (8 * input_size + (algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>::num_bits - 1) - 1) /
                         (algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>::num_bits - 1);
        }
    }

    r1cs_example<algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>> example =
        generate_r1cs_example_with_field_input<algebra::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>>(num_constraints,
                                                                                                   input_size);

    run_r1cs_ppzkadsnark<default_r1cs_ppzkadsnark_pp>(example);
}
