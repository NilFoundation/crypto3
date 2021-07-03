//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include <nil/crypto3/zk/snark/default_types/r1cs_ppzkadsnark_pp.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/examples/run_r1cs_ppzkadsnark.hpp>

using namespace nil::crypto3::zk::snark;

int main(int argc, const char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
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
