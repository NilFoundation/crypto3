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

#include <cassert>
#include <cstdio>

#include <nil/crypto3/zk/snark/default_types/r1cs_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

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
            input_size = (8 * input_size + (typename algebra::default_ec_pp::scalar_field_type::capacity()) - 1) /
                         typename algebra::default_ec_pp::scalar_field_type::capacity();
        }
    }

    std::cout << "Generate R1CS example" << std::endl;
    r1cs_example<typename default_r1cs_ppzksnark_pp::scalar_field_type> example =
        generate_r1cs_example_with_field_input<typename default_r1cs_ppzksnark_pp::scalar_field_type>(num_constraints,
                                                                                                      input_size);

    std::cout << "Profile R1CS ppzkSNARK" << std::endl;
    run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example);
}
