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

#include <cstdio>

#include <nil/crypto3/zk/snark/default_types/bacs_ppzksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/examples/bacs_examples.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/examples/run_bacs_ppzksnark.hpp>

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
    bacs_example<typename default_bacs_ppzksnark_pp::scalar_field_type> example =
        generate_bacs_example<typename default_bacs_ppzksnark_pp::scalar_field_type>(
            primary_input_size, auxiliary_input_size, num_gates, num_outputs);

    std::cout << "(enter) Profile BACS ppzkSNARK" << std::endl;
    run_bacs_ppzksnark<default_bacs_ppzksnark_pp>(example);
}
