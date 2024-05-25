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

#define BOOST_TEST_MODULE ram_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "ram_examples.hpp"
#include "run_ram_ppzksnark.hpp"

using namespace nil::crypto3::zk::snark;

template<typename CurveType>
void test_ram_ppzksnark(const std::size_t w,
                        const std::size_t k,
                        const std::size_t program_size,
                        const std::size_t input_size,
                        const std::size_t time_bound) {
    typedef ram_ppzksnark_machine_pp<CurveType> machine_ppT;
    const std::size_t boot_trace_size_bound = program_size + input_size;
    const bool satisfiable = true;

    const ram_ppzksnark_architecture_params<CurveType> ap(w, k);
    const ram_example<machine_ppT> example =
        gen_ram_example_complex<machine_ppT>(ap, boot_trace_size_bound, time_bound, satisfiable);

    const bool bit = run_ram_ppzksnark<CurveType>(example);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(ram_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(ram_ppzksnark_test) {
    const std::size_t program_size = 100;
    const std::size_t input_size = 2;
    const std::size_t time_bound = 20;

    // 16-bit TinyRAM with 16 registers
    test_ram_ppzksnark<default_ram_ppzksnark_pp>(16, 16, program_size, input_size, time_bound);

    // 32-bit TinyRAM with 16 registers
    test_ram_ppzksnark<default_ram_ppzksnark_pp>(32, 16, program_size, input_size, time_bound);
}

BOOST_AUTO_TEST_SUITE_END()
