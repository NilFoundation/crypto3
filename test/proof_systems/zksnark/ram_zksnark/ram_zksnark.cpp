//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Test program that exercises the SEppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ram_zksnark_test

#include <boost/test/unit_test.hpp>

#include <sstream>

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_params.hpp>

#include "ram_examples.hpp"
#include "run_ram_zksnark.hpp"

using namespace nil::crypto3::zk::snark;

template<typename CurveType>
void test_ram_zksnark(const std::size_t w, const std::size_t k, const std::size_t boot_trace_size_bound, const std::size_t time_bound) {
    typedef ram_zksnark_machine_pp<CurveType> RAMType;
    const ram_architecture_params<RAMType> ap(w, k);
    const ram_example<RAMType> example = gen_ram_example_complex<RAMType>(ap, boot_trace_size_bound, time_bound, true);
    const bool ans = run_ram_zksnark<CurveType>(example);
    BOOST_CHECK(ans);
}

BOOST_AUTO_TEST_SUITE(ram_zksnark_test_suite)
BOOST_AUTO_TEST_CASE(ram_zksnark_test) {

    const std::size_t w = 32;
    const std::size_t k = 16;

    const std::size_t boot_trace_size_bound = 20;
    const std::size_t time_bound = 10;

    test_ram_zksnark<default_ram_zksnark_pp>(w, k, boot_trace_size_bound, time_bound);
}

BOOST_AUTO_TEST_SUITE_END()