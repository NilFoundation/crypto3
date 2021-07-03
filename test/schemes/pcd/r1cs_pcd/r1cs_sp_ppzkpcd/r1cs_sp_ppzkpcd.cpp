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

#define BOOST_TEST_MODULE r1cs_sp_ppzkpcd_test

#include <boost/test/unit_test.hpp>

#include "run_r1cs_sp_ppzkpcd.hpp"

using namespace nil::crypto3::zk::snark;

template<typename PCD_ppT>
void test_tally(const std::size_t arity, const std::size_t max_layer) {
    const std::size_t wordsize = 32;
    const bool bit = run_r1cs_sp_ppzkpcd_tally_example<PCD_ppT>(wordsize, arity, max_layer);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(r1cs_sp_ppzkpcd_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_sp_ppzkpcd_test) {
    typedef default_r1cs_ppzkpcd_pp PCD_pp;

    const std::size_t arity = 2;
    const std::size_t max_layer = 2;

    test_tally<PCD_pp>(arity, max_layer);
}

BOOST_AUTO_TEST_SUITE_END()
