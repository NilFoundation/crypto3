//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
    typedef ram_zksnark_machine_pp<CurveType> ramT;
    const ram_architecture_params<ramT> ap(w, k);
    const ram_example<ramT> example = gen_ram_example_complex<ramT>(ap, boot_trace_size_bound, time_bound, true);
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