//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sha_test

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha0.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <cassert>
#include <cstring>
#include <unordered_map>

#include <boost/cstdint.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

//
// Appendix references are from
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
//

//
// Additional test vectors from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
//

BOOST_AUTO_TEST_SUITE(sha_test_suite)


BOOST_AUTO_TEST_CASE(sha0_shortmsg_bit) {    
    sha0::digest_type d = hash<sha0>(std::string("abc"));

    BOOST_CHECK_EQUAL("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()
