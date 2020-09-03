//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE threshold_test

#include <nil/crypto3/pubkey/modes/algorithm/agree.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/kem_decrypt.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/kem_encrypt.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/pubkey.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/recover.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/modes/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/modes/threshold.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>
#include <string>
#include <cassert>
#include <unordered_map>

BOOST_AUTO_TEST_SUITE(threshold_hash_test_suite)

BOOST_AUTO_TEST_CASE(adler_iterator_range_hash) {
}

BOOST_AUTO_TEST_SUITE_END()