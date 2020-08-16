//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE padding_test

#include <nil/crypto3/pubkey/modes/threshold/algorithm/agree.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/kem_decrypt.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/kem_encrypt.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/pubkey.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/modes/threshold/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/modes/threshold/mode.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>
#include <string>
#include <cassert>
#include <unordered_map>

BOOST_AUTO_TEST_SUITE(padding_hash_test_suite)

BOOST_AUTO_TEST_CASE(adler_iterator_range_hash) {
}

BOOST_AUTO_TEST_SUITE_END()