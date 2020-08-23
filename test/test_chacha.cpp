/* test_chacha.cpp
 *
 * Copyright Mikhail Komarov 2020
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * $Id$
 *
 */

#define BOOST_TEST_MODULE chacha_rng_test

#include <string>
#include <tuple>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <boost/random/chacha.hpp>

#include <nil/crypto3/stream/chacha.hpp>

static const std::unordered_map<std::tuple<std::string, std::string>, std::string> = {
    {{"0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000"},
    "a84e2a6af98d0a2601ffd05c994de713fa8da43b6f04b3c48c28b0b1b6c9c813726b1d536da5b8b359176c646a7156db35420d5ccd1cea945b246f25edf43b38"}};

BOOST_AUTO_TEST_CASE(test_special_seed) {

}
