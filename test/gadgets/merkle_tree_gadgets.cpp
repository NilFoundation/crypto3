//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE merkle_tree_gadgets_test

#include <boost/test/unit_test.hpp>

#include <nil/algebra/curves/bn128.hpp>
#include <nil/algebra/curves/edwards.hpp>
#include <nil/algebra/curves/mnt4.hpp>
#include <nil/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

template<typename CurveType>
void test_all_merkle_tree_gadgets() {
    typedef typename CurveType::scalar_field_type FieldType;
    test_merkle_tree_check_read_gadget<FieldType, CRH_with_bit_out_gadget<FieldType>>();
    test_merkle_tree_check_read_gadget<FieldType, sha256_two_to_one_hash_gadget<FieldType>>();

    test_merkle_tree_check_update_gadget<FieldType, CRH_with_bit_out_gadget<FieldType>>();
    test_merkle_tree_check_update_gadget<FieldType, sha256_two_to_one_hash_gadget<FieldType>>();
}

BOOST_AUTO_TEST_SUITE(merkle_tree_gadgets_test_suite)

BOOST_AUTO_TEST_CASE(merkle_tree_gadgets_test) {
    test_all_merkle_tree_gadgets<algebra::curves::bn128>();
    test_all_merkle_tree_gadgets<algebra::curves::edwards>();
    test_all_merkle_tree_gadgets<algebra::curves::mnt4>();
    test_all_merkle_tree_gadgets<algebra::curves::mnt6>();
}

BOOST_AUTO_TEST_SUITE_END()