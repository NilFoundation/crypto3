//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE merkle_tree_components_test

#include <boost/test/unit_test.hpp>

#include <nil/algebra/curves/bn128.hpp>
#include <nil/algebra/curves/edwards.hpp>
#include <nil/algebra/curves/mnt4.hpp>
#include <nil/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/hashes/sha256/sha256_component.hpp>
#include <nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_read_component.hpp>
#include <nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_update_components.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;
using namespace nil::algebra;

template<typename CurveType>
void test_all_merkle_tree_components() {
    typedef typename CurveType::scalar_field_type FieldType;
    test_merkle_tree_check_read_component<FieldType, crh_with_bit_out_component<FieldType>>();
    test_merkle_tree_check_read_component<FieldType, sha256_two_to_one_hash_component<FieldType>>();

    test_merkle_tree_check_update_component<FieldType, crh_with_bit_out_component<FieldType>>();
    test_merkle_tree_check_update_component<FieldType, sha256_two_to_one_hash_component<FieldType>>();
}

BOOST_AUTO_TEST_SUITE(merkle_tree_components_test_suite)

BOOST_AUTO_TEST_CASE(merkle_tree_components_test) {
    test_all_merkle_tree_components<curves::bn128>();
    test_all_merkle_tree_components<curves::edwards>();
    test_all_merkle_tree_components<curves::mnt4>();
    test_all_merkle_tree_components<curves::mnt6>();
}

BOOST_AUTO_TEST_SUITE_END()