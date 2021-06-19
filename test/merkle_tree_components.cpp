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

#define BOOST_TEST_MODULE merkle_tree_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/components/hashes/sha256/sha256_component.hpp>
#include <nil/crypto3/zk/components/merkle_tree/merkle_tree_check_read_component.hpp>
#include <nil/crypto3/zk/components/merkle_tree/merkle_tree_check_update_components.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FieldType, typename Hash>
void test_merkle_tree_check_update_component() {
    /* prepare test */
    const std::size_t digest_len = Hash::get_digest_len();

    const std::size_t tree_depth = 16;
    std::vector<merkle_authentication_node> prev_path(tree_depth);

    std::vector<bool> prev_load_hash(digest_len);
    std::generate(prev_load_hash.begin(), prev_load_hash.end(), [&]() { return std::rand() % 2; });
    std::vector<bool> prev_store_hash(digest_len);
    std::generate(prev_store_hash.begin(), prev_store_hash.end(), [&]() { return std::rand() % 2; });

    std::vector<bool> loaded_leaf = prev_load_hash;
    std::vector<bool> stored_leaf = prev_store_hash;

    std::vector<bool> address_bits;

    std::size_t address = 0;
    for (long level = tree_depth - 1; level >= 0; --level) {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
        address_bits.push_back(computed_is_right);
        std::vector<bool> other(digest_len);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        std::vector<bool> load_block = prev_load_hash;
        load_block.insert(computed_is_right ? load_block.begin() : load_block.end(), other.begin(), other.end());
        std::vector<bool> store_block = prev_store_hash;
        store_block.insert(computed_is_right ? store_block.begin() : store_block.end(), other.begin(), other.end());

        std::vector<bool> load_h = Hash::get_hash(load_block);
        std::vector<bool> store_h = Hash::get_hash(store_block);

        prev_path[level] = other;

        prev_load_hash = load_h;
        prev_store_hash = store_h;
    }

    std::vector<bool> load_root = prev_load_hash;
    std::vector<bool> store_root = prev_store_hash;

    /* execute the test */
    components::blueprint<FieldType> bp;
    components::blueprint_variable_vector<FieldType> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    digest_variable<FieldType> prev_leaf_digest(bp, digest_len);
    digest_variable<FieldType> prev_root_digest(bp, digest_len);
    merkle_authentication_path_variable<FieldType, Hash> prev_path_var(bp, tree_depth);
    digest_variable<FieldType> next_leaf_digest(bp, digest_len);
    digest_variable<FieldType> next_root_digest(bp, digest_len);
    merkle_authentication_path_variable<FieldType, Hash> next_path_var(bp, tree_depth);
    merkle_tree_check_update_components<FieldType, Hash> mls(bp, tree_depth, address_bits_va, prev_leaf_digest,
                                                             prev_root_digest, prev_path_var, next_leaf_digest,
                                                             next_root_digest, next_path_var, components::blueprint_variable<FieldType>(0));

    prev_path_var.generate_r1cs_constraints();
    mls.generate_r1cs_constraints();

    address_bits_va.fill_with_bits(bp, address_bits);
    assert(address_bits_va.get_field_element_from_bits(bp).as_ulong() == address);
    prev_leaf_digest.generate_r1cs_witness(loaded_leaf);
    prev_path_var.generate_r1cs_witness(address, prev_path);
    next_leaf_digest.generate_r1cs_witness(stored_leaf);
    address_bits_va.fill_with_bits(bp, address_bits);
    mls.generate_r1cs_witness();

    /* make sure that update check will check for the right things */
    prev_leaf_digest.generate_r1cs_witness(loaded_leaf);
    next_leaf_digest.generate_r1cs_witness(stored_leaf);
    prev_root_digest.generate_r1cs_witness(load_root);
    next_root_digest.generate_r1cs_witness(store_root);
    address_bits_va.fill_with_bits(bp, address_bits);
    assert(bp.is_satisfied());

    const std::size_t num_constraints = bp.num_constraints();
    const std::size_t expected_constraints =
        merkle_tree_check_update_components<FieldType, Hash>::expected_constraints(tree_depth);
    assert(num_constraints == expected_constraints);
}

template<typename FieldType, typename Hash>
void test_merkle_tree_check_read_component() {
    /* prepare test */
    const std::size_t digest_len = Hash::get_digest_len();
    const std::size_t tree_depth = 16;
    std::vector<merkle_authentication_node> path(tree_depth);

    std::vector<bool> prev_hash(digest_len);
    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    std::vector<bool> leaf = prev_hash;

    std::vector<bool> address_bits;

    std::size_t address = 0;
    for (long level = tree_depth - 1; level >= 0; --level) {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
        address_bits.push_back(computed_is_right);
        std::vector<bool> other(digest_len);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        std::vector<bool> block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        std::vector<bool> h = Hash::get_hash(block);

        path[level] = other;

        prev_hash = h;
    }
    std::vector<bool> root = prev_hash;

    /* execute test */
    components::blueprint<FieldType> bp;
    components::blueprint_variable_vector<FieldType> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    digest_variable<FieldType> leaf_digest(bp, digest_len);
    digest_variable<FieldType> root_digest(bp, digest_len);
    merkle_authentication_path_variable<FieldType, Hash> path_var(bp, tree_depth);
    merkle_tree_check_read_component<FieldType, Hash> ml(bp, tree_depth, address_bits_va, leaf_digest, root_digest,
                                                         path_var, components::blueprint_variable<FieldType>(0));

    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    address_bits_va.fill_with_bits(bp, address_bits);
    assert(address_bits_va.get_field_element_from_bits(bp).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);
    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(bp, address_bits);
    leaf_digest.generate_r1cs_witness(leaf);
    root_digest.generate_r1cs_witness(root);
    assert(bp.is_satisfied());

    const std::size_t num_constraints = bp.num_constraints();
    const std::size_t expected_constraints =
        merkle_tree_check_read_component<FieldType, Hash>::expected_constraints(tree_depth);
    assert(num_constraints == expected_constraints);
}

template<typename CurveType>
void test_all_merkle_tree_components() {
    typedef typename CurveType::scalar_field_type scalar_field_type;

    // for now all CRH components are knapsack CRH's; can be easily extended
    // later to more expressive selector types.
    using crh_with_field_out_component = knapsack_crh_with_field_out_component<scalar_field_type>;
    using crh_with_bit_out_component = knapsack_crh_with_bit_out_component<scalar_field_type>;

    test_merkle_tree_check_read_component<scalar_field_type, crh_with_bit_out_component>();
    test_merkle_tree_check_read_component<scalar_field_type, sha256_two_to_one_hash_component<scalar_field_type>>();

    test_merkle_tree_check_update_component<scalar_field_type, crh_with_bit_out_component>();
    test_merkle_tree_check_update_component<scalar_field_type, sha256_two_to_one_hash_component<scalar_field_type>>();
}

BOOST_AUTO_TEST_SUITE(merkle_tree_components_test_suite)

BOOST_AUTO_TEST_CASE(merkle_tree_components_bls12_381_test) {

    test_all_merkle_tree_components<curves::bls12<381>>();

}

BOOST_AUTO_TEST_CASE(merkle_tree_components_mnt4_test) {

    test_all_merkle_tree_components<curves::mnt4<398>>();

}

BOOST_AUTO_TEST_CASE(merkle_tree_components_mnt6_test) {

    test_all_merkle_tree_components<curves::mnt6<298>>();
    
}

BOOST_AUTO_TEST_SUITE_END()