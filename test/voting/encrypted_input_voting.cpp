//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE voting_encrypted_input_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/crypto3/zk/components/hashes/pedersen.hpp>

#include <nil/crypto3/zk/components/voting/encrypted_input_voting.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename HashComponent>
std::vector<bool> calculate_hash_via_component(const std::vector<bool> &in_bits) {
    using field_type = typename HashComponent::field_type;

    blueprint<field_type> bp_bits;
    components::block_variable<field_type> in_block(bp_bits, in_bits.size());
    in_block.generate_r1cs_witness(in_bits);

    HashComponent hash_comp_bits(bp_bits, in_block);
    hash_comp_bits.generate_r1cs_witness();
    hash_comp_bits.generate_r1cs_constraints();
    return hash_comp_bits.result.get_digest();
}

void test_jubjub_pedersen_encrypted_input_voting_component() {
    using curve_type = curves::jubjub;
    using bp_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, bp_generator_hash_type, hash_params>;
    using hash_type = typename hash_component::hash_type;
    using merkle_hash_component = hash_component;
    using merkle_hash_type = typename merkle_hash_component::hash_type;
    using field_type = typename hash_component::field_type;
    constexpr std::size_t arity = 2;
    using voting_component =
        components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using merkle_validate_component = typename voting_component::merkle_proof_validating_component;

    /* prepare test */
    const std::size_t tree_depth = 16;
    // TODO: use merkle_proof from container module
    std::vector<std::vector<bool>> path(tree_depth);

    const std::size_t sk_len = 128;
    std::vector<bool> sk(sk_len);
    std::generate(sk.begin(), sk.end(), [&]() { return std::rand() % 2; });
    auto sk_wrong = sk;
    sk_wrong[0] = !sk_wrong[0];

    std::vector<bool> pk = hash<hash_type>(sk);
    std::vector<bool> pk_leaf = hash<merkle_hash_type>(pk);
    BOOST_CHECK(pk_leaf.size() == merkle_hash_component::digest_bits);

    std::vector<bool> prev_hash = pk_leaf;
    std::vector<bool> leaf = pk_leaf;

    std::vector<bool> address_bits;

    std::size_t address = 0;
    for (long level = tree_depth - 1; level >= 0; --level) {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
        address_bits.push_back(computed_is_right);
        std::vector<bool> other(merkle_hash_component::digest_bits);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        std::vector<bool> block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        std::vector<bool> h = hash<merkle_hash_type>(block);

        path[level] = other;

        prev_hash = h;
    }
    std::vector<bool> root = prev_hash;
    auto root_wrong = root;
    root_wrong[0] = !root_wrong[0];
    auto path_wrong = path;
    path_wrong[0][0] = !path_wrong[0][0];
    auto address_bits_wrong = address_bits;
    address_bits_wrong[0] = !address_bits_wrong[0];

    std::vector<bool> m = {0, 1, 0, 0, 0, 0, 0};
    auto m_wrong = m;
    m_wrong[0] = !m_wrong[0];

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });

    std::vector<bool> eid_sk;
    std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
    std::copy(std::cbegin(sk), std::cend(sk), std::back_inserter(eid_sk));
    std::vector<bool> sn = hash<hash_type>(eid_sk);
    auto sn_wrong = sn;
    sn_wrong[0] = !sn_wrong[0];

    /* execute test */
    blueprint<field_type> bp;
    nil::crypto3::zk::detail::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    components::block_variable<field_type> m_block(bp, m.size());
    components::block_variable<field_type> eid_block(bp, eid.size());
    components::block_variable<field_type> sk_block(bp, sk.size());
    components::digest_variable<field_type> sn_digest(bp, hash_component::digest_bits);
    components::digest_variable<field_type> root_digest(bp, merkle_hash_component::digest_bits);
    merkle_proof_component path_var(bp, tree_depth);
    voting_component vote_var(bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
                              nil::crypto3::zk::detail::blueprint_variable<field_type>(0));

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();

    address_bits_va.fill_with_bits(bp, address_bits);
    BOOST_CHECK(address_bits_va.get_field_element_from_bits(bp) == address);
    m_block.generate_r1cs_witness(m);
    eid_block.generate_r1cs_witness(eid);
    sk_block.generate_r1cs_witness(sk);
    path_var.generate_r1cs_witness(address, path);

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(bp, address_bits);
    vote_var.generate_r1cs_witness(root, sn);
    BOOST_CHECK(bp.is_satisfied());

    // false positive test with wrong root
    root_digest.generate_r1cs_witness(root_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    root_digest.generate_r1cs_witness(root);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong sk
    sk_block.generate_r1cs_witness(sk_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    sk_block.generate_r1cs_witness(sk);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong path
    path_var.generate_r1cs_witness(address, path_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    path_var.generate_r1cs_witness(address, path);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong address
    address_bits_va.fill_with_bits(bp, address_bits_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    address_bits_va.fill_with_bits(bp, address_bits);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong sn
    sn_digest.generate_r1cs_witness(sn_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    sn_digest.generate_r1cs_witness(sn);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong m
    m_block.generate_r1cs_witness(m_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    m_block.generate_r1cs_witness(m);
    BOOST_CHECK(bp.is_satisfied());

    // const std::size_t num_constraints = bp.num_constraints();
    // const std::size_t expected_constraints =
    //     components::merkle_tree_check_read_component<FieldType, Hash>::expected_constraints(tree_depth);
    // BOOST_CHECK(num_constraints == expected_constraints);
}

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

void test_jubjub_merkle_container_pedersen_encrypted_input_voting_component() {
    using curve_type = curves::jubjub;
    using bp_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, bp_generator_hash_type, hash_params>;
    using hash_type = typename hash_component::hash_type;
    using merkle_hash_component = hash_component;
    using merkle_hash_type = typename merkle_hash_component::hash_type;
    using field_type = typename hash_component::field_type;
    constexpr std::size_t arity = 2;
    using voting_component =
        components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using merkle_validate_component = typename voting_component::merkle_proof_validating_component;

    /* prepare test */
    constexpr std::size_t tree_depth = 4;
    constexpr std::size_t leafs_number = 1 << tree_depth;
    auto secret_keys = generate_random_data<bool, hash_type::digest_bits>(leafs_number);
    std::vector<std::array<bool, hash_type::digest_bits>> public_keys;
    for (const auto &sk : secret_keys) {
        std::array<bool, hash_type::digest_bits> pk;
        hash<merkle_hash_type>(sk, std::begin(pk));
        public_keys.emplace_back(pk);
    }
    nil::crypto3::containers::merkle_tree<merkle_hash_type, arity> tree(std::cbegin(public_keys),
                                                                        std::cend(public_keys));
    std::size_t proof_idx = std::rand() % leafs_number;
    nil::crypto3::containers::merkle_proof<merkle_hash_type, arity> proof(tree, proof_idx);
    nil::crypto3::containers::merkle_proof<merkle_hash_type, arity> proof_wrong(tree, (proof_idx + 1) % leafs_number);

    auto tree_pk_leaf = tree[proof_idx];
    std::vector<bool> pk_leaf = hash<merkle_hash_type>(public_keys[proof_idx]);

    BOOST_ASSERT(tree_pk_leaf.size() == pk_leaf.size());
    for (auto i = 0; i < pk_leaf.size(); ++i) {
        BOOST_ASSERT(tree_pk_leaf[i] == pk_leaf[i]);
    }

    auto sk_wrong = secret_keys[proof_idx];
    sk_wrong[0] = !sk_wrong[0];

    auto root = tree.root();
    auto root_wrong = root;
    root_wrong[0] = !root_wrong[0];

    std::vector<bool> m = {0, 1, 0, 0, 0, 0, 0};
    auto m_wrong = m;
    m_wrong[0] = !m_wrong[0];

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });

    std::vector<bool> eid_sk;
    std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
    std::copy(std::cbegin(secret_keys[proof_idx]), std::cend(secret_keys[proof_idx]), std::back_inserter(eid_sk));
    std::vector<bool> sn = hash<hash_type>(eid_sk);
    auto sn_wrong = sn;
    sn_wrong[0] = !sn_wrong[0];

    /* execute test */
    blueprint<field_type> bp;
    nil::crypto3::zk::detail::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    components::block_variable<field_type> m_block(bp, m.size());
    components::block_variable<field_type> eid_block(bp, eid.size());
    components::block_variable<field_type> sk_block(bp, secret_keys[proof_idx].size());
    components::digest_variable<field_type> sn_digest(bp, hash_component::digest_bits);
    components::digest_variable<field_type> root_digest(bp, merkle_hash_component::digest_bits);
    merkle_proof_component path_var(bp, tree_depth);
    voting_component vote_var(bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
                              nil::crypto3::zk::detail::blueprint_variable<field_type>(0));

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();

    std::cout << "Constraints number: " << bp.num_constraints() << std::endl;

    path_var.generate_r1cs_witness(proof);
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    auto address = path_var.address;
    BOOST_CHECK(address_bits_va.get_field_element_from_bits(bp) == path_var.address);
    m_block.generate_r1cs_witness(m);
    eid_block.generate_r1cs_witness(eid);
    sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
    vote_var.generate_r1cs_witness(root, sn);
    BOOST_CHECK(bp.is_satisfied());

    // false positive test with wrong root
    root_digest.generate_r1cs_witness(root_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    root_digest.generate_r1cs_witness(root);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong sk
    sk_block.generate_r1cs_witness(sk_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong address
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address - 1);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong sn
    sn_digest.generate_r1cs_witness(sn_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    sn_digest.generate_r1cs_witness(sn);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong m
    m_block.generate_r1cs_witness(m_wrong);
    BOOST_CHECK(!bp.is_satisfied());

    // reset blueprint in the correct state
    m_block.generate_r1cs_witness(m);
    BOOST_CHECK(bp.is_satisfied());
    // false positive test with wrong path
    path_var.generate_r1cs_witness(proof_wrong, true);
    BOOST_CHECK(!bp.is_satisfied());
}

BOOST_AUTO_TEST_SUITE(voting_component_test_suite)

BOOST_AUTO_TEST_CASE(voting_component_jubjub_pedersen_test) {
    test_jubjub_pedersen_encrypted_input_voting_component();
}

BOOST_AUTO_TEST_CASE(voting_component_jubjub_merkle_container_pedersen_test) {
    test_jubjub_merkle_container_pedersen_encrypted_input_voting_component();
}

BOOST_AUTO_TEST_SUITE_END()