//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE merkle_tree_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/jubjub.hpp>

// TODO: fix sha256 component
// #include <nil/blueprint/components/hashes/sha256/sha256_component.hpp>
#include <nil/blueprint/components/hashes/pedersen.hpp>

// TODO: fix update component
// #include <nil/blueprint/components/merkle_tree/update.hpp>
#include <nil/blueprint/components/merkle_tree/validate.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

// template<typename FieldType, typename Hash>
// void test_merkle_tree_check_update_component() {
//     /* prepare test */
//     const std::size_t digest_len = Hash::get_digest_len();
//
//     const std::size_t tree_depth = 16;
//     std::vector<snark::merkle_authentication_node> prev_path(tree_depth);
//
//     std::vector<bool> prev_load_hash(digest_len);
//     std::generate(prev_load_hash.begin(), prev_load_hash.end(), [&]() { return std::rand() % 2; });
//     std::vector<bool> prev_store_hash(digest_len);
//     std::generate(prev_store_hash.begin(), prev_store_hash.end(), [&]() { return std::rand() % 2; });
//
//     std::vector<bool> loaded_leaf = prev_load_hash;
//     std::vector<bool> stored_leaf = prev_store_hash;
//
//     std::vector<bool> address_bits;
//
//     std::size_t address = 0;
//     for (long level = tree_depth - 1; level >= 0; --level) {
//         const bool computed_is_right = (std::rand() % 2);
//         address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
//         address_bits.push_back(computed_is_right);
//         std::vector<bool> other(digest_len);
//         std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });
//
//         std::vector<bool> load_block = prev_load_hash;
//         load_block.insert(computed_is_right ? load_block.begin() : load_block.end(), other.begin(), other.end());
//         std::vector<bool> store_block = prev_store_hash;
//         store_block.insert(computed_is_right ? store_block.begin() : store_block.end(), other.begin(), other.end());
//
//         std::vector<bool> load_h = Hash::get_hash(load_block);
//         std::vector<bool> store_h = Hash::get_hash(store_block);
//
//         prev_path[level] = other;
//
//         prev_load_hash = load_h;
//         prev_store_hash = store_h;
//     }
//
//     std::vector<bool> load_root = prev_load_hash;
//     std::vector<bool> store_root = prev_store_hash;
//
//     /* execute the test */
//     components::blueprint<FieldType> bp;
//     components::blueprint_variable_vector<FieldType> address_bits_va;
//     address_bits_va.allocate(bp, tree_depth);
//     components::digest_variable<FieldType> prev_leaf_digest(bp, digest_len);
//     components::digest_variable<FieldType> prev_root_digest(bp, digest_len);
//     components::merkle_authentication_path_variable<FieldType, Hash> prev_path_var(bp, tree_depth);
//     components::digest_variable<FieldType> next_leaf_digest(bp, digest_len);
//     components::digest_variable<FieldType> next_root_digest(bp, digest_len);
//     components::merkle_authentication_path_variable<FieldType, Hash> next_path_var(bp, tree_depth);
//     components::merkle_tree_check_update_components<FieldType, Hash> mls(
//         bp, tree_depth, address_bits_va, prev_leaf_digest, prev_root_digest, prev_path_var, next_leaf_digest,
//         next_root_digest, next_path_var, components::blueprint_variable<FieldType>(0));
//
//     prev_path_var.generate_gates();
//     mls.generate_gates();
//
//     address_bits_va.fill_with_bits(bp, address_bits);
//     BOOST_REQUIRE(address_bits_va.get_field_element_from_bits(bp) == address);
//     prev_leaf_digest.generate_assignments(loaded_leaf);
//     prev_path_var.generate_assignments(address, prev_path);
//     next_leaf_digest.generate_assignments(stored_leaf);
//     address_bits_va.fill_with_bits(bp, address_bits);
//     mls.generate_assignments();
//
//     /* make sure that update check will check for the right things */
//     prev_leaf_digest.generate_assignments(loaded_leaf);
//     next_leaf_digest.generate_assignments(stored_leaf);
//     prev_root_digest.generate_assignments(load_root);
//     next_root_digest.generate_assignments(store_root);
//     address_bits_va.fill_with_bits(bp, address_bits);
//     BOOST_REQUIRE(bp.is_satisfied());
//
//     const std::size_t num_constraints = bp.num_constraints();
//     const std::size_t expected_constraints =
//         components::merkle_tree_check_update_components<FieldType, Hash>::expected_constraints(tree_depth);
//     BOOST_REQUIRE(num_constraints == expected_constraints);
// }

// template<typename FieldType, typename Hash>
// void test_merkle_tree_check_read_component() {
//     /* prepare test */
//     const std::size_t digest_len = Hash::get_digest_len();
//     const std::size_t tree_depth = 16;
//     std::vector<snark::merkle_authentication_node> path(tree_depth);
//
//     std::vector<bool> prev_hash(digest_len);
//     std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
//     std::vector<bool> leaf = prev_hash;
//
//     std::vector<bool> address_bits;
//
//     std::size_t address = 0;
//     for (long level = tree_depth - 1; level >= 0; --level) {
//         const bool computed_is_right = (std::rand() % 2);
//         address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
//         address_bits.push_back(computed_is_right);
//         std::vector<bool> other(digest_len);
//         std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });
//
//         std::vector<bool> block = prev_hash;
//         block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
//         std::vector<bool> h = Hash::get_hash(block);
//
//         path[level] = other;
//
//         prev_hash = h;
//     }
//     std::vector<bool> root = prev_hash;
//
//     /* execute test */
//     components::blueprint<FieldType> bp;
//     components::blueprint_variable_vector<FieldType> address_bits_va;
//     address_bits_va.allocate(bp, tree_depth);
//     components::digest_variable<FieldType> leaf_digest(bp, digest_len);
//     components::digest_variable<FieldType> root_digest(bp, digest_len);
//     components::merkle_authentication_path_variable<FieldType, Hash> path_var(bp, tree_depth);
//     components::merkle_tree_check_read_component<FieldType, Hash> ml(bp, tree_depth, address_bits_va, leaf_digest,
//                                                                      root_digest, path_var,
//                                                                      components::blueprint_variable<FieldType>(0));
//
//     path_var.generate_gates();
//     ml.generate_gates();
//
//     address_bits_va.fill_with_bits(bp, address_bits);
//     BOOST_REQUIRE(address_bits_va.get_field_element_from_bits(bp) == address);
//     leaf_digest.generate_assignments(leaf);
//     path_var.generate_assignments(address, path);
//     ml.generate_assignments();
//
//     /* make sure that read checker didn't accidentally overwrite anything */
//     address_bits_va.fill_with_bits(bp, address_bits);
//     leaf_digest.generate_assignments(leaf);
//     root_digest.generate_assignments(root);
//     BOOST_REQUIRE(bp.is_satisfied());
//
//     const std::size_t num_constraints = bp.num_constraints();
//     const std::size_t expected_constraints =
//         components::merkle_tree_check_read_component<FieldType, Hash>::expected_constraints(tree_depth);
//     BOOST_REQUIRE(num_constraints == expected_constraints);
// }

// template<typename CurveType>
// void test_all_merkle_tree_components() {
//     typedef typename CurveType::scalar_field_type scalar_field_type;
//
//     // for now all CRH components are knapsack CRH's; can be easily extended
//     // later to more expressive selector types.
//     using crh_with_field_out_component = components::knapsack_crh_with_field_out_component<scalar_field_type>;
//     using crh_with_bit_out_component = components::knapsack_crh_with_bit_out_component<scalar_field_type>;
//
//     test_merkle_tree_check_read_component<scalar_field_type, components::knapsack_crh_with_bit_out_component>();
//     test_merkle_tree_check_read_component<scalar_field_type,
//                                           components::sha256_two_to_one_hash_component<scalar_field_type>>();
//
//     test_merkle_tree_check_update_component<scalar_field_type, components::knapsack_crh_with_bit_out_component>();
//     test_merkle_tree_check_update_component<scalar_field_type,
//                                             components::sha256_two_to_one_hash_component<scalar_field_type>>();
// }

template<typename Curve, typename BasePointsGeneratorHash, typename HashParams>
std::vector<bool> calculate_pedersen_via_component(const std::vector<bool> &in_bits) {
    using hash_component = components::pedersen<Curve, BasePointsGeneratorHash, HashParams>;
    using field_type = typename hash_component::field_type;

    components::blueprint<field_type> bp_bits;
    components::block_variable<field_type> in_block(bp_bits, in_bits.size());
    in_block.generate_assignments(in_bits);

    hash_component hash_comp_bits(bp_bits, in_block);
    hash_comp_bits.generate_assignments();
    hash_comp_bits.generate_gates();
    return hash_comp_bits.result.get_digest();
}

void test_jubjub_pedersen_merkle_tree_container_check_validate_component() {
    using curve_type = curves::jubjub;
    using bp_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, bp_generator_hash_type, hash_params>;
    using field_type = typename hash_component::field_type;
    constexpr std::size_t arity = 2;
    using merkle_proof_component = components::merkle_proof<hash_component, field_type, arity>;
    using merkle_validate_component = components::merkle_proof_validate<hash_component, field_type, arity>;

    /* prepare test */
    const std::size_t digest_len = hash_component::get_digest_len();
    const std::size_t tree_depth = 2;
    const std::size_t leafs_number = nil::crypto3::detail::pow(arity, tree_depth);

    // TODO: remove copy from array to vector
    std::vector<std::array<bool, hash_component::digest_bits>> leafs;
    std::vector<std::vector<bool>> leafs_v;
    for (std::size_t i = 0; i < leafs_number; ++i) {
        std::array<bool, hash_component::digest_bits> leaf;
        std::generate(leaf.begin(), leaf.end(), [&]() { return std::rand() % 2; });
        leafs.emplace_back(leaf);
    }

    std::size_t leaf_idx = 0;
    typename merkle_proof_component::merkle_tree_container tree(leafs);
    typename merkle_proof_component::merkle_proof_container proof(tree, leaf_idx);
    BOOST_CHECK(proof.validate(leafs[leaf_idx]));
    BOOST_CHECK(!proof.validate(leafs[(leaf_idx + 1) % leafs_number]));
    for (std::size_t i = 0; i < leafs_number; ++i) {
        leafs_v.emplace_back(
            static_cast<std::vector<bool>>(nil::crypto3::hash<typename hash_component::hash_type>(leafs[i])));
    }

    /* execute test */
    components::blueprint<field_type> bp;
    components::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    components::digest_variable<field_type> leaf_digest(bp, digest_len);
    components::digest_variable<field_type> root_digest(bp, digest_len);
    merkle_proof_component path_var(bp, tree_depth);
    merkle_validate_component ml(bp, tree_depth, address_bits_va, leaf_digest, root_digest, path_var,
                                 components::blueprint_variable<field_type>(0));

    path_var.generate_gates();
    ml.generate_gates();

    leaf_digest.generate_assignments(leafs_v[leaf_idx]);
    path_var.generate_assignments(proof);
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    BOOST_REQUIRE(address_bits_va.get_field_element_from_bits(bp) == path_var.address);
    ml.generate_assignments();

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    leaf_digest.generate_assignments(leafs_v[leaf_idx]);
    /// Very important step, hidden error could appear without it. merkle_validate_component use
    /// bit_vector_copy_component to copy computed root into root_digest, so without this step internal check of the
    /// computed step will always be positive
    root_digest.generate_assignments(merkle_proof_component::root(proof));
    BOOST_REQUIRE(bp.is_satisfied());

    auto root_wrong = merkle_proof_component::root(proof);
    root_wrong[0] = !root_wrong[0];
    // false negative test with wrong root
    root_digest.generate_assignments(root_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // reset blueprint in the correct state
    root_digest.generate_assignments(merkle_proof_component::root(proof));
    BOOST_REQUIRE(bp.is_satisfied());
    // false negative test with wrong leaf
    auto leaf_digest_wrong = leafs_v[leaf_idx];
    leaf_digest_wrong[0] = !leaf_digest_wrong[0];
    leaf_digest.generate_assignments(leaf_digest_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // reset blueprint in the correct state
    leaf_digest.generate_assignments(leafs_v[leaf_idx]);
    BOOST_REQUIRE(bp.is_satisfied());
    // false negative test with wrong path
    typename merkle_proof_component::merkle_proof_container proof_wrong(tree, (leaf_idx + 1) % leafs_number);
    path_var.generate_assignments(proof_wrong);
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    BOOST_REQUIRE(!bp.is_satisfied());
}

void test_jubjub_pedersen_merkle_tree_check_validate_component() {
    using curve_type = curves::jubjub;
    using bp_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, bp_generator_hash_type, hash_params>;
    using field_type = typename hash_component::field_type;
    constexpr std::size_t arity = 2;
    using merkle_proof_component = components::merkle_proof<hash_component, field_type, arity>;
    using merkle_validate_component = components::merkle_proof_validate<hash_component, field_type, arity>;

    /* prepare test */
    const std::size_t digest_len = hash_component::get_digest_len();
    const std::size_t tree_depth = 16;
    std::vector<snark::merkle_authentication_node> path(tree_depth);

    std::vector<bool> prev_hash(digest_len);
    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    std::vector<bool> leaf = prev_hash;
    auto leaf_wrong = leaf;
    leaf_wrong[0] = !leaf_wrong[0];

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
        std::vector<bool> h = calculate_pedersen_via_component<curve_type, bp_generator_hash_type, hash_params>(block);

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

    /* execute test */
    components::blueprint<field_type> bp;
    components::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    components::digest_variable<field_type> leaf_digest(bp, digest_len);
    components::digest_variable<field_type> root_digest(bp, digest_len);
    merkle_proof_component path_var(bp, tree_depth);
    merkle_validate_component ml(bp, tree_depth, address_bits_va, leaf_digest, root_digest, path_var,
                                 components::blueprint_variable<field_type>(0));

    path_var.generate_gates();
    ml.generate_gates();

    address_bits_va.fill_with_bits(bp, address_bits);
    BOOST_REQUIRE(address_bits_va.field_element_from_bits(bp) == address);
    leaf_digest.generate_assignments(leaf);
    path_var.generate_assignments(address, path);
    ml.generate_assignments();

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(bp, address_bits);
    leaf_digest.generate_assignments(leaf);
    /// Very important step, hidden error could appear without it. merkle_validate_component use
    /// bit_vector_copy_component to copy computed root into root_digest, so without this step internal check of the
    /// computed step will always be positive
    root_digest.generate_assignments(root);
    BOOST_REQUIRE(bp.is_satisfied());

    // false negative test with wrong root
    root_digest.generate_assignments(root_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // reset blueprint in the correct state
    root_digest.generate_assignments(root);
    BOOST_REQUIRE(bp.is_satisfied());
    // false negative test with wrong leaf
    leaf_digest.generate_assignments(leaf_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // reset blueprint in the correct state
    leaf_digest.generate_assignments(leaf);
    BOOST_REQUIRE(bp.is_satisfied());
    // false negative test with wrong path
    path_var.generate_assignments(address, path_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // reset blueprint in the correct state
    path_var.generate_assignments(address, path);
    BOOST_REQUIRE(bp.is_satisfied());
    // false negative test with wrong address
    address_bits_va.fill_with_bits(bp, address_bits_wrong);
    BOOST_REQUIRE(!bp.is_satisfied());

    // const std::size_t num_constraints = bp.num_constraints();
    // const std::size_t expected_constraints =
    //     components::merkle_tree_check_read_component<FieldType, Hash>::expected_constraints(tree_depth);
    // BOOST_REQUIRE(num_constraints == expected_constraints);
}

BOOST_AUTO_TEST_SUITE(merkle_tree_components_test_suite)

// BOOST_AUTO_TEST_CASE(merkle_tree_components_bls12_381_test) {
//
//     test_all_merkle_tree_components<curves::bls12<381>>();
// }
//
// BOOST_AUTO_TEST_CASE(merkle_tree_components_mnt4_test) {
//
//     test_all_merkle_tree_components<curves::mnt4<398>>();
// }
//
// BOOST_AUTO_TEST_CASE(merkle_tree_components_mnt6_test) {
//
//     test_all_merkle_tree_components<curves::mnt6<298>>();
// }

BOOST_AUTO_TEST_CASE(merkle_tree_components_jubjub_pedersen_test) {

    test_jubjub_pedersen_merkle_tree_container_check_validate_component();
    // test_jubjub_pedersen_merkle_tree_check_validate_component();
}

BOOST_AUTO_TEST_SUITE_END()