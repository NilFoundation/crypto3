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

#define BOOST_TEST_MODULE pubkey_elgamal_verifiable_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/generate_keypair.hpp>
#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_encryption.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_decryption.hpp>
#include <nil/crypto3/pubkey/algorithm/rerandomize.hpp>

#include <nil/crypto3/pubkey/modes/verifiable_encryption.hpp>

#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/algorithms/generate.hpp>

#include <nil/crypto3/zk/components/voting/encrypted_input_voting.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::random;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    std::cout << e.data[0].data << ", " << e.data[1].data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp3<FieldParams> &e) {
    std::cout << e.data[0].data << ", " << e.data[1].data << ", " << e.data[2].data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]" << std::endl;
}

template<typename CurveParams, typename Form>
void print_curve_point(std::ostream &os,
                       const curves::detail::curve_element<CurveParams, Form, curves::coordinates::affine> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "] )" << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, curves::coordinates::jacobian_with_a4_0>::value>::type
    print_curve_point(std::ostream &os, const curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X);
    os << "], Y: [";
    print_field_element(os, p.Y);
    os << "], Z:[";
    print_field_element(os, p.Z);
    os << "] )" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename CurveParams, typename Form, typename Coordinates>
            struct print_log_value<curves::detail::curve_element<CurveParams, Form, Coordinates>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams, Form, Coordinates> const &p) {
                    print_curve_point(os, p);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

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

BOOST_AUTO_TEST_SUITE(pubkey_elgamal_verifiable_auto_test_suite)

BOOST_AUTO_TEST_CASE(elgamal_verifiable_auto_test) {
    using pairing_curve_type = curves::bls12_381;
    using curve_type = curves::jubjub;
    using base_points_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, base_points_generator_hash_type, hash_params>;
    using hash_type = typename hash_component::hash_type;
    using merkle_hash_component = hash_component;
    using merkle_hash_type = typename merkle_hash_component::hash_type;
    using field_type = typename hash_component::field_type;
    constexpr std::size_t arity = 2;
    using voting_component =
        components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using encryption_scheme = elgamal_verifiable<pairing_curve_type>;
    using proof_system = typename encryption_scheme::proof_system_type;

    /* prepare test */
    constexpr std::size_t tree_depth = 1;
    constexpr std::size_t participants_number = 1 << tree_depth;
    auto secret_keys = generate_random_data<bool, hash_type::digest_bits>(participants_number);
    std::vector<std::array<bool, hash_type::digest_bits>> public_keys;
    for (const auto &sk : secret_keys) {
        std::array<bool, hash_type::digest_bits> pk;
        hash<merkle_hash_type>(sk, std::begin(pk));
        public_keys.emplace_back(pk);
    }
    merkle_tree<merkle_hash_type, arity> tree(public_keys);
    std::size_t proof_idx = std::rand() % participants_number;
    merkle_proof<merkle_hash_type, arity> proof(tree, proof_idx);
    auto tree_pk_leaf = tree[proof_idx];

    std::vector<bool> m = {0, 1, 0, 0, 0, 0, 0};
    std::vector<typename pairing_curve_type::scalar_field_type::value_type> m_field;
    for (const auto m_i : m) {
        m_field.emplace_back(std::size_t(m_i));
    }
    // std::vector<>

    const std::size_t eid_size = 64;
    std::vector<bool> eid(eid_size);
    std::generate(eid.begin(), eid.end(), [&]() { return std::rand() % 2; });

    std::vector<bool> eid_sk;
    std::copy(std::cbegin(eid), std::cend(eid), std::back_inserter(eid_sk));
    std::copy(std::cbegin(secret_keys[proof_idx]), std::cend(secret_keys[proof_idx]), std::back_inserter(eid_sk));
    std::vector<bool> sn = hash<hash_type>(eid_sk);

    components::blueprint<field_type> bp;
    components::block_variable<field_type> m_block(bp, m.size());
    components::block_variable<field_type> eid_block(bp, eid.size());
    components::digest_variable<field_type> sn_digest(bp, hash_component::digest_bits);
    components::digest_variable<field_type> root_digest(bp, merkle_hash_component::digest_bits);
    components::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    merkle_proof_component path_var(bp, tree_depth);
    components::block_variable<field_type> sk_block(bp, secret_keys[proof_idx].size());
    voting_component vote_var(bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
                              components::blueprint_variable<field_type>(0));

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();

    BOOST_REQUIRE(!bp.is_satisfied());
    path_var.generate_r1cs_witness(proof);
    BOOST_REQUIRE(!bp.is_satisfied());
    address_bits_va.fill_with_bits_of_ulong(bp, path_var.address);
    BOOST_REQUIRE(!bp.is_satisfied());
    auto address = path_var.address;
    BOOST_REQUIRE(address_bits_va.get_field_element_from_bits(bp) == path_var.address);
    m_block.generate_r1cs_witness(m);
    BOOST_REQUIRE(!bp.is_satisfied());
    eid_block.generate_r1cs_witness(eid);
    BOOST_REQUIRE(!bp.is_satisfied());
    sk_block.generate_r1cs_witness(secret_keys[proof_idx]);
    BOOST_REQUIRE(!bp.is_satisfied());
    vote_var.generate_r1cs_witness(tree.root(), sn);
    BOOST_REQUIRE(bp.is_satisfied());

    std::cout << "Constraints number: " << bp.num_constraints() << std::endl;

    bp.set_input_sizes(vote_var.get_input_size());

    typename proof_system::keypair_type gg_keypair = snark::generate<proof_system>(bp.get_constraint_system());

    algebraic_random_device<typename pairing_curve_type::scalar_field_type> d;
    std::vector<typename pairing_curve_type::scalar_field_type::value_type> rnd;
    for (std::size_t i = 0; i < m.size() * 3 + 2; ++i) {
        rnd.emplace_back(d());
    }
    typename encryption_scheme::keypair_type keypair =
        generate_keypair<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>(rnd,
                                                                                             {gg_keypair, m.size()});

    typename encryption_scheme::cipher_type cipher_text =
        encrypt<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>(
            m_field, {d(), std::get<0>(keypair), gg_keypair, bp.primary_input(), bp.auxiliary_input()});
    typename encryption_scheme::decipher_type decipher_text =
        decrypt<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>(
            cipher_text.first, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
    BOOST_REQUIRE(decipher_text.first.size() == m_field.size());
    for (std::size_t i = 0; i < m_field.size(); ++i) {
        BOOST_REQUIRE(decipher_text.first[i] == m_field[i]);
    }

    typename proof_system::primary_input_type pinput = bp.primary_input();
    bool enc_verification_ans = verify_encryption<encryption_scheme>(
        cipher_text.first,
        {std::get<0>(keypair), gg_keypair, cipher_text.second,
         typename proof_system::primary_input_type {std::cbegin(pinput) + m.size(), std::cend(pinput)}});
    BOOST_REQUIRE(enc_verification_ans);

    bool dec_verification_ans = verify_decryption<encryption_scheme>(
        cipher_text.first, decipher_text.first, {std::get<2>(keypair), gg_keypair, decipher_text.second});
    BOOST_REQUIRE(dec_verification_ans);

    /// Rerandomized cipher text
    std::vector<typename pairing_curve_type::scalar_field_type::value_type> rnd_rerandomization;
    for (std::size_t i = 0; i < 3; ++i) {
        rnd_rerandomization.emplace_back(d());
    }
    typename encryption_scheme::cipher_type rerand_cipher_text = rerandomize<encryption_scheme>(
        rnd_rerandomization, cipher_text.first, {std::get<0>(keypair), gg_keypair, cipher_text.second});

    /// Decryption of the rerandomized cipher text
    typename encryption_scheme::decipher_type decipher_rerand_text =
        decrypt<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>(
            rerand_cipher_text.first, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
    BOOST_REQUIRE(decipher_rerand_text.first.size() == m_field.size());
    for (std::size_t i = 0; i < m_field.size(); ++i) {
        BOOST_REQUIRE(decipher_rerand_text.first[i] == m_field[i]);
    }

    /// Encryption verification of the rerandomized cipher text
    enc_verification_ans = verify_encryption<encryption_scheme>(
        rerand_cipher_text.first,
        {std::get<0>(keypair), gg_keypair, rerand_cipher_text.second,
         typename proof_system::primary_input_type {std::cbegin(pinput) + m.size(), std::cend(pinput)}});
    BOOST_REQUIRE(enc_verification_ans);

    /// Decryption verification of the rerandomized cipher text
    dec_verification_ans =
        verify_decryption<encryption_scheme>(rerand_cipher_text.first, decipher_rerand_text.first,
                                             {std::get<2>(keypair), gg_keypair, decipher_rerand_text.second});
    BOOST_REQUIRE(dec_verification_ans);

    // TODO: add status return
    // /// False-positive tests
    // auto cipher_text_wrong = cipher_text.first;
    // for (auto & c: cipher_text_wrong) {
    //     c = c + std::iterator_traits<typename decltype(cipher_text.first)::iterator>::value_type::one();
    // }
    // typename encryption_scheme::decipher_type decipher_text_wrong =
    //     decrypt<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>(
    //         cipher_text_wrong, {std::get<1>(keypair), std::get<2>(keypair), gg_keypair});
    // BOOST_REQUIRE(decipher_text.first.size() == m_field.size());
    // bool wrong_decryption_ans = true;
    // for (std::size_t i = 0; i < m_field.size(); ++i) {
    //     wrong_decryption_ans &= (decipher_text.first[i] == m_field[i]);
    // }
    // BOOST_REQUIRE(!wrong_decryption_ans);

}

BOOST_AUTO_TEST_SUITE_END()
