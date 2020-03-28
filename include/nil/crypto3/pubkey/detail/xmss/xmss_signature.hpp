//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_XMSS_SIGNATURE_HPP
#define CRYPTO3_PUBKEY_XMSS_SIGNATURE_HPP

#include <cstddef>
#include <nil/crypto3/utilities/exceptions.hpp>
#include <nil/crypto3/utilities/types.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/pubkey/xmss/xmss_parameters.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_publickey.hpp>

namespace nil {
    namespace crypto3 {

        class XMSS_Signature final {
        public:
            /**
             * Creates a signature from an XMSS signature method and a uint8_t sequence
             * representing a raw signature.
             *
             * @param oid XMSS signature method
             * @param raw_sig An XMSS signature serialized using
             *                XMSS_Signature::bytes().
             **/
            XMSS_Signature(XMSS_Parameters::xmss_algorithm_t oid, const secure_vector<uint8_t> &raw_sig);

            /**
             * Creates an XMSS Signature from a leaf index used for signature
             * generation, a random value and a tree signature.
             *
             * @param leaf_idx Leaf index used to generate the signature.
             * @param randomness A random value.
             * @param tree_sig A tree signature.
             **/
            XMSS_Signature(size_t leaf_idx, const secure_vector<uint8_t> &randomness,
                           const XMSS_WOTS_PublicKey::TreeSignature &tree_sig) :
                m_leaf_idx(leaf_idx),
                m_randomness(randomness), m_tree_sig(tree_sig) {
            }

            /**
             * Creates an XMSS Signature from a leaf index used for signature
             * generation, a random value and a tree signature.
             *
             * @param leaf_idx Leaf index used to generate the signature.
             * @param randomness A random value.
             * @param tree_sig A tree signature.
             **/
            XMSS_Signature(size_t leaf_idx, secure_vector<uint8_t> &&randomness,
                           XMSS_WOTS_PublicKey::TreeSignature &&tree_sig) :
                m_leaf_idx(leaf_idx),
                m_randomness(std::move(randomness)), m_tree_sig(std::move(tree_sig)) {
            }

            size_t unused_leaf_index() const {
                return m_leaf_idx;
            }

            void set_unused_leaf_idx(size_t idx) {
                m_leaf_idx = idx;
            }

            const secure_vector<uint8_t> randomness() const {
                return m_randomness;
            }

            secure_vector<uint8_t> &randomness() {
                return m_randomness;
            }

            void set_randomness(const secure_vector<uint8_t> &randomness) {
                m_randomness = randomness;
            }

            void set_randomness(secure_vector<uint8_t> &&randomness) {
                m_randomness = std::move(randomness);
            }

            const XMSS_WOTS_PublicKey::TreeSignature &tree() const {
                return m_tree_sig;
            }

            XMSS_WOTS_PublicKey::TreeSignature &tree() {
                return m_tree_sig;
            }

            void set_tree(const XMSS_WOTS_PublicKey::TreeSignature &tree_sig) {
                m_tree_sig = tree_sig;
            }

            void set_tree(XMSS_WOTS_PublicKey::TreeSignature &&tree_sig) {
                m_tree_sig = std::move(tree_sig);
            }

            /**
             * Generates a serialized representation of XMSS Signature by
             * concatenating the following elements in order:
             * 8-byte leaf index, n-bytes randomness, ots_signature,
             * authentication path.
             *
             * n is the element_size(), len equal to len(), h the tree height
             * defined by the chosen XMSS signature method.
             *
             * @return serialized signature, a sequence of
             *         (len + h + 1)n bytes.
             **/
            secure_vector<uint8_t> bytes() const;

        private:
            size_t m_leaf_idx;
            secure_vector<uint8_t> m_randomness;
            XMSS_WOTS_PublicKey::TreeSignature m_tree_sig;
        };

        XMSS_Signature::XMSS_Signature(XMSS_Parameters::xmss_algorithm_t oid, const secure_vector<uint8_t> &raw_sig) :
            m_leaf_idx(0), m_randomness(0, 0x00), m_tree_sig() {
            BOOST_ASSERT_MSG(sizeof(size_t) >=
                                 std::ceil(static_cast<float>((XMSS_Parameters(oid)).tree_height()) / 8.f),
                             "System type \"size_t\" not big enough to support"
                             " leaf index.");

            XMSS_Parameters xmss_params(oid);
            uint64_t leaf_idx = 0;
            for (size_t i = 0; i < 8; i++) {
                leaf_idx = ((leaf_idx << 8) | raw_sig[i]);
            }

            if (leaf_idx >= (1ull << (xmss_params.tree_height() - 1))) {
                throw Integrity_Failure(
                    "XMSS signature leaf index out of "
                    "bounds.");
            }
            m_leaf_idx = static_cast<size_t>(leaf_idx);

            auto begin = raw_sig.begin() + sizeof(uint64_t);
            auto end = begin + xmss_params.element_size();
            std::copy(begin, end, std::back_inserter(m_randomness));

            for (size_t i = 0; i < xmss_params.len(); i++) {
                begin = end;
                end = begin + xmss_params.element_size();
                m_tree_sig.ots_signature().push_back(secure_vector<uint8_t>(0));
                m_tree_sig.ots_signature().back().reserve(xmss_params.element_size());
                std::copy(begin, end, std::back_inserter(m_tree_sig.ots_signature().back()));
            }

            for (size_t i = 0; i < xmss_params.tree_height(); i++) {
                begin = end;
                end = begin + xmss_params.element_size();
                m_tree_sig.authentication_path().push_back(secure_vector<uint8_t>(0));
                m_tree_sig.authentication_path().back().reserve(xmss_params.element_size());
                std::copy(begin, end, std::back_inserter(m_tree_sig.authentication_path().back()));
            }
        }

        secure_vector<uint8_t> XMSS_Signature::bytes() const {
            secure_vector<uint8_t> result {static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 56U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 48U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 40U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 32U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 24U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 16U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx) >> 8U),
                                           static_cast<uint8_t>(static_cast<uint64_t>(m_leaf_idx))};

            std::copy(m_randomness.begin(), m_randomness.end(), std::back_inserter(result));

            for (const auto &sig : tree().ots_signature()) {
                std::copy(sig.begin(), sig.end(), std::back_inserter(result));
            }

            for (const auto &auth : tree().authentication_path()) {
                std::copy(auth.begin(), auth.end(), std::back_inserter(result));
            }
            return result;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
