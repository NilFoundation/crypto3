#ifndef CRYPTO3_PUBKEY_XMSS_VERIFICATION_OPERATION_HPP
#define CRYPTO3_PUBKEY_XMSS_VERIFICATION_OPERATION_HPP

#include <array>
#include <cstddef>
#include <iterator>
#include <string>

#include <nil/crypto3/utilities/types.hpp>

#include <nil/crypto3/pubkey/pk_operations.hpp>

#include <nil/crypto3/pubkey/xmss/xmss_publickey.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_common_ops.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_signature.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * Provides signature verification capabilities for Extended Hash-Based
         * Signatures (XMSS).
         **/
        class XMSS_Verification_Operation final : public virtual pk_operations::verification, public XMSS_Common_Ops {
        public:
            XMSS_Verification_Operation(const XMSS_PublicKey &public_key);

            bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;

            void update(const uint8_t msg[], size_t msg_len) override;

        private:
            /**
             * Algorithm 13: "XMSS_rootFromSig"
             * Computes a root node using an XMSS signature, a message and a seed.
             *
             * @param msg A message.
             * @param sig The XMSS signature for msg.
             * @param ards A XMSS tree address.
             * @param seed A seed.
             *
             * @return An n-byte string holding the value of the root of a tree
             *         defined by the input parameters.
             **/
            secure_vector<uint8_t> root_from_signature(const XMSS_Signature &sig, const secure_vector<uint8_t> &msg,
                                                       XMSS_Address &ards, const secure_vector<uint8_t> &seed);

            /**
             * Algorithm 14: "XMSS_verify"
             * Verifies a XMSS signature using the corresponding XMSS public key.
             *
             * @param sig A XMSS signature.
             * @param msg The message signed with sig.
             * @param pub_key the public key
             *
             * @return true if signature sig is valid for msg, false otherwise.
             **/
            bool verify(const XMSS_Signature &sig, const secure_vector<uint8_t> &msg, const XMSS_PublicKey &pub_key);

            XMSS_PublicKey m_pub_key;
            secure_vector<uint8_t> m_msg_buf;
        };

        XMSS_Verification_Operation::XMSS_Verification_Operation(const XMSS_PublicKey &public_key) :
            XMSS_Common_Ops(public_key.xmss_oid()), m_pub_key(public_key), m_msg_buf(0) {
        }

        secure_vector<uint8_t> XMSS_Verification_Operation::root_from_signature(const XMSS_Signature &sig,
                                                                                const secure_vector<uint8_t> &msg,
                                                                                XMSS_Address &adrs,
                                                                                const secure_vector<uint8_t> &seed) {
            adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
            adrs.set_ots_address(sig.unused_leaf_index());

            XMSS_WOTS_PublicKey pub_key_ots(m_pub_key.wots_parameters().oid(), msg, sig.tree().ots_signature(), adrs,
                                            seed);

            adrs.set_type(XMSS_Address::Type::LTree_Address);
            adrs.set_ltree_address(sig.unused_leaf_index());

            std::array<secure_vector<uint8_t>, 2> node;
            create_l_tree(node[0], pub_key_ots, adrs, seed);

            adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
            adrs.set_tree_index(sig.unused_leaf_index());

            for (size_t k = 0; k < m_xmss_params.tree_height(); k++) {
                adrs.set_tree_height(k);
                if (((sig.unused_leaf_index() / (1 << k)) & 0x01) == 0) {
                    adrs.set_tree_index(adrs.get_tree_index() >> 1);
                    randomize_tree_hash(node[1], node[0], sig.tree().authentication_path()[k], adrs, seed);
                } else {
                    adrs.set_tree_index((adrs.get_tree_index() - 1) >> 1);
                    randomize_tree_hash(node[1], sig.tree().authentication_path()[k], node[0], adrs, seed);
                }
                node[0] = node[1];
            }
            return node[0];
        }

        bool XMSS_Verification_Operation::verify(const XMSS_Signature &sig, const secure_vector<uint8_t> &msg,
                                                 const XMSS_PublicKey &public_key) {
            XMSS_Address adrs;
            secure_vector<uint8_t> index_bytes;
            XMSS_Tools::concat(index_bytes, sig.unused_leaf_index(), m_xmss_params.element_size());
            secure_vector<uint8_t> msg_digest = m_hash.h_msg(sig.randomness(), public_key.root(), index_bytes, msg);

            secure_vector<uint8_t> node = root_from_signature(sig, msg_digest, adrs, public_key.public_seed());

            return (node == public_key.root());
        }

        // FIXME: XMSS signature verification requires the "randomness" parameter out
        // of the XMSS signature, which is part of the prefix that is hashed before
        // msg. Since the signature is unknown till sign() is called all message
        // content has to be buffered. For large messages this can be inconvenient or
        // impossible.
        // Possible solution: Change pk_operations::verification interface to take the
        // signature as constructor argument, make sign a parameterless member call.
        void XMSS_Verification_Operation::update(const uint8_t msg[], size_t msg_len) {
            std::copy(msg, msg + msg_len, std::back_inserter(m_msg_buf));
        }

        bool XMSS_Verification_Operation::is_valid_signature(const uint8_t sig[], size_t sig_len) {
            try {
                XMSS_Signature signature(m_pub_key.xmss_parameters().oid(), secure_vector<uint8_t>(sig, sig + sig_len));
                bool result = verify(signature, m_msg_buf, m_pub_key);
                m_msg_buf.clear();
                return result;
            } catch (Integrity_Failure &) {
                m_msg_buf.clear();
                return false;
            }
        }
    }    // namespace crypto3
}    // namespace nil

#endif
