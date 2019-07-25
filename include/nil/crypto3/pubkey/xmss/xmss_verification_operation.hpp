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
            secure_vector <uint8_t> root_from_signature(const XMSS_Signature &sig, const secure_vector <uint8_t> &msg,
                                                        XMSS_Address &ards, const secure_vector <uint8_t> &seed);

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
            bool verify(const XMSS_Signature &sig, const secure_vector <uint8_t> &msg, const XMSS_PublicKey &pub_key);

            XMSS_PublicKey m_pub_key;
            secure_vector <uint8_t> m_msg_buf;
        };
    }
}

#endif
