#ifndef CRYPTO3_XMSS_SIGNATURE_OPERATION_H_
#define CRYPTO3_XMSS_SIGNATURE_OPERATION_H_

#include <cstddef>
#include <string>

#include <nil/crypto3/utilities/secmem.hpp>
#include <nil/crypto3/utilities/types.hpp>

#include <nil/crypto3/pubkey/pk_operations.hpp>

#include <nil/crypto3/pubkey/xmss/xmss_parameters.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_privatekey.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_address.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_common_ops.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_signature.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_publickey.hpp>

namespace nil {
    namespace crypto3 {

/**
 * Signature generation operation for Extended Hash-Based Signatures (XMSS) as
 * defined in:
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     draft-itrf-cfrg-xmss-hash-based-signatures-06
 *     Release: July 2016.
 *     https://datatracker.ietf.org/doc/
 *     draft-irtf-cfrg-xmss-hash-based-signatures/?include_text=1
 **/
        class XMSS_Signature_Operation final : public virtual pk_operations::signature, public XMSS_Common_Ops {
        public:
            XMSS_Signature_Operation(const XMSS_PrivateKey &private_key);

            /**
             * Creates an XMSS signature for the message provided through call to
             * update().
             *
             * @return serialized XMSS signature.
             **/
            secure_vector <uint8_t> sign(RandomNumberGenerator &) override;

            void update(const uint8_t msg[], size_t msg_len) override;

        private:
            /**
             * Algorithm 11: "treeSig"
             * Generate a WOTS+ signature on a message with corresponding auth path.
             *
             * @param msg A message.
             * @param xmss_priv_key A XMSS private key.
             * @param adrs A XMSS Address.
             **/
            XMSS_WOTS_PublicKey::TreeSignature generate_tree_signature(const secure_vector <uint8_t> &msg,
                                                                       XMSS_PrivateKey &xmss_priv_key,
                                                                       XMSS_Address &adrs);

            /**
             * Algorithm 12: "XMSS_sign"
             * Generate an XMSS signature and update the XMSS secret key
             *
             * @param msg A message to sign of arbitrary length.
             * @param [out] xmss_priv_key A XMSS private key. The private key will be
             *              updated during the signing process.
             *
             * @return The signature of msg signed using xmss_priv_key.
             **/
            XMSS_Signature sign(const secure_vector <uint8_t> &msg, XMSS_PrivateKey &xmss_priv_key);

            wots_keysig_t build_auth_path(XMSS_PrivateKey &priv_key, XMSS_Address &adrs);

            void initialize();

            XMSS_PrivateKey m_priv_key;
            secure_vector <uint8_t> m_randomness;
            size_t m_leaf_idx;
            bool m_is_initialized;
        };
    }
}

#endif

