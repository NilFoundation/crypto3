//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_XMSS_WOTS_ADDRESSED_PRIVATEKEY_HPP
#define CRYPTO3_PUBKEY_XMSS_WOTS_ADDRESSED_PRIVATEKEY_HPP

#include <nil/crypto3/pubkey/xmss/xmss_address.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_addressed_publickey.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_privatekey.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * Wrapper class to pair an XMSS_WOTS_PrivateKey with an XMSS Address. Since
         * the pk_operations::signature interface does not allow an extra address
         * parameter to be passed to the sign(RandomNumberGenerator&), the address
         * needs to be stored together with the key and passed to the
         * XMSS_WOTS_Signature_Operation() on creation.
         **/
        class XMSS_WOTS_Addressed_PrivateKey final : public virtual XMSS_WOTS_Addressed_PublicKey,
                                                     public virtual private_key_policy {
        public:
            XMSS_WOTS_Addressed_PrivateKey(const XMSS_WOTS_PrivateKey &private_key) :
                XMSS_WOTS_Addressed_PublicKey(private_key), m_priv_key(private_key) {
            }

            XMSS_WOTS_Addressed_PrivateKey(const XMSS_WOTS_PrivateKey &private_key, const XMSS_Address &adrs) :
                XMSS_WOTS_Addressed_PublicKey(private_key, adrs), m_priv_key(private_key) {
            }

            XMSS_WOTS_Addressed_PrivateKey(XMSS_WOTS_PrivateKey &&private_key) :
                XMSS_WOTS_Addressed_PublicKey(XMSS_WOTS_PublicKey(private_key)), m_priv_key(std::move(private_key)) {
            }

            XMSS_WOTS_Addressed_PrivateKey(XMSS_WOTS_PrivateKey &&private_key, XMSS_Address &&adrs) :
                XMSS_WOTS_Addressed_PublicKey(XMSS_WOTS_PublicKey(private_key), std::move(adrs)),
                m_priv_key(std::move(private_key)) {
            }

            const XMSS_WOTS_PrivateKey &private_key() const {
                return m_priv_key;
            }

            XMSS_WOTS_PrivateKey &private_key() {
                return m_priv_key;
            }

            algorithm_identifier pkcs8_algorithm_identifier() const override {
                return m_priv_key.pkcs8_algorithm_identifier();
            }

            secure_vector<uint8_t> private_key_bits() const override {
                return m_priv_key.private_key_bits();
            }

        private:
            XMSS_WOTS_PrivateKey m_priv_key;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
