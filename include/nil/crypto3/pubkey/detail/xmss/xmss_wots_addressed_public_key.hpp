#ifndef CRYPTO3_XMSS_WOTS_ADDRESSED_PUBLICKEY_H_
#define CRYPTO3_XMSS_WOTS_ADDRESSED_PUBLICKEY_H_

#include <nil/crypto3/pubkey/xmss/xmss_address.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_publickey.hpp>

namespace nil {
    namespace crypto3 {

/**
 * Wrapper class to pair a XMSS_WOTS_PublicKey with an XMSS Address. Since
 * the pk_operations::verification interface does not allow an extra address
 * parameter to be passed to the sign(RandomNumberGenerator&), the address
 * needs to be stored together with the key and passed to the
 * XMSS_WOTS_Verification_Operation() on creation.
 **/
        class XMSS_WOTS_Addressed_PublicKey : public virtual public_key_policy {
        public:
            XMSS_WOTS_Addressed_PublicKey(const XMSS_WOTS_PublicKey &public_key) : m_pub_key(public_key), m_adrs() {
            }

            XMSS_WOTS_Addressed_PublicKey(const XMSS_WOTS_PublicKey &public_key, const XMSS_Address &adrs) : m_pub_key(
                    public_key), m_adrs(adrs) {
            }

            XMSS_WOTS_Addressed_PublicKey(XMSS_WOTS_PublicKey &&public_key) : m_pub_key(std::move(public_key)),
                    m_adrs() {
            }

            XMSS_WOTS_Addressed_PublicKey(XMSS_WOTS_PublicKey &&public_key, XMSS_Address &&adrs) : m_pub_key(
                    std::move(public_key)), m_adrs(std::move(adrs)) {
            }

            const XMSS_WOTS_PublicKey &public_key() const {
                return m_pub_key;
            }

            XMSS_WOTS_PublicKey &public_key() {
                return m_pub_key;
            }

            const XMSS_Address &address() const {
                return m_adrs;
            }

            XMSS_Address &address() {
                return m_adrs;
            }

            std::string algo_name() const override {
                return m_pub_key.algo_name();
            }

            algorithm_identifier algorithm_identifier() const override {
                return m_pub_key.algorithm_identifier();
            }

            bool check_key(RandomNumberGenerator &rng, bool strong) const override {
                return m_pub_key.check_key(rng, strong);
            }

            std::unique_ptr <pk_operations::verification> create_verification_op(const std::string &params,
                                                                          const std::string &provider) const override {
                return m_pub_key.create_verification_op(params, provider);
            }

            OID get_oid() const override {
                return m_pub_key.get_oid();
            }

            size_t estimated_strength() const override {
                return m_pub_key.estimated_strength();
            }

            size_t key_length() const override {
                return m_pub_key.estimated_strength();
            }

            std::vector <uint8_t> public_key_bits() const override {
                return m_pub_key.public_key_bits();
            }

        protected:
            XMSS_WOTS_PublicKey m_pub_key;
            XMSS_Address m_adrs;
        };
    }
}

#endif
