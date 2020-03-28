#ifndef CRYPTO3_PUBKEY_DL_ALGO_HPP
#define CRYPTO3_PUBKEY_DL_ALGO_HPP

#include <nil/crypto3/pubkey/dl_group/dl_group.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {

        using namespace boost::multiprecision;

        /**
         * This class represents discrete logarithm (DL) public keys.
         */
        class dl_scheme_public_key : public virtual public_key_policy {
        public:
            bool check_key(random_number_generator &rng, bool) const override;

            algorithm_identifier get_algorithm_identifier() const override;

            std::vector<uint8_t> public_key_bits() const override;

            /**
             * Get the DL domain parameters of this key.
             * @return DL domain parameters of this key
             */
            const dl_group &get_domain() const {
                return m_group;
            }

            /**
             * Get the DL domain parameters of this key.
             * @return DL domain parameters of this key
             */
            const dl_group &get_group() const {
                return m_group;
            }

            /**
             * Get the public value y with y = g^x mod p where x is the secret key.
             */
            const number<Backend, ExpressionTemplates> &get_y() const {
                return m_y;
            }

            /**
             * Get the prime p of the underlying DL group.
             * @return prime p
             */
            const number<Backend, ExpressionTemplates> &group_p() const {
                return m_group.p();
            }

            /**
             * Get the prime q of the underlying DL group.
             * @return prime q
             */
            const number<Backend, ExpressionTemplates> &group_q() const {
                return m_group.get_q();
            }

            /**
             * Get the generator g of the underlying DL group.
             * @return generator g
             */
            const number<Backend, ExpressionTemplates> &group_g() const {
                return m_group.get_g();
            }

            /**
             * Get the underlying groups encoding format.
             * @return encoding format
             */
            virtual dl_group::format group_format() const = 0;

            size_t key_length() const override;

            size_t estimated_strength() const override;

            dl_scheme_public_key &operator=(const dl_scheme_public_key &other) = default;

        protected:
            dl_scheme_public_key() = default;

            /**
             * Create a public key.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits DER encoded public key bits
             * @param group_format the underlying groups encoding format
             */
            dl_scheme_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits,
                                 dl_group::format group_format);

            dl_scheme_public_key(const dl_group &group, const number<Backend, ExpressionTemplates> &y);

            /**
             * The DL public key
             */
            number<Backend, ExpressionTemplates> m_y;

            /**
             * The DL group
             */
            dl_group m_group;
        };

        /**
         * This class represents discrete logarithm (DL) private keys.
         */
        class dl_scheme_private_key : public virtual dl_scheme_public_key, public virtual private_key_policy {
        public:
            bool check_key(random_number_generator &rng, bool) const override;

            /**
             * Get the secret key x.
             * @return secret key
             */
            const number<Backend, ExpressionTemplates> &get_x() const {
                return m_x;
            }

            secure_vector<uint8_t> private_key_bits() const override;

            dl_scheme_private_key &operator=(const dl_scheme_private_key &other) = default;

        protected:
            /**
             * Create a private key.
             * @param alg_id the X.509 algorithm identifier
             * @param key_bits DER encoded private key bits
             * @param group_format the underlying groups encoding format
             */
            dl_scheme_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits,
                                  dl_group::format group_format);

            dl_scheme_private_key() = default;

            /**
             * The DL private key
             */
            number<Backend, ExpressionTemplates> m_x;
        };

        size_t dl_scheme_public_key::key_length() const {
            return m_group.p_bits();
        }

        size_t dl_scheme_public_key::estimated_strength() const {
            return m_group.estimated_strength();
        }

        algorithm_identifier dl_scheme_public_key::get_algorithm_identifier() const {
            return algorithm_identifier(oid(), m_group.der_encode(group_format()));
        }

        std::vector<uint8_t> dl_scheme_public_key::public_key_bits() const {
            return der_encoder().encode(m_y).get_contents_unlocked();
        }

        dl_scheme_public_key::dl_scheme_public_key(
            const dl_group &group, const boost::multiprecision::number<Backend, ExpressionTemplates> &y) :
            m_y(y),
            m_group(group) {
        }

        dl_scheme_public_key::dl_scheme_public_key(const algorithm_identifier &alg_id,
                                                   const std::vector<uint8_t> &key_bits, dl_group::format format) :
            m_group(alg_id.get_parameters(), format) {
            ber_decoder(key_bits).decode(m_y);
        }

        secure_vector<uint8_t> dl_scheme_private_key::private_key_bits() const {
            return der_encoder().encode(m_x).get_contents();
        }

        dl_scheme_private_key::dl_scheme_private_key(const algorithm_identifier &alg_id,
                                                     const secure_vector<uint8_t> &key_bits, dl_group::format format) {
            m_group.ber_decode(alg_id.get_parameters(), format);

            ber_decoder(key_bits).decode(m_x);
        }

        /*
         * Check Public DL Parameters
         */
        bool dl_scheme_public_key::check_key(random_number_generator &rng, bool strong) const {
            return m_group.verify_group(rng, strong) && m_group.verify_public_element(m_y);
        }

        /*
         * Check DL Scheme Private Parameters
         */
        bool dl_scheme_private_key::check_key(random_number_generator &rng, bool strong) const {
            return m_group.verify_group(rng, strong) && m_group.verify_element_pair(m_y, m_x);
        }
    }    // namespace crypto3
}    // namespace nil

#endif
