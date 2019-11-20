#ifndef CRYPTO3_PUBKEY_DIFFIE_HELLMAN_HPP
#define CRYPTO3_PUBKEY_DIFFIE_HELLMAN_HPP

#include <nil/crypto3/pubkey/dl_group/dl_algorithm.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents Diffie-Hellman public keys.
             */
            class dh_public_key : public virtual dl_scheme_public_key {
            public:
                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 2, 840, 10046, 2, 1});
                }

                std::string algo_name() const override {
                    return "DH";
                }

                std::vector<uint8_t> public_value() const {
                    return unlock(number<Backend, ExpressionTemplates>::encode_1363(m_y, group_p().bytes()));
                }

                dl_group::format group_format() const override {
                    return dl_group::ANSI_X9_42;
                }

                /**
                 * Create a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                dh_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    dl_scheme_public_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
                }

                /**
                 * Construct a public key with the specified parameters.
                 * @param grp the DL group to use in the key
                 * @param y the public value y
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                dh_public_key(const dl_group &grp, const number<Backend, ExpressionTemplates> &y) {
                    m_group = grp;
                    m_y = y;
                }

            protected:
                dh_public_key() = default;
            };

            /**
             * This class represents Diffie-Hellman private keys.
             */
            class dh_private_key final : public dh_public_key,
                                         public pk_key_agreement_key,
                                         public virtual dl_scheme_private_key {
            public:
                std::vector<uint8_t> public_value() const override {
                    return dh_public_key::public_value();
                }

                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits PKCS #8 structure
                 */
                dh_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    dl_scheme_private_key(alg_id, key_bits, dl_group::ANSI_X9_42) {
                    if (m_y == 0) {
                        m_y = m_group.power_g_p(m_x);
                    }
                }

                /**
                 * Create a private key.
                 * @param rng random number generator to use
                 * @param grp the group to be used in the key
                 * @param x the key's secret value (or if zero, generate a new key)
                 */
                template<typename UniformRandomGenerator, typename Backend,
                         expression_template_option ExpressionTemplates>
                dh_private_key(random_number_generator &rng, const dl_group &grp,
                               const number<Backend, ExpressionTemplates> &x = number<Backend, ExpressionTemplates>()) {
                    m_group = grp;

                    if (x_arg == 0) {
                        m_x.randomize(rng, grp.exponent_bits());
                    } else {
                        m_x = x_arg;
                    }

                    if (m_y == 0) {
                        m_y = m_group.power_g_p(m_x);
                    }
                }

                std::unique_ptr<pk_operations::key_agreement>
                    create_key_agreement_op(random_number_generator &rng,
                                            const std::string &params,
                                            const std::string &provider) const override;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
