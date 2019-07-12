#ifndef CRYPTO3_DSA_H_
#define CRYPTO3_DSA_H_

#include <nil/crypto3/pubkey/detail/stream_preprocessor.hpp>

#include <nil/crypto3/pubkey/dl_group/dl_algorithm.hpp>
#include <nil/crypto3/pubkey/dl_group/dl_group.hpp>

namespace nil {
    namespace crypto3 {

/**
* DSA Public Key
*/
        class dsa_public_key_policy : public virtual dl_scheme_public_key {
        public:

            /**
             * Get the OID of the underlying public key scheme.
             * @return oid_t of the public key scheme
             */
            static const oid_t oid() {
                return oid_t({1, 2, 840, 10040, 4, 1});
            }

            std::string algo_name() const override {
                return "DSA";
            }

            dl_group::format group_format() const override {
                return dl_group::ANSI_X9_57;
            }

            size_t message_parts() const override {
                return 2;
            }

            size_t message_part_size() const override {
                return group_q().bytes();
            }

/**
* Load a public key.
* @param alg_id the X.509 algorithm identifier
* @param key_bits DER encoded public key bits
*/
            dsa_public_key_policy(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits)
                    : dl_scheme_public_key(alg_id, key_bits, dl_group::ANSI_X9_57) {
            }

/**
* Create a public key.
* @param group the underlying DL group
* @param y the public value y = g^x mod p
*/
            template<typename Backend, expression_template_option ExpressionTemplates>
            dsa_public_key_policy(const dl_group &group, const number<Backend, ExpressionTemplates> &y) : m_group(
                    group), m_y(y) {
            }

            std::unique_ptr<pk_operations::verification> create_verification_op(const std::string &params,
                                                                                const std::string &provider) const override;

        protected:

            dsa_public_key_policy() = default;

        };

/**
* DSA Private Key
*/
        class dsa_private_key_policy final : public dsa_public_key_policy, public virtual dl_scheme_private_key {
        public:

/**
* Load a private key.
* @param alg_id the X.509 algorithm identifier
* @param key_bits DER encoded key bits in ANSI X9.57 format
*/
            dsa_private_key_policy(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits);

/**
* Create a private key.
* @param rng the RNG to use
* @param group the underlying DL group
* @param private_key the private key (if zero, a new random key is generated)
*/
            dsa_private_key_policy(random_number_generator &rng, const dl_group &group,
                                   const boost::multiprecision::cpp_int &private_key = 0);

            bool check_key(random_number_generator &rng, bool strong) const override;

            std::unique_ptr<pk_operations::signature> create_signature_op(random_number_generator &rng,
                                                                          const std::string &params,
                                                                          const std::string &provider) const override;
        };

        namespace pubkey {
            class dsa {
            public:
                typedef dsa_public_key_policy public_key_policy;
                typedef dsa_private_key_policy private_key_policy;

                template<typename ProcessingMode, std::size_t ValueBits>
                struct stream_processor {
                    typedef stream_preprocessor<ProcessingMode, stream_endian::little_octet_big_bit, ValueBits,
                                                CHAR_BIT * CHAR_BIT> type_;
#ifdef CRYPTO3_PUBKEY_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };
            };
        }
    }
}

#endif
