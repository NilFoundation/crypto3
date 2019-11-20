#include <nil/crypto3/pubkey/rsa.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/blinding.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

#include <boost/multiprecision/pow_mod.hpp>
#include <boost/multiprecision/monty.hpp>
#include <boost/multiprecision/monty_exp.hpp>

#if defined(CRYPTO3_HAS_OPENSSL)
#include <nil/crypto3/prov/openssl/openssl.hpp>
#endif

#if defined(CRYPTO3_TARGET_OS_HAS_THREADS)

#include <future>

#include <nil/crypto3/pubkey/workfactor.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

#endif

#include <boost/math/common_factor.hpp>
#include <boost/multiprecision/montgomery/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            size_t rsa_public_key::key_length() const {
                return m_n.bits();
            }

            size_t rsa_public_key::estimated_strength() const {
                return if_work_factor(key_length());
            }

            algorithm_identifier rsa_public_key::algorithm_identifier() const {
                return algorithm_identifier(get_oid(), algorithm_identifier::USE_NULL_PARAM);
            }

            std::vector<uint8_t> rsa_public_key::public_key_bits() const {
                return der_encoder().start_cons(SEQUENCE).encode(m_n).encode(m_e).end_cons().get_contents_unlocked();
            }

            rsa_public_key::rsa_public_key(const algorithm_identifier &, const std::vector<uint8_t> &key_bits) {
                ber_decoder(key_bits).start_cons(SEQUENCE).decode(m_n).decode(m_e).end_cons();
            }

            /*
             * Check RSA Public Parameters
             */
            bool rsa_public_key::check_key(random_number_generator &, bool) const {
                if (m_n < 35 || m_n.is_even() || m_e < 3 || m_e.is_even()) {
                    return false;
                }
                return true;
            }

            secure_vector<uint8_t> rsa_private_key::private_key_bits() const {
                return der_encoder()
                    .start_cons(SEQUENCE)
                    .encode(static_cast<size_t>(0))
                    .encode(m_n)
                    .encode(m_e)
                    .encode(m_d)
                    .encode(m_p)
                    .encode(m_q)
                    .encode(m_d1)
                    .encode(m_d2)
                    .encode(m_c)
                    .end_cons()
                    .get_contents();
            }

            rsa_private_key::rsa_private_key(const algorithm_identifier &, const secure_vector<uint8_t> &key_bits) {
                ber_decoder(key_bits)
                    .start_cons(SEQUENCE)
                    .decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
                    .decode(m_n)
                    .decode(m_e)
                    .decode(m_d)
                    .decode(m_p)
                    .decode(m_q)
                    .decode(m_d1)
                    .decode(m_d2)
                    .decode(m_c)
                    .end_cons();
            }

            rsa_private_key::rsa_private_key(const number<Backend, ExpressionTemplates> &prime1,
                                             const number<Backend, ExpressionTemplates> &prime2,
                                             const number<Backend, ExpressionTemplates> &exp,
                                             const number<Backend, ExpressionTemplates> &d_exp,
                                             const number<Backend, ExpressionTemplates> &mod) :
                m_d {d_exp},
                m_p {prime1}, m_q {prime2}, m_d1 {}, m_d2 {}, m_c {inverse_mod(m_q, m_p)} {
                m_n = mod.is_nonzero() ? mod : m_p * m_q;
                m_e = exp;

                if (m_d == 0) {
                    const number<Backend, ExpressionTemplates> phi_n = boost::math::lcm(m_p - 1, m_q - 1);
                    m_d = inverse_mod(m_e, phi_n);
                }

                m_d1 = m_d % (m_p - 1);
                m_d2 = m_d % (m_q - 1);
            }

            /*
             * Create a RSA private key
             */
            rsa_private_key::rsa_private_key(random_number_generator &rng, size_t bits, size_t exp) {
                if (bits < 1024) {
                    throw

                        std::invalid_argument(algo_name()

                                              + ": Can't make a key that is only " + std::to_string(bits)
                                              + " bits long");
                }
                if (exp < 3 || exp % 2 == 0) {
                    throw

                        std::invalid_argument(algo_name()

                                              + ": Invalid encryption exponent");
                }

                m_e = exp;

                do {
                    m_p = random_prime(rng, (bits + 1) / 2, m_e);
                    m_q = random_prime(rng, bits - m_p.bits(), m_e);
                    m_n = m_p * m_q;
                } while (m_n.

                         bits()

                         != bits);

                const number<Backend, ExpressionTemplates> phi_n = boost::math::lcm(m_p - 1, m_q - 1);
                m_d = inverse_mod(m_e, phi_n);
                m_d1 = m_d % (m_p - 1);
                m_d2 = m_d % (m_q - 1);
                m_c = inverse_mod(m_q, m_p);
            }

            /*
             * Check Private RSA Parameters
             */
            bool rsa_private_key::check_key(random_number_generator &rng, bool strong) const {
                if (m_n < 35 || m_n.is_even() || m_e < 3 || m_e.is_even()) {
                    return false;
                }

                if (m_d < 2 || m_p < 3 || m_q < 3 || m_p * m_q != m_n) {
                    return false;
                }

                if (m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverse_mod(m_q, m_p)) {
                    return false;
                }

                const size_t prob = (strong) ? 128 : 12;

                if (!miller_rabin_test(m_p, prob, rng) || !miller_rabin_test(m_q, prob, rng)) {
                    return false;
                }

                if (strong) {
                    if ((m_e * m_d) % boost::math::lcm(m_p - 1, m_q - 1) != 1) {
                        return false;
                    }

                    return key_pair::signature_consistency_check(rng, *this, "EMSA4(SHA-256)");
                }

                return true;
            }

            namespace {

                /**
                 * RSA private (decrypt/sign) operation
                 */
                class rsa_private_operation {
                protected:
                    size_t get_max_input_bits() const {
                        return (m_mod_bits - 1);
                    }

                    explicit rsa_private_operation(const rsa_private_key &rsa, random_number_generator &rng) :
                        m_key(rsa), m_mod_p(m_key.get_p()), m_mod_q(m_key.get_q()),
                        m_monty_p(std::make_shared<montgomery_params>(m_key.get_p(), m_mod_p)),
                        m_monty_q(std::make_shared<montgomery_params>(m_key.get_q(), m_mod_q)),
                        m_powermod_e_n(m_key.get_e(), m_key.get_n()),
                        m_blinder(
                            m_key.get_n(), rng, [this](const number<Backend, ExpressionTemplates> &k) { return m_powermod_e_n(k); },
                            [this](const number<Backend, ExpressionTemplates> &k) { return inverse_mod(k, m_key.get_n()); }),
                        m_mod_bytes(m_key.get_n().bytes()), m_mod_bits(m_key.get_n().bits()) {
                    }

                    number<Backend, ExpressionTemplates> blinded_private_op(const number<Backend, ExpressionTemplates> &m) const {
                        if (m >= m_key.get_n()) {
                            throw std::invalid_argument("RSA private op - input is too large");
                        }

                        return m_blinder.unblind(private_op(m_blinder.blind(m)));
                    }

                    number<Backend, ExpressionTemplates> private_op(const number<Backend, ExpressionTemplates> &m) const {
                        const size_t powm_window = 4;
                        const size_t exp_blinding_bits = 64;

                        const number<Backend, ExpressionTemplates> d1_mask(m_blinder.rng(), exp_blinding_bits);
                        const number<Backend, ExpressionTemplates> d2_mask(m_blinder.rng(), exp_blinding_bits);

                        const number<Backend, ExpressionTemplates> masked_d1 = m_key.get_d1() + (d1_mask * (m_key.get_p() - 1));
                        const number<Backend, ExpressionTemplates> masked_d2 = m_key.get_d2() + (d2_mask * (m_key.get_q() - 1));

#if defined(CRYPTO3_TARGET_OS_HAS_THREADS)
                        auto future_j1 = std::async(std::launch::async, [this, &m, &masked_d1, powm_window]() {
                            auto powm_d1_p = monty_precompute(m_monty_p, m, powm_window);
                            return monty_execute(*powm_d1_p, masked_d1);
                        });

                        auto powm_d2_q = monty_precompute(m_monty_q, m, powm_window);
                        number<Backend, ExpressionTemplates> j2 = monty_execute(*powm_d2_q, masked_d2);
                        number<Backend, ExpressionTemplates> j1 = future_j1.get();
#else
                        auto powm_d1_p = monty_precompute(m_monty_p, m, powm_window);
                        auto powm_d2_q = monty_precompute(m_monty_q, m, powm_window);

                        number<Backend, ExpressionTemplates> j1 = monty_execute(*powm_d1_p, masked_d1);
                        number<Backend, ExpressionTemplates> j2 = monty_execute(*powm_d2_q, masked_d2);
#endif

                        j1 = m_mod_p.reduce((j1 - j2) * m_key.get_c());

                        return j1 * m_key.get_q() + j2;
                    }

                    const rsa_private_key &m_key;

                    // TODO these could all be computed once and stored in the key object
                    modular_reducer m_mod_p;
                    modular_reducer m_mod_q;
                    std::shared_ptr<const montgomery_params> m_monty_p;
                    std::shared_ptr<const montgomery_params> m_monty_q;

                    fixed_exponent_power_mod m_powermod_e_n;
                    blinder m_blinder;
                    size_t m_mod_bytes;
                    size_t m_mod_bits;
                };

                class rsa_signature_operation final : public pk_operations::signature_with_emsa,
                                                      private rsa_private_operation {
                public:
                    size_t max_input_bits() const override {
                        return get_max_input_bits();
                    }

                    rsa_signature_operation(const rsa_private_key &rsa, const std::string &emsa,
                                            random_number_generator &rng) :
                        pk_operations::signature_with_emsa(emsa),
                        rsa_private_operation(rsa, rng) {
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &) override {
                        const number<Backend, ExpressionTemplates> m(msg, msg_len);
                        const number<Backend, ExpressionTemplates> x = blinded_private_op(m);
                        const number<Backend, ExpressionTemplates> c = m_powermod_e_n(x);
                        BOOST_ASSERT_MSG(m == c, "RSA sign consistency check");
                        return number<Backend, ExpressionTemplates>::encode_1363(x, m_mod_bytes);
                    }
                };

                class RSA_Decryption_Operation final : public pk_operations::decryption_with_eme,
                                                       private rsa_private_operation {
                public:
                    RSA_Decryption_Operation(const rsa_private_key &rsa, const std::string &eme,
                                             random_number_generator &rng) :
                        pk_operations::decryption_with_eme(eme),
                        rsa_private_operation(rsa, rng) {
                    }

                    secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override {
                        const number<Backend, ExpressionTemplates> m(msg, msg_len);
                        const number<Backend, ExpressionTemplates> x = blinded_private_op(m);
                        const number<Backend, ExpressionTemplates> c = m_powermod_e_n(x);
                        BOOST_ASSERT_MSG(m == c, "RSA isomorphic_decryption_mode consistency check");
                        return number<Backend, ExpressionTemplates>::encode_1363(x, m_mod_bytes);
                    }
                };

                class RSA_KEM_Decryption_Operation final : public pk_operations::kem_decryption_with_kdf,
                                                           private rsa_private_operation {
                public:
                    RSA_KEM_Decryption_Operation(const rsa_private_key &key, const std::string &kdf,
                                                 random_number_generator &rng) :
                        pk_operations::kem_decryption_with_kdf(kdf),
                        rsa_private_operation(key, rng) {
                    }

                    secure_vector<uint8_t> raw_kem_decrypt(const uint8_t encap_key[], size_t len) override {
                        const number<Backend, ExpressionTemplates> m(encap_key, len);
                        const number<Backend, ExpressionTemplates> x = blinded_private_op(m);
                        const number<Backend, ExpressionTemplates> c = m_powermod_e_n(x);
                        BOOST_ASSERT_MSG(m == c, "RSA KEM consistency check");
                        return number<Backend, ExpressionTemplates>::encode_1363(x, m_mod_bytes);
                    }
                };

                /**
                 * RSA public (encrypt/verify) operation
                 */
                class RSA_Public_Operation {
                public:
                    explicit RSA_Public_Operation(const rsa_public_key &rsa) :
                        m_n(rsa.get_n()), m_e(rsa.get_e()), m_monty_n(std::make_shared<montgomery_params>(m_n)) {
                    }

                    size_t get_max_input_bits() const {
                        return (m_n.bits() - 1);
                    }

                protected:
                    number<Backend, ExpressionTemplates> public_op(const number<Backend, ExpressionTemplates> &m) const {
                        if (m >= m_n) {
                            throw std::invalid_argument("RSA public op - input is too large");
                        }

                        const size_t powm_window = 1;

                        auto powm_m_n = monty_precompute(m_monty_n, m, powm_window);
                        return monty_execute_vartime(*powm_m_n, m_e);
                    }

                    const number<Backend, ExpressionTemplates> &get_n() const {
                        return m_n;
                    }

                    const number<Backend, ExpressionTemplates> &m_n;
                    const number<Backend, ExpressionTemplates> &m_e;
                    std::shared_ptr<montgomery_params> m_monty_n;
                };

                class RSA_Encryption_Operation final : public pk_operations::encryption_with_eme,
                                                       private RSA_Public_Operation {
                public:
                    RSA_Encryption_Operation(const rsa_public_key &rsa, const std::string &eme) :
                        pk_operations::encryption_with_eme(eme), RSA_Public_Operation(rsa) {
                    }

                    size_t max_raw_input_bits() const override {
                        return get_max_input_bits();
                    }

                    secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                                       random_number_generator &) override {
                        number<Backend, ExpressionTemplates> m(msg, msg_len);
                        return number<Backend, ExpressionTemplates>::encode_1363(public_op(m), m_n.bytes());
                    }
                };

                class RSA_Verify_Operation final : public pk_operations::verification_with_emsa,
                                                   private RSA_Public_Operation {
                public:
                    size_t max_input_bits() const override {
                        return get_max_input_bits();
                    }

                    RSA_Verify_Operation(const rsa_public_key &rsa, const std::string &emsa) :
                        pk_operations::verification_with_emsa(emsa), RSA_Public_Operation(rsa) {
                    }

                    bool with_recovery() const override {
                        return true;
                    }

                    secure_vector<uint8_t> verify_mr(const uint8_t msg[], size_t msg_len) override {
                        number<Backend, ExpressionTemplates> m(msg, msg_len);
                        return number<Backend, ExpressionTemplates>::encode_locked(public_op(m));
                    }
                };

                class RSA_KEM_Encryption_Operation final : public pk_operations::kem_encryption_with_kdf,
                                                           private RSA_Public_Operation {
                public:
                    RSA_KEM_Encryption_Operation(const rsa_public_key &key, const std::string &kdf) :
                        pk_operations::kem_encryption_with_kdf(kdf), RSA_Public_Operation(key) {
                    }

                private:
                    void raw_kem_encrypt(secure_vector<uint8_t> &out_encapsulated_key,
                                         secure_vector<uint8_t> &raw_shared_key,
                                         nil::crypto3::random_number_generator &rng) override {
                        const number<Backend, ExpressionTemplates> r = number<Backend, ExpressionTemplates>::random_integer(rng, 1, get_n());
                        const number<Backend, ExpressionTemplates> c = public_op(r);

                        out_encapsulated_key = number<Backend, ExpressionTemplates>::encode_locked(c);
                        raw_shared_key = number<Backend, ExpressionTemplates>::encode_locked(r);
                    }
                };

            }    // namespace

            std::unique_ptr<pk_operations::encryption>
                rsa_public_key::create_encryption_op(random_number_generator & /*random*/, const std::string &params,
                                                     const std::string &provider) const {
#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    try {
                        return make_openssl_rsa_enc_op(*this, params);
                    } catch (Exception &e) {
                        /*
                         * If OpenSSL for some reason could not handle this (eg due to OAEP params),
                         * throw if openssl was specifically requested but otherwise just fall back
                         * to the normal version.
                         */
                        if (provider == "openssl")
                            throw lookup_error("OpenSSL RSA provider rejected key:" + std::string(e.what()));
                    }
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::encryption>(new RSA_Encryption_Operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::kem_encryption>
                rsa_public_key::create_kem_encryption_op(random_number_generator & /*random*/,
                                                         const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::kem_encryption>(
                        new RSA_KEM_Encryption_Operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::verification>
                rsa_public_key::create_verification_op(const std::string &params, const std::string &provider) const {
#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    std::unique_ptr<pk_operations::verification> res = make_openssl_rsa_ver_op(*this, params);
                    if (res)
                        return res;
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(new RSA_Verify_Operation(*this, params));
                }

                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::decryption>
                rsa_private_key::create_decryption_op(random_number_generator &rng,
                                                      const std::string &params,
                                                      const std::string &provider) const {
#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    try {
                        return make_openssl_rsa_dec_op(*this, params);
                    } catch (Exception &e) {
                        if (provider == "openssl")
                            throw lookup_error("OpenSSL RSA provider rejected key:" + std::string(e.what()));
                    }
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::decryption>(new RSA_Decryption_Operation(*this, params, rng));
                }

                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::kem_decryption>
                rsa_private_key::create_kem_decryption_op(random_number_generator &rng, const std::string &params,
                                                          const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::kem_decryption>(
                        new RSA_KEM_Decryption_Operation(*this, params, rng));
                }

                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                rsa_private_key::create_signature_op(random_number_generator &rng,
                                                     const std::string &params,
                                                     const std::string &provider) const {
#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider == "openssl" || provider.empty()) {
                    std::unique_ptr<pk_operations::signature> res = make_openssl_rsa_sig_op(*this, params);
                    if (res)
                        return res;
                }
#endif

                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new rsa_signature_operation(*this, params, rng));
                }

                throw provider_not_found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}