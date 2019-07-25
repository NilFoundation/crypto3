#include <nil/crypto3/pubkey/dsa.hpp>

#include <nil/crypto3/multiprecision/modular_reduce.hpp>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

#include <nil/crypto3/random/random.hpp>

#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

#if defined(CRYPTO3_HAS_RFC6979)

#include <nil/crypto3/pk_pad/emsa.hpp>
#include <nil/crypto3/pubkey/rfc6979.hpp>

#endif

namespace nil {
    namespace crypto3 {

/*
* dsa_public_key_policy Constructor
*/
        dsa_public_key_policy::dsa_public_key_policy(const dl_group &grp, const cpp_int &y1) {
            m_group = grp;
            m_y = y1;
        }

/*
* Create a DSA private key
*/
        dsa_private_key_policy::dsa_private_key_policy(random_number_generator &rng, const dl_group &grp,
                                         const cpp_int &x_arg) {
            m_group = grp;

            if (x_arg == 0) {
                m_x = cpp_int::random_integer(rng, 2, group_q());
            } else {
                m_x = x_arg;
            }

            m_y = m_group.power_g_p(m_x);
        }

        dsa_private_key_policy::dsa_private_key_policy(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits)
                : dl_scheme_private_key(alg_id, key_bits, dl_group::ANSI_X9_57) {
            m_y = m_group.power_g_p(m_x);
        }

/*
* Check Private DSA Parameters
*/
        bool dsa_private_key_policy::check_key(random_number_generator &rng, bool strong) const {
            if (!dl_scheme_private_key::check_key(rng, strong) || m_x >= group_q()) {
                return false;
            }

            if (!strong) {
                return true;
            }

            return keypair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
        }

        namespace {

/**
* Object that can create a DSA signature
*/
            class dsa_signature_operation final : public pk_operations::signature_with_emsa {
            public:
                dsa_signature_operation(const dsa_private_key_policy &dsa, const std::string &emsa)
                        : pk_operations::signature_with_emsa(emsa), m_group(dsa.get_group()), m_x(dsa.get_x()),
                        m_mod_q(dsa.group_q()) {
#if defined(CRYPTO3_HAS_RFC6979)
                    m_rfc6979_hash = hash_for_emsa(emsa);
#endif
                }

                size_t max_input_bits() const override {
                    return m_group.get_q().bits();
                }

                secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                random_number_generator &rng) override;

            private:
                const dl_group m_group;
                const cpp_int &m_x;
                modular_reducer m_mod_q;
#if defined(CRYPTO3_HAS_RFC6979)
                std::string m_rfc6979_hash;
#endif
            };

            secure_vector<uint8_t> dsa_signature_operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                     random_number_generator &rng) {
                const cpp_int &q = m_group.get_q();

                cpp_int i(msg, msg_len, q.bits());

                while (i >= q) {
                    i -= q;
                }

#if defined(CRYPTO3_HAS_RFC6979)
                CRYPTO3_UNUSED(random);
                const cpp_int k = generate_rfc6979_nonce(m_x, q, i, m_rfc6979_hash);
#else
                const cpp_int k = cpp_int::random_integer(rng, 1, q);
#endif

                cpp_int s = inverse_mod(k, q);
                const cpp_int r = m_mod_q.reduce(m_group.power_g_p(k));

                s = m_mod_q.multiply(s, m_x * r + i);

                // With overwhelming probability, a bug rather than actual zero r/s
                if (r == 0 || s == 0) {
                    throw Internal_Error("Computed zero r/s during DSA signature");
                }

                return cpp_int::encode_fixed_length_int_pair(r, s, q.bytes());
            }

/**
* Object that can verify a DSA signature
*/
            class dsa_verification_operation final : public pk_operations::verification_with_emsa {
            public:
                dsa_verification_operation(const dsa_public_key_policy &dsa, const std::string &emsa)
                        : pk_operations::verification_with_emsa(emsa), m_group(dsa.get_group()), m_y(dsa.get_y()),
                        m_mod_q(dsa.group_q()) {
                }

                size_t max_input_bits() const override {
                    return m_group.get_q().bits();
                }

                bool with_recovery() const override {
                    return false;
                }

                bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

            private:
                const dl_group m_group;
                const cpp_int &m_y;

                modular_reducer m_mod_q;
            };

            bool dsa_verification_operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
                                                    size_t sig_len) {
                const cpp_int &q = m_group.get_q();
                const size_t q_bytes = q.bytes();

                if (sig_len != 2 * q_bytes || msg_len > q_bytes) {
                    return false;
                }

                cpp_int r(sig, q_bytes);
                cpp_int s(sig + q_bytes, q_bytes);
                cpp_int i(msg, msg_len, q.bits());

                if (r <= 0 || r >= q || s <= 0 || s >= q) {
                    return false;
                }

                s = inverse_mod(s, q);

                const cpp_int sr = m_mod_q.multiply(s, r);
                const cpp_int si = m_mod_q.multiply(s, i);

                s = m_group.multi_exponentiate(si, m_y, sr);

                return (m_mod_q.reduce(s) == r);
            }

        }

        std::unique_ptr<pk_operations::verification> dsa_public_key_policy::create_verification_op(const std::string &params,
                                                                                            const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::verification>(new dsa_verification_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }

        std::unique_ptr<pk_operations::signature> dsa_private_key_policy::create_signature_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::signature>(new dsa_signature_operation(*this, params));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }
    }
}