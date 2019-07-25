#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/ec_group/point_mul.hpp>

#include <boost/multiprecision/montgomery/modular_reduce.hpp>

#if defined(CRYPTO3_HAS_RFC6979)

#include <nil/crypto3/pubkey/rfc6979.hpp>
#include <boost/multiprecision/modular_inverse.hpp>

#endif

#if defined(CRYPTO3_HAS_BEARSSL)
#include <nil/crypto3/prov/bearssl/bearssl.hpp>
#endif

#if defined(CRYPTO3_HAS_OPENSSL)
#include <nil/crypto3/prov/openssl/openssl.hpp>
#endif

namespace nil {
    namespace crypto3 {

        namespace {

            /**
             * ECDSA signature operation
             */
            class ecdsa_signature_operation final : public pk_operations::signature_with_emsa {
            public:
                ecdsa_signature_operation(const ecdsa_private_key &ecdsa, const std::string &emsa) :
                    pk_operations::signature_with_emsa(emsa), m_group(ecdsa.domain()), m_x(ecdsa.private_value()) {
#if defined(CRYPTO3_HAS_RFC6979)
                    m_rfc6979_hash = hash_for_emsa(emsa);
#endif
                }

                size_t max_input_bits() const override {
                    return m_group.get_order_bits();
                }

                secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                random_number_generator &rng) override;

            private:
                const ec_group m_group;
                const boost::multiprecision::cpp_int &m_x;

#if defined(CRYPTO3_HAS_RFC6979)
                std::string m_rfc6979_hash;
#endif

                std::vector<boost::multiprecision::cpp_int> m_ws;
            };

            secure_vector<uint8_t> ecdsa_signature_operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                                                       random_number_generator &rng) {
                boost::multiprecision::cpp_int m(msg, msg_len, m_group.get_order_bits());

#if defined(CRYPTO3_HAS_RFC6979)
                const boost::multiprecision::cpp_int k
                    = generate_rfc6979_nonce(m_x, m_group.get_order(), m, m_rfc6979_hash);
#else
                const boost::multiprecision::cpp_int k = m_group.random_scalar(rng);
#endif

                const boost::multiprecision::cpp_int k_inv = inverse_mod(k, m_group.get_order());
                const boost::multiprecision::cpp_int r
                    = m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                const boost::multiprecision::cpp_int xrm = m_group.mod_order(m_group.multiply_mod_order(m_x, r) + m);
                const boost::multiprecision::cpp_int s = m_group.multiply_mod_order(k_inv, xrm);

                // With overwhelming probability, a bug rather than actual zero r/s
                if (r.is_zero() || s.is_zero()) {
                    throw Internal_Error("During ECDSA signature generated zero r/s");
                }

                return boost::multiprecision::cpp_int::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
            }

            /**
             * ECDSA verification operation
             */
            class ecdsa_verification_operation final : public pk_operations::verification_with_emsa {
            public:
                ecdsa_verification_operation(const ecdsa_public_key &ecdsa, const std::string &emsa) :
                    pk_operations::verification_with_emsa(emsa), m_group(ecdsa.domain()),
                    m_gy_mul(m_group.get_base_point(), ecdsa.public_point()) {
                }

                size_t max_input_bits() const override {
                    return m_group.get_order_bits();
                }

                bool with_recovery() const override {
                    return false;
                }

                bool verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[], size_t sig_len) override;

            private:
                const ec_group m_group;
                const point_gfp_multi_point_precompute m_gy_mul;
            };

            bool ecdsa_verification_operation::verify(const uint8_t msg[], size_t msg_len, const uint8_t sig[],
                                                      size_t sig_len) {
                if (sig_len != m_group.get_order_bytes() * 2) {
                    return false;
                }

                const boost::multiprecision::cpp_int e(msg, msg_len, m_group.get_order_bits());

                const boost::multiprecision::cpp_int r(sig, sig_len / 2);
                const boost::multiprecision::cpp_int s(sig + sig_len / 2, sig_len / 2);

                if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                    return false;
                }

                const boost::multiprecision::cpp_int w = inverse_mod(s, m_group.get_order());

                const boost::multiprecision::cpp_int u1 = m_group.multiply_mod_order(e, w);
                const boost::multiprecision::cpp_int u2 = m_group.multiply_mod_order(r, w);
                const point_gfp R = m_gy_mul.multi_exp(u1, u2);

                if (R.is_zero()) {
                    return false;
                }

                const boost::multiprecision::cpp_int v = m_group.mod_order(R.get_affine_x());
                return (v == r);
            }

        }    // namespace

        std::unique_ptr<pk_operations::verification>
            ecdsa_public_key::create_verification_op(const std::string &params, const std::string &provider) const {
#if defined(CRYPTO3_HAS_BEARSSL)
            if (provider == "bearssl" || provider.empty()) {
                try {
                    return make_bearssl_ecdsa_ver_op(*this, params);
                } catch (lookup_error &e) {
                    if (provider == "bearssl")
                        throw;
                }
            }
#endif

#if defined(CRYPTO3_HAS_OPENSSL)
            if (provider == "openssl" || provider.empty()) {
                try {
                    return make_openssl_ecdsa_ver_op(*this, params);
                } catch (lookup_error &e) {
                    if (provider == "openssl")
                        throw;
                }
            }
#endif

            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::verification>(new ecdsa_verification_operation(*this, params));
            }

            throw Provider_Not_Found(algo_name(), provider);
        }

        std::unique_ptr<pk_operations::signature>
            ecdsa_private_key::create_signature_op(random_number_generator & /*random*/, const std::string &params,
                                                   const std::string &provider) const {
#if defined(CRYPTO3_HAS_BEARSSL)
            if (provider == "bearssl" || provider.empty()) {
                try {
                    return make_bearssl_ecdsa_sig_op(*this, params);
                } catch (lookup_error &e) {
                    if (provider == "bearssl")
                        throw;
                }
            }
#endif

#if defined(CRYPTO3_HAS_OPENSSL)
            if (provider == "openssl" || provider.empty()) {
                try {
                    return make_openssl_ecdsa_sig_op(*this, params);
                } catch (lookup_error &e) {
                    if (provider == "openssl")
                        throw;
                }
            }
#endif

            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::signature>(new ecdsa_signature_operation(*this, params));
            }

            throw Provider_Not_Found(algo_name(), provider);
        }
    }    // namespace crypto3
}