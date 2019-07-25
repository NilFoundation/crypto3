#include <nil/crypto3/pubkey/sm2.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>

#include <nil/crypto3/multiprecision/prime.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

#include <nil/crypto3/multiprecision/modular_inverse.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            bool sm2_signature_private_key::check_key(random_number_generator &rng, bool strong) const {
                if (!public_point().on_the_curve()) {
                    return false;
                }

                if (!strong) {
                    return true;
                }

                return keypair::signature_consistency_check(rng, *this, "SM3");
            }

            sm2_signature_private_key::sm2_signature_private_key(const algorithm_identifier &alg_id,
                                                                 const secure_vector<uint8_t> &key_bits) :
                ec_private_key(alg_id, key_bits) {
                m_da_inv = inverse_mod(m_private_key + 1, domain().get_order());
            }

            sm2_signature_private_key::sm2_signature_private_key(random_number_generator &rng, const ec_group &domain,
                                                                 const boost::multiprecision::cpp_int &x) :
                ec_private_key(rng, domain, x) {
                m_da_inv = inverse_mod(m_private_key + 1, domain.get_order());
            }

            std::vector<uint8_t> sm2_compute_za(HashFunction &hash, const std::string &user_id, const ec_group &domain,
                                                const point_gfp &pubkey) {
                if (user_id.size() >= 8192) {
                    throw std::invalid_argument("SM2 user id too long to represent");
                }

                const uint16_t uid_len = static_cast<uint16_t>(8 * user_id.size());

                hash.update(extract_uint_t<CHAR_BIT>(uid_len, 0));
                hash.update(extract_uint_t<CHAR_BIT>(uid_len, 1));
                hash.update(user_id);

                const size_t p_bytes = domain.get_p_bytes();

                hash.update(boost::multiprecision::cpp_int::encode_1363(domain.get_a(), p_bytes));
                hash.update(boost::multiprecision::cpp_int::encode_1363(domain.get_b(), p_bytes));
                hash.update(boost::multiprecision::cpp_int::encode_1363(domain.get_g_x(), p_bytes));
                hash.update(boost::multiprecision::cpp_int::encode_1363(domain.get_g_y(), p_bytes));
                hash.update(boost::multiprecision::cpp_int::encode_1363(pubkey.get_affine_x(), p_bytes));
                hash.update(boost::multiprecision::cpp_int::encode_1363(pubkey.get_affine_y(), p_bytes));

                std::vector<uint8_t> za(hash.output_length());
                hash.final(za.data());

                return za;
            }

            namespace {

                /**
                 * SM2 signature operation
                 */
                class sm2_signature_operation final : public pk_operations::signature {
                public:
                    sm2_signature_operation(const sm2_signature_private_key &sm2, const std::string &ident,
                                            const std::string &hash) :
                        m_group(sm2.domain()),
                        m_x(sm2.private_value()), m_da_inv(sm2.get_da_inv()),
                        m_hash(HashFunction::create_or_throw(hash)) {
                        // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
                        m_za = sm2_compute_za(*m_hash, ident, m_group, sm2.public_point());
                        m_hash->update(m_za);
                    }

                    void update(const uint8_t msg[], size_t msg_len) override {
                        m_hash->update(msg, msg_len);
                    }

                    secure_vector<uint8_t> sign(random_number_generator &rng) override;

                private:
                    const ec_group m_group;
                    const boost::multiprecision::cpp_int &m_x;
                    const boost::multiprecision::cpp_int &m_da_inv;

                    std::vector<uint8_t> m_za;
                    std::unique_ptr<HashFunction> m_hash;
                    std::vector<boost::multiprecision::cpp_int> m_ws;
                };

                secure_vector<uint8_t> sm2_signature_operation::sign(random_number_generator &rng) {
                    const boost::multiprecision::cpp_int e = boost::multiprecision::cpp_int::decode(m_hash->final());

                    const boost::multiprecision::cpp_int k = m_group.random_scalar(rng);

                    const boost::multiprecision::cpp_int r
                        = m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws) + e);
                    const boost::multiprecision::cpp_int s = m_group.multiply_mod_order(m_da_inv, (k - r * m_x));

                    // prepend ZA for next signature if any
                    m_hash->update(m_za);

                    return boost::multiprecision::cpp_int::encode_fixed_length_int_pair(r, s,
                                                                                        m_group.get_order().bytes());
                }

                /**
                 * SM2 verification operation
                 */
                class sm2_verification_operation final : public pk_operations::verification {
                public:
                    sm2_verification_operation(const sm2_signature_public_key &sm2, const std::string &ident,
                                               const std::string &hash) :
                        m_group(sm2.domain()),
                        m_public_point(sm2.public_point()), m_hash(HashFunction::create_or_throw(hash)) {
                        // ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
                        m_za = sm2_compute_za(*m_hash, ident, m_group, m_public_point);
                        m_hash->update(m_za);
                    }

                    void update(const uint8_t msg[], size_t msg_len) override {
                        m_hash->update(msg, msg_len);
                    }

                    bool is_valid_signature(const uint8_t sig[], size_t sig_len) override;

                private:
                    const ec_group m_group;
                    const point_gfp &m_public_point;
                    std::vector<uint8_t> m_za;
                    std::unique_ptr<HashFunction> m_hash;
                };

                bool sm2_verification_operation::is_valid_signature(const uint8_t sig[], size_t sig_len) {
                    const boost::multiprecision::cpp_int e = boost::multiprecision::cpp_int::decode(m_hash->final());

                    // Update for next verification
                    m_hash->update(m_za);

                    if (sig_len != m_group.get_order().bytes() * 2) {
                        return false;
                    }

                    const boost::multiprecision::cpp_int r(sig, sig_len / 2);
                    const boost::multiprecision::cpp_int s(sig + sig_len / 2, sig_len / 2);

                    if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    const boost::multiprecision::cpp_int t = m_group.mod_order(r + s);

                    if (t == 0) {
                        return false;
                    }

                    const point_gfp R = m_group.point_multiply(s, m_public_point, t);

                    // ???
                    if (R.is_zero()) {
                        return false;
                    }

                    return (m_group.mod_order(R.get_affine_x() + e) == r);
                }

            }    // namespace

            std::unique_ptr<pk_operations::verification>
                sm2_signature_public_key::create_verification_op(const std::string &params,
                                                                 const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    std::string userid = "";
                    std::string hash = "SM3";

                    auto comma = params.find(',');
                    if (comma == std::string::npos) {
                        userid = params;
                    } else {
                        userid = params.substr(0, comma);
                        hash = params.substr(comma + 1, std::string::npos);
                    }

                    if (userid.empty()) {
                        // GM/T 0009-2012 specifies this as the default userid
                        userid = "1234567812345678";
                    }

                    return std::unique_ptr<pk_operations::verification>(
                        new sm2_verification_operation(*this, userid, hash));
                }

                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature> sm2_signature_private_key::create_signature_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    std::string userid = "";
                    std::string hash = "SM3";

                    auto comma = params.find(',');
                    if (comma == std::string::npos) {
                        userid = params;
                    } else {
                        userid = params.substr(0, comma);
                        hash = params.substr(comma + 1, std::string::npos);
                    }

                    if (userid.empty()) {
                        // GM/T 0009-2012 specifies this as the default userid
                        userid = "1234567812345678";
                    }

                    return std::unique_ptr<pk_operations::signature>(new sm2_signature_operation(*this, userid, hash));
                }

                throw Provider_Not_Found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil
