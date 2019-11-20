#include <nil/crypto3/pubkey/sm2_encrypt.hpp>
#include <nil/crypto3/pubkey/ec_group/point_mul.hpp>
#include <nil/crypto3/pubkey/pk_operations.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>

#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>

#include <nil/crypto3/kdf/kdf.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            bool sm2_encryption_private_key::check_key(random_number_generator &rng, bool strong) const {
                if (!public_point().on_the_curve()) {
                    return false;
                }

                if (!strong) {
                    return true;
                }

                return keypair::encryption_consistency_check(rng, *this, "SM3");
            }

            sm2_encryption_private_key::sm2_encryption_private_key(const algorithm_identifier &alg_id,
                                                                   const secure_vector<uint8_t> &key_bits) :
                ec_private_key(alg_id, key_bits) {
            }

            sm2_encryption_private_key::sm2_encryption_private_key(random_number_generator &rng, const ec_group &domain,
                                                                   const boost::multiprecision::number<Backend, ExpressionTemplates> &x) :
                ec_private_key(rng, domain, x) {
            }

            namespace {

                class SM2_Encryption_Operation final : public pk_operations::encryption {
                public:
                    SM2_Encryption_Operation(const sm2_encryption_public_key &key, const std::string &kdf_hash) :
                        m_group(key.domain()), m_mul_public_point(key.public_point()), m_kdf_hash(kdf_hash) {
                    }

                    size_t max_input_bits() const override {
                        // This is arbitrary, but assumes SM2 is used for key encapsulation
                        return 512;
                    }

                    secure_vector<uint8_t> encrypt(const uint8_t msg[], size_t msg_len,
                                                   random_number_generator &rng) override {
                        std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
                        std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

                        const size_t p_bytes = m_group.get_p_bytes();

                        const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                        const point_gfp C1 = m_group.blinded_base_point_multiply(k, rng, m_ws);
                        const boost::multiprecision::number<Backend, ExpressionTemplates> x1 = C1.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> y1 = C1.get_affine_y();
                        std::vector<uint8_t> x1_bytes(p_bytes);
                        std::vector<uint8_t> y1_bytes(p_bytes);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(x1_bytes.data(), x1_bytes.size(), x1);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(y1_bytes.data(), y1_bytes.size(), y1);

                        const point_gfp kPB = m_mul_public_point.mul(k, rng, m_group.get_order(), m_ws);

                        const boost::multiprecision::number<Backend, ExpressionTemplates> x2 = kPB.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> y2 = kPB.get_affine_y();
                        std::vector<uint8_t> x2_bytes(p_bytes);
                        std::vector<uint8_t> y2_bytes(p_bytes);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(x2_bytes.data(), x2_bytes.size(), x2);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(y2_bytes.data(), y2_bytes.size(), y2);

                        secure_vector<uint8_t> kdf_input;
                        kdf_input += x2_bytes;
                        kdf_input += y2_bytes;

                        const secure_vector<uint8_t> kdf_output
                            = kdf->derive_key(msg_len, kdf_input.data(), kdf_input.size());

                        secure_vector<uint8_t> masked_msg(msg_len);
                        xor_buf(masked_msg.data(), msg, kdf_output.data(), msg_len);

                        hash->update(x2_bytes);
                        hash->update(msg, msg_len);
                        hash->update(y2_bytes);
                        std::vector<uint8_t> C3(hash->output_length());
                        hash->final(C3.data());

                        return der_encoder()
                            .start_cons(SEQUENCE)
                            .encode(x1)
                            .encode(y1)
                            .encode(C3, OCTET_STRING)
                            .encode(masked_msg, OCTET_STRING)
                            .end_cons()
                            .get_contents();
                    }

                private:
                    const ec_group m_group;
                    point_gfp_var_point_precompute m_mul_public_point;
                    const std::string m_kdf_hash;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

                class SM2_Decryption_Operation final : public pk_operations::decryption {
                public:
                    SM2_Decryption_Operation(const sm2_encryption_private_key &key, random_number_generator &rng,
                                             const std::string &kdf_hash) :
                        m_key(key),
                        m_rng(rng), m_kdf_hash(kdf_hash) {
                    }

                    secure_vector<uint8_t> decrypt(uint8_t &valid_mask, const uint8_t ciphertext[],
                                                   size_t ciphertext_len) override {
                        const ec_group &group = m_key.domain();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> &cofactor = group.get_cofactor();
                        const size_t p_bytes = group.get_p_bytes();

                        valid_mask = 0x00;

                        std::unique_ptr<HashFunction> hash = HashFunction::create_or_throw(m_kdf_hash);
                        std::unique_ptr<KDF> kdf = KDF::create_or_throw("KDF2(" + m_kdf_hash + ")");

                        // Too short to be valid - no timing problem from early return
                        if (ciphertext_len < 1 + p_bytes * 2 + hash->output_length()) {
                            return secure_vector<uint8_t>();
                        }

                        boost::multiprecision::number<Backend, ExpressionTemplates> x1, y1;
                        secure_vector<uint8_t> C3, masked_msg;

                        ber_decoder(ciphertext, ciphertext_len)
                            .start_cons(SEQUENCE)
                            .decode(x1)
                            .decode(y1)
                            .decode(C3, OCTET_STRING)
                            .decode(masked_msg, OCTET_STRING)
                            .end_cons()
                            .verify_end();

                        point_gfp C1 = group.point(x1, y1);
                        C1.randomize_repr(m_rng);

                        if (!C1.on_the_curve()) {
                            return secure_vector<uint8_t>();
                        }

                        if (cofactor > 1 && (C1 * cofactor).is_zero()) {
                            return secure_vector<uint8_t>();
                        }

                        const point_gfp dbC1 = group.blinded_var_point_multiply(C1, m_key.private_value(), m_rng, m_ws);

                        const boost::multiprecision::number<Backend, ExpressionTemplates> x2 = dbC1.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> y2 = dbC1.get_affine_y();

                        std::vector<uint8_t> x2_bytes(p_bytes);
                        std::vector<uint8_t> y2_bytes(p_bytes);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(x2_bytes.data(), x2_bytes.size(), x2);
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(y2_bytes.data(), y2_bytes.size(), y2);

                        secure_vector<uint8_t> kdf_input;
                        kdf_input += x2_bytes;
                        kdf_input += y2_bytes;

                        const secure_vector<uint8_t> kdf_output
                            = kdf->derive_key(masked_msg.size(), kdf_input.data(), kdf_input.size());

                        xor_buf(masked_msg.data(), kdf_output.data(), kdf_output.size());

                        hash->update(x2_bytes);
                        hash->update(masked_msg);
                        hash->update(y2_bytes);
                        secure_vector<uint8_t> u = hash->final();

                        if (constant_time_compare(u.data(), C3.data(), hash->output_length()) == false) {
                            return secure_vector<uint8_t>();
                        }

                        valid_mask = 0xFF;
                        return masked_msg;
                    }

                private:
                    const sm2_encryption_private_key &m_key;
                    random_number_generator &m_rng;
                    const std::string m_kdf_hash;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

            }    // namespace

            std::unique_ptr<pk_operations::encryption> sm2_encryption_public_key::create_encryption_op(
                random_number_generator & /*random*/, const std::string &params, const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    const std::string kdf_hash = (params.empty() ? "SM3" : params);
                    return std::unique_ptr<pk_operations::encryption>(new SM2_Encryption_Operation(*this, kdf_hash));
                }

                throw provider_not_found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::decryption>
                sm2_encryption_private_key::create_decryption_op(random_number_generator &rng,
                                                                 const std::string &params,
                                                                 const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    const std::string kdf_hash = (params.empty() ? "SM3" : params);
                    return std::unique_ptr<pk_operations::decryption>(
                        new SM2_Decryption_Operation(*this, rng, kdf_hash));
                }

                throw provider_not_found(algo_name(), provider);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil
