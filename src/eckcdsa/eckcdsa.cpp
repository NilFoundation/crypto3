#include <nil/crypto3/pubkey/eckcdsa.hpp>
#include <nil/crypto3/pubkey/pk_ops_impl.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>
#include <nil/crypto3/multiprecision/modular_reduce.hpp>
#include <nil/crypto3/pk_pad/emsa.hpp>
#include <nil/crypto3/random/random.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            bool eckcdsa_private_key::check_key(random_number_generator &rng, bool strong) const {
                if (!public_point().on_the_curve()) {
                    return false;
                }

                if (!strong) {
                    return true;
                }

                return keypair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
            }

            namespace {

                /**
* ECKCDSA signature operation
                 */
                class ECKCDSA_Signature_Operation final : public pk_operations::Signature_with_EMSA {
                public:
                    ECKCDSA_Signature_Operation(const eckcdsa_private_key &eckcdsa, const std::string &emsa) :
                        pk_operations::Signature_with_EMSA(emsa), m_group(eckcdsa.domain()),
                        m_x(eckcdsa.private_value()), m_prefix() {
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_x = eckcdsa.public_point().get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_y = eckcdsa.public_point().get_affine_y();

                        m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
                        public_point_x.binary_encode(m_prefix.data());
                        public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
                        m_prefix.resize(
                            HashFunction::create(hash_for_signature())
                                ->hash_block_size());    // use only the "hash input block size" leftmost bits
                    }

                    secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                                    random_number_generator &rng) override;

                    size_t max_input_bits() const override {
                        return m_group.get_order_bits();
                    }

                    bool has_prefix() override {
                        return true;
                    }

                    secure_vector<uint8_t> message_prefix() const override {
                        return m_prefix;
                    }

                private:
                    const ec_group m_group;
                    const boost::multiprecision::number<Backend, ExpressionTemplates> &m_x;
                    secure_vector<uint8_t> m_prefix;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                };

                secure_vector<uint8_t> ECKCDSA_Signature_Operation::raw_sign(const uint8_t msg[], size_t,
                                                                             random_number_generator &rng) {
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k_times_P_x
                        = m_group.blinded_base_point_multiply_x(k, rng, m_ws);

                    secure_vector<uint8_t> to_be_hashed(k_times_P_x.bytes());
                    k_times_P_x.binary_encode(to_be_hashed.data());

                    std::unique_ptr<emsa> emsa = this->clone_emsa();
                    emsa->update(to_be_hashed.data(), to_be_hashed.size());
                    secure_vector<uint8_t> c = emsa->raw_data();
                    c = emsa->encoding_of(c, max_input_bits(), rng);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r(c.data(), c.size());

                    xor_buf(c, msg, c.size());
                    boost::multiprecision::number<Backend, ExpressionTemplates> w(c.data(), c.size());
                    w = m_group.mod_order(w);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s = m_group.multiply_mod_order(m_x, k - w);
                    if (s.is_zero()) {
                        throw internal_error("During ECKCDSA signature generation created zero s");
                    }

                    secure_vector<uint8_t> output = boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(r, c.size());
                    output += boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(s, m_group.get_order_bytes());
                    return output;
                }

                /**
* ECKCDSA verification operation
                 */
                class ECKCDSA_Verification_Operation final : public pk_operations::Verification_with_EMSA {
                public:
                    ECKCDSA_Verification_Operation(const ECKCdsa_public_key &eckcdsa, const std::string &emsa) :
                        pk_operations::Verification_with_EMSA(emsa), m_group(eckcdsa.domain()),
                        m_public_point(eckcdsa.public_point()), m_prefix() {
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_x = m_public_point.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_y = m_public_point.get_affine_y();

                        m_prefix.resize(public_point_x.bytes() + public_point_y.bytes());
                        public_point_x.binary_encode(&m_prefix[0]);
                        public_point_y.binary_encode(&m_prefix[public_point_x.bytes()]);
                        m_prefix.resize(
                            HashFunction::create(hash_for_signature())
                                ->hash_block_size());    // use only the "hash input block size" leftmost bits
                    }

                    bool has_prefix() override {
                        return true;
                    }

                    secure_vector<uint8_t> message_prefix() const override {
                        return m_prefix;
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
                    const point_gfp &m_public_point;
                    secure_vector<uint8_t> m_prefix;
                };

                bool ECKCDSA_Verification_Operation::verify(const uint8_t msg[], size_t, const uint8_t sig[],
                                                            size_t sig_len) {
                    const std::unique_ptr<HashFunction> hash = HashFunction::create(hash_for_signature());
                    // calculate size of r

                    const size_t order_bytes = m_group.get_order_bytes();

                    const size_t size_r = std::min(hash->output_length(), order_bytes);
                    if (sig_len != size_r + order_bytes) {
                        return false;
                    }

                    secure_vector<uint8_t> r(sig, sig + size_r);

                    // check that 0 < s < q
                    const boost::multiprecision::number<Backend, ExpressionTemplates> s(sig + size_r, order_bytes);

                    if (s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    secure_vector<uint8_t> r_xor_e(r);
                    xor_buf(r_xor_e, msg, r.size());
                    boost::multiprecision::number<Backend, ExpressionTemplates> w(r_xor_e.data(), r_xor_e.size());
                    w = m_group.mod_order(w);

                    const point_gfp q = m_group.point_multiply(w, m_public_point, s);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> q_x = q.get_affine_x();
                    secure_vector<uint8_t> c(q_x.bytes());
                    q_x.binary_encode(c.data());
                    std::unique_ptr<emsa> emsa = this->clone_emsa();
                    emsa->update(c.data(), c.size());
                    secure_vector<uint8_t> v = emsa->raw_data();
                    Null_RNG rng;
                    v = emsa->encoding_of(v, max_input_bits(), rng);

                    return (v == r);
                }

            }

        std::unique_ptr<pk_operations::verification>
                ECKCdsa_public_key::create_verification_op(const std::string &params,
                                                           const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::verification>(
                        new ECKCDSA_Verification_Operation(*this, params));
                }
                throw Provider_Not_Found(algo_name(), provider);
            }

            std::unique_ptr<pk_operations::signature>
                eckcdsa_private_key::create_signature_op(random_number_generator & /*random*/,
                                                         const std::string &params,
                                                         const std::string &provider) const {
                if (provider == "core" || provider.empty()) {
                    return std::unique_ptr<pk_operations::signature>(new ECKCDSA_Signature_Operation(*this, params));
                }
                throw provider_not_found(algo_name(), provider);
            }
        }
    }
}
