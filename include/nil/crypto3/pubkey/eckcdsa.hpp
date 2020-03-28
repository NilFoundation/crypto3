//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECKCDSA_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            /**
             * This class represents ECKCDSA public keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa_public_key : public virtual ec_public_key<CurveType, NumberType> {
            public:
                /**
                 * Construct a public key from a given public point.
                 * @param dom_par the domain parameters associated with this key
                 * @param public_point the public point defining this key
                 */
                eckcdsa_public_key(const ec_group<CurveType, NumberType> &dom_par,
                                   const point_gfp<CurveType> &public_point) :
                    ec_public_key<CurveType, NumberType>(dom_par, public_point) {
                }

                /**
                 * Load a public key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits DER encoded public key bits
                 */
                eckcdsa_public_key(const algorithm_identifier &alg_id, const std::vector<uint8_t> &key_bits) :
                    ec_public_key<CurveType, NumberType>(alg_id, key_bits) {
                }

                /**
                 * Get the OID of the underlying public key scheme.
                 * @return oid_t of the public key scheme
                 */
                static const oid_t oid() {
                    return oid_t({1, 0, 14888, 3, 0, 5});
                }

                /**
                 * Get this keys algorithm name.
                 * @result this keys algorithm name ("ECGDSA")
                 */
                std::string algo_name() const override {
                    return "ECKCDSA";
                }

                size_t message_parts() const override {
                    return 2;
                }

                size_t message_part_size() const override {
                    return domain().get_order().bytes();
                }

                std::unique_ptr<pk_operations::verification>
                    create_verification_op(const std::string &params, const std::string &provider) const override;

            protected:
                eckcdsa_public_key() = default;
            };

            /**
             * This class represents ECKCDSA private keys.
             */
            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa_private_key : public eckcdsa_public_key<CurveType, NumberType>,
                                        public ec_private_key<CurveType, NumberType> {
            public:
                /**
                 * Load a private key.
                 * @param alg_id the X.509 algorithm identifier
                 * @param key_bits ECPrivateKey bits
                 */
                eckcdsa_private_key(const algorithm_identifier &alg_id, const secure_vector<uint8_t> &key_bits) :
                    ec_private_key<CurveType, NumberType>(alg_id, key_bits, true) {
                }

                /**
                 * Create a private key.
                 * @param rng a random number generator
                 * @param domain parameters to used for this key
                 * @param x the private key (if zero, generate a new random key)
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                eckcdsa_private_key(random_number_generator &rng, const ec_group<CurveType, NumberType> &domain,
                                    const number<Backend, ExpressionTemplates> &x = 0) :
                    ec_private_key<CurveType, NumberType>(rng, domain, x, true) {
                }

                bool check_key(random_number_generator &rng, bool) const override;

                std::unique_ptr<pk_operations::signature>
                    create_signature_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const override;
            };

            template<typename CurveType, typename NumberType = typename CurveType::number_type>
            class eckcdsa {
            public:
                typedef eckcdsa_public_key<CurveType, NumberType> public_key_policy;
                typedef eckcdsa_private_key<CurveType, NumberType> private_key_policy;
            };

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
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_x =
                            eckcdsa.public_point().get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_y =
                            eckcdsa.public_point().get_affine_y();

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
                    const boost::multiprecision::number<Backend, ExpressionTemplates> k_times_P_x =
                        m_group.blinded_base_point_multiply_x(k, rng, m_ws);

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

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.multiply_mod_order(m_x, k - w);
                    if (s.is_zero()) {
                        throw internal_error("During ECKCDSA signature generation created zero s");
                    }

                    secure_vector<uint8_t> output =
                        boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(r, c.size());
                    output += boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        s, m_group.get_order_bytes());
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
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_x =
                            m_public_point.get_affine_x();
                        const boost::multiprecision::number<Backend, ExpressionTemplates> public_point_y =
                            m_public_point.get_affine_y();

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

            }    // namespace

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
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
