//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECIES_HPP
#define CRYPTO3_PUBKEY_ECIES_HPP

#include <memory>
#include <string>
#include <vector>
#include <limits>

#include <nil/crypto3/pubkey/ecdh.hpp>
#include <nil/crypto3/pubkey/scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct ecies_public_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct ecies_private_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct ecies_agreement_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType, typename KeyDerivationFunction, typename MessageAuthenticationCode>
            struct ecies {
                typedef CurveType curve_type;
                typedef KeyDerivationFunction kdf_type;
                typedef MessageAuthenticationCode mac_type;

                typedef ecies_public_key<CurveType> public_key_type;
                typedef ecies_private_key<CurveType> private_key_type;
                typedef ecies_agreement_key<CurveType> agreement_key_type;
            };

            enum class ecies_flags : uint32_t {
                NONE = 0,

                /// if set: prefix the input of the (ecdh) key agreement with the encoded (ephemeral) public key
                SINGLE_HASH_MODE = 1,

                /// (decryption only) if set: use cofactor multiplication during (ecdh) key agreement
                COFACTOR_MODE = 2,

                /// if set: use ecdhc instead of ecdh
                OLD_COFACTOR_MODE = 4,

                /// (decryption only) if set: test if the (ephemeral) public key is on the curve
                CHECK_MODE = 8
            };

            inline ecies_flags operator|(ecies_flags a, ecies_flags b) {
                return static_cast<ecies_flags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
            }

            inline ecies_flags operator&(ecies_flags a, ecies_flags b) {
                return static_cast<ecies_flags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
            }

            /**
             * Parameters for ECIES secret derivation
             */
            class ecies_ka_params {
            public:
                /**
                 * @param domain ec domain parameters of the involved ec keys
                 * @param kdf_spec name of the key derivation function
                 * @param length length of the secret to be derived
                 * @param compression_type format of encoded keys (affects the secret derivation if single_hash_mode is
                 * used)
                 * @param flags options, see documentation of ecies_flags
                 */
                ecies_ka_params(const ec_group &domain, const std::string &kdf_spec, size_t length,
                                point_gfp::compression_type compression_type, ecies_flags flags);

                ecies_ka_params(const ecies_ka_params &) = default;

                ecies_ka_params &operator=(const ecies_ka_params &) = default;

                virtual ~ecies_ka_params() = default;

                inline const ec_group &domain() const {
                    return m_domain;
                }

                inline size_t secret_length() const {
                    return m_length;
                }

                inline bool single_hash_mode() const {
                    return (m_flags & ecies_flags::SINGLE_HASH_MODE) == ecies_flags::SINGLE_HASH_MODE;
                }

                inline bool cofactor_mode() const {
                    return (m_flags & ecies_flags::COFACTOR_MODE) == ecies_flags::COFACTOR_MODE;
                }

                inline bool old_cofactor_mode() const {
                    return (m_flags & ecies_flags::OLD_COFACTOR_MODE) == ecies_flags::OLD_COFACTOR_MODE;
                }

                inline bool check_mode() const {
                    return (m_flags & ecies_flags::CHECK_MODE) == ecies_flags::CHECK_MODE;
                }

                inline point_gfp::compression_type compression_type() const {
                    return m_compression_mode;
                }

                const std::string &kdf_spec() const {
                    return m_kdf_spec;
                }

            private:
                const ec_group m_domain;
                const std::string m_kdf_spec;
                const size_t m_length;
                const point_gfp::compression_type m_compression_mode;
                const ecies_flags m_flags;
            };

            class ecies_system_params final : public ecies_ka_params {
            public:
                /**
                 * @param domain ec domain parameters of the involved ec keys
                 * @param kdf_spec name of the key derivation function
                 * @param dem_algo_spec name of the data encryption method
                 * @param dem_key_len length of the key used for the data encryption method
                 * @param mac_spec name of the message authentication code
                 * @param mac_key_len length of the key used for the message authentication code
                 */
                ecies_system_params(const ec_group &domain, const std::string &kdf_spec,
                                    const std::string &dem_algo_spec, size_t dem_key_len, const std::string &mac_spec,
                                    size_t mac_key_len);

                /**
                 * @param domain ec domain parameters of the involved ec keys
                 * @param kdf_spec name of the key derivation function
                 * @param dem_algo_spec name of the data encryption method
                 * @param dem_key_len length of the key used for the data encryption method
                 * @param mac_spec name of the message authentication code
                 * @param mac_key_len length of the key used for the message authentication code
                 * @param compression_type format of encoded keys (affects the secret derivation if single_hash_mode is
                 * used)
                 * @param flags options, see documentation of ecies_flags
                 */
                ecies_system_params(const ec_group &domain, const std::string &kdf_spec,
                                    const std::string &dem_algo_spec, size_t dem_key_len, const std::string &mac_spec,
                                    size_t mac_key_len, point_gfp::compression_type compression_type,
                                    ecies_flags flags);

                ecies_system_params(const ecies_system_params &) = default;

                ecies_system_params &operator=(const ecies_system_params &) = default;

                virtual ~ecies_system_params() = default;

                /// creates an instance of the message authentication code
                std::unique_ptr<MessageAuthenticationCode> create_mac() const;

                /// creates an instance of the data encryption method
                std::unique_ptr<cipher_mode> create_cipher(nil::crypto3::cipher_dir direction) const;

                /// returns the length of the key used by the data encryption method
                inline size_t dem_keylen() const {
                    return m_dem_keylen;
                }

                /// returns the length of the key used by the message authentication code
                inline size_t mac_keylen() const {
                    return m_mac_keylen;
                }

            private:
                const std::string m_dem_spec;
                const size_t m_dem_keylen;
                const std::string m_mac_spec;
                const size_t m_mac_keylen;
            };

            /**
             * ECIES secret derivation according to ISO 18033-2
             */
            class ecies_ka_operation {
            public:
                /**
                 * @param private_key the (ephemeral) private key which is used to derive the secret
                 * @param ecies_params settings for ecies
                 * @param for_encryption disable cofactor mode if the secret will be used for encryption
                 * (according to ISO 18033 cofactor mode is only used during decryption)
                 * @param rng the RNG to use
                 */
                ecies_ka_operation(const pk_key_agreement_key &private_key, const ecies_ka_params &ecies_params,
                                   bool for_encryption, random_number_generator &rng);

                /**
                 * Performs a key agreement with the provided keys and derives the secret from the result
                 * @param eph_public_key_bin the encoded (ephemeral) public key which belongs to the used (ephemeral)
                 * private key
                 * @param other_public_key_point public key point of the other party
                 */
                symmetric_key derive_secret(const std::vector<uint8_t> &eph_public_key_bin,
                                            const point_gfp &other_public_key_point) const;

            private:
                const pk_key_agreement m_ka;
                const ecies_ka_params m_params;
            };

            /**
             * ECIES Encryption according to ISO 18033-2
             */
            class ecies_encryptor final : public pk_encryptor {
            public:
                /**
                 * @param private_key the (ephemeral) private key which is used for the key agreement
                 * @param ecies_params settings for ecies
                 * @param rng random generator to use
                 */
                ecies_encryptor(const pk_key_agreement_key &private_key, const ecies_system_params &ecies_params,
                                random_number_generator &rng);

                /**
                 * Creates an ephemeral private key which is used for the key agreement
                 * @param rng random generator used during private key generation
                 * @param ecies_params settings for ecies
                 */
                ecies_encryptor(random_number_generator &rng, const ecies_system_params &ecies_params);

                /// Set the public key of the other party
                inline void set_other_key(const nil::crypto3::point_gfp &public_point) {
                    m_other_point = public_point;
                }

                /// Set the initialization vector for the data encryption method
                inline void set_initialization_vector(const InitializationVector &iv) {
                    m_iv = iv;
                }

                /// Set the label which is appended to the input for the message authentication code
                inline void set_label(const std::string &label) {
                    m_label = std::vector<uint8_t>(label.begin(), label.end());
                }

            private:
                std::vector<uint8_t> enc(const uint8_t data[], size_t length, random_number_generator &) const override;

                inline size_t maximum_input_size() const override {
                    return std::numeric_limits<size_t>::max();
                }

                const ecies_ka_operation m_ka;
                const ecies_system_params m_params;
                std::vector<uint8_t> m_eph_public_key_bin;
                InitializationVector m_iv;
                point_gfp m_other_point;
                std::vector<uint8_t> m_label;
            };

            /**
             * ECIES Decryption according to ISO 18033-2
             */
            class ecies_decryptor final : public pk_decryptor {
            public:
                /**
                 * @param private_key the private key which is used for the key agreement
                 * @param ecies_params settings for ecies
                 * @param rng the random generator to use
                 */
                ecies_decryptor(const pk_key_agreement_key &private_key, const ecies_system_params &ecies_params,
                                random_number_generator &rng);

                /// Set the initialization vector for the data encryption method
                inline void set_initialization_vector(const InitializationVector &iv) {
                    m_iv = iv;
                }

                /// Set the label which is appended to the input for the message authentication code
                inline void set_label(const std::string &label) {
                    m_label = std::vector<uint8_t>(label.begin(), label.end());
                }

            private:
                secure_vector<uint8_t> do_decrypt(uint8_t &valid_mask, const uint8_t in[],
                                                  size_t in_len) const override;

                const ecies_ka_operation m_ka;
                const ecies_system_params m_params;
                InitializationVector m_iv;
                std::vector<uint8_t> m_label;
            };

            namespace {

                /**
                 * Private key type for ECIES_ECDH_KA_Operation
                 */
                class ecies_private_key final : public ec_private_key, public pk_key_agreement_key {
                public:
                    explicit ecies_private_key(const ecdh_private_key &private_key) :
                        ec_public_key(private_key), ec_private_key(private_key), pk_key_agreement_key(),
                        m_key(private_key) {
                    }

                    std::vector<uint8_t> public_value() const override {
                        return m_key.public_value();
                    }

                    std::string algo_name() const override {
                        return "ECIES";
                    }

                    std::unique_ptr<pk_operations::key_agreement>
                        create_key_agreement_op(random_number_generator &rng,
                                                const std::string &params,
                                                const std::string &provider) const override;

                private:
                    ecdh_private_key m_key;
                };

                /**
                 * Implements ECDH key agreement without using the cofactor mode
                 */
                class ecies_ecdh_ka_operation final : public pk_operations::key_agreement_with_kdf {
                public:
                    ecies_ecdh_ka_operation(const ecies_private_key &private_key, random_number_generator &rng) :
                        pk_operations::key_agreement_with_kdf("Raw"), m_key(private_key), m_rng(rng) {
                    }

                    secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
                        const ec_group &group = m_key.domain();

                        point_gfp input_point = group.os2ecp(w, w_len);
                        input_point.randomize_repr(m_rng);

                        const point_gfp S =
                            group.blinded_var_point_multiply(input_point, m_key.private_value(), m_rng, m_ws);

                        if (S.on_the_curve() == false) {
                            throw internal_error("ECDH agreed value was not on the curve");
                        }
                        return number<Backend, ExpressionTemplates>::encode_1363(S.get_affine_x(), group.get_p_bytes());
                    }

                private:
                    ecies_private_key m_key;
                    random_number_generator &m_rng;
                    std::vector<number<Backend, ExpressionTemplates>> m_ws;
                };

                std::unique_ptr<pk_operations::key_agreement>
                    ecies_private_key::create_key_agreement_op(random_number_generator &rng,
                                                               const std::string & /*params*/,
                                                               const std::string & /*provider*/) const {
                    return std::unique_ptr<pk_operations::key_agreement>(new ecies_ecdh_ka_operation(*this, rng));
                }

                /**
                 * Creates a pk_key_agreement instance for the given key and ecies_params
                 * Returns either ECIES_ECDH_KA_Operation or the default implementation for the given key,
                 * depending on the key and ecies_params
                 * @param private_key the private key used for the key agreement
                 * @param ecies_params settings for ecies
                 * @param for_encryption disable cofactor mode if the secret will be used for encryption
                 * (according to ISO 18033 cofactor mode is only used during decryption)
                 */
                pk_key_agreement create_key_agreement(const pk_key_agreement_key &private_key,
                                                      const ecies_ka_params &ecies_params, bool for_encryption,
                                                      random_number_generator &rng) {
                    const ecdh_private_key *ecdh_key = dynamic_cast<const ecdh_private_key *>(&private_key);

                    if (ecdh_key == nullptr && (ecies_params.cofactor_mode() || ecies_params.old_cofactor_mode() ||
                                                ecies_params.check_mode())) {
                        // assume we have a private key from an external provider (e.g. pkcs#11):
                        // there is no way to determine or control whether the provider uses cofactor mode or not.
                        // ISO 18033 does not allow cofactor mode in combination with old cofactor mode or check mode
                        // => disable cofactor mode, old cofactor mode and check mode for unknown keys/providers (as a
                        // precaution).
                        throw std::invalid_argument(
                            "ECIES: cofactor, old cofactor and check mode are only supported for ecdh_private_key");
                    }

                    if (ecdh_key && (for_encryption || !ecies_params.cofactor_mode())) {
                        // ecdh_ka_operation uses cofactor mode: use own key agreement method if cofactor should not be
                        // used.
                        return pk_key_agreement(ecies_private_key(*ecdh_key), rng, "Raw");
                    }

                    return pk_key_agreement(private_key, rng, "Raw");    // use default implementation
                }
            }    // namespace

            ecies_ka_operation::ecies_ka_operation(const pk_key_agreement_key &private_key,
                                                   const ecies_ka_params &ecies_params, bool for_encryption,
                                                   random_number_generator &rng) :
                m_ka(create_key_agreement(private_key, ecies_params, for_encryption, rng)),
                m_params(ecies_params) {
            }

            /**
             * ECIES secret derivation according to ISO 18033-2
             */
            symmetric_key ecies_ka_operation::derive_secret(const std::vector<uint8_t> &eph_public_key_bin,
                                                            const point_gfp &other_public_key_point) const {
                if (other_public_key_point.is_zero()) {
                    throw std::invalid_argument("ECIES: other public key point is zero");
                }

                std::unique_ptr<kdf> kdf = nil::crypto3::kdf::create_or_throw(m_params.kdf_spec());

                point_gfp other_point = other_public_key_point;

                // ISO 18033: step b
                if (m_params.old_cofactor_mode()) {
                    other_point *= m_params.domain().get_cofactor();
                }

                secure_vector<uint8_t> derivation_input;

                // ISO 18033: encryption step e / decryption step g
                if (!m_params.single_hash_mode()) {
                    derivation_input += eph_public_key_bin;
                }

                // ISO 18033: encryption step f / decryption step h
                std::vector<uint8_t> other_public_key_bin = other_point.encode(m_params.compression_type());
                // Note: the argument `m_params.secret_length()` passed for `key_len` will only be used by providers
                // because "Raw" is passed to the `pk_key_agreement` if the implementation of botan is used.
                const symmetric_key peh = m_ka.derive_key(m_params.domain().get_order().bytes(),
                                                          other_public_key_bin.data(), other_public_key_bin.size());
                derivation_input.insert(derivation_input.end(), peh.begin(), peh.end());

                // ISO 18033: encryption step g / decryption step i
                return kdf->derive_key(m_params.secret_length(), derivation_input);
            }

            ecies_ka_params::ecies_ka_params(const ec_group &domain, const std::string &kdf_spec, size_t length,
                                             point_gfp::compression_type compression_type, ecies_flags flags) :
                m_domain(domain),
                m_kdf_spec(kdf_spec), m_length(length), m_compression_mode(compression_type), m_flags(flags) {
            }

            ecies_system_params::ecies_system_params(const ec_group &domain, const std::string &kdf_spec,
                                                     const std::string &dem_algo_spec, size_t dem_key_len,
                                                     const std::string &mac_spec, size_t mac_key_len,
                                                     point_gfp::compression_type compression_type, ecies_flags flags) :
                ecies_ka_params(domain, kdf_spec, dem_key_len + mac_key_len, compression_type, flags),
                m_dem_spec(dem_algo_spec), m_dem_keylen(dem_key_len), m_mac_spec(mac_spec), m_mac_keylen(mac_key_len) {
                // ISO 18033: "At most one of CofactorMode, OldCofactorMode, and CheckMode may be 1."
                if (size_t(cofactor_mode()) + size_t(old_cofactor_mode()) + size_t(check_mode()) > 1) {
                    throw std::invalid_argument(
                        "ECIES: only one of cofactor_mode, old_cofactor_mode and check_mode can be set");
                }
            }

            ecies_system_params::ecies_system_params(const ec_group &domain, const std::string &kdf_spec,
                                                     const std::string &dem_algo_spec, size_t dem_key_len,
                                                     const std::string &mac_spec, size_t mac_key_len) :
                ecies_system_params(domain, kdf_spec, dem_algo_spec, dem_key_len, mac_spec, mac_key_len,
                                    point_gfp::UNCOMPRESSED, ecies_flags::NONE) {
            }

            std::unique_ptr<MessageAuthenticationCode> ecies_system_params::create_mac() const {
                return nil::crypto3::MessageAuthenticationCode::create_or_throw(m_mac_spec);
            }

            std::unique_ptr<cipher_mode> ecies_system_params::create_cipher(nil::crypto3::cipher_dir direction) const {
                return cipher_mode::create_or_throw(m_dem_spec, direction);
            }

            /*
             * ecies_encryptor Constructor
             */
            ecies_encryptor::ecies_encryptor(const pk_key_agreement_key &private_key,
                                             const ecies_system_params &ecies_params, random_number_generator &rng) :
                m_ka(private_key, ecies_params, true, rng),
                m_params(ecies_params),
                m_eph_public_key_bin(
                    private_key.public_value()),    // returns the uncompressed public key, see conversion below
                m_iv(), m_other_point(), m_label() {
                if (ecies_params.compression_type() != point_gfp::UNCOMPRESSED) {
                    // ISO 18033: step d
                    // convert only if necessary; m_eph_public_key_bin has been initialized with the uncompressed format
                    m_eph_public_key_bin =
                        m_params.domain().os2ecp(m_eph_public_key_bin).encode(ecies_params.compression_type());
                }
            }

            /*
             * ecies_encryptor Constructor
             */
            ecies_encryptor::ecies_encryptor(random_number_generator &rng, const ecies_system_params &ecies_params) :
                ecies_encryptor(ecdh_private_key(rng, ecies_params.domain()), ecies_params, rng) {
            }

            /*
             * ECIES encryption according to ISO 18033-2
             */
            std::vector<uint8_t> ecies_encryptor::enc(const uint8_t data[], size_t length,
                                                      random_number_generator &) const {
                if (m_other_point.is_zero()) {
                    throw invalid_state("ECIES: the other key is zero");
                }

                const symmetric_key secret_key = m_ka.derive_secret(m_eph_public_key_bin, m_other_point);

                // encryption
                std::unique_ptr<cipher_mode> cipher = m_params.create_cipher(ENCRYPTION);
                BOOST_ASSERT_MSG(cipher != nullptr, "Cipher is found");

                cipher->set_key(symmetric_key(secret_key.begin(), m_params.dem_keylen()));
                if (m_iv.size() != 0) {
                    cipher->start(m_iv.bits_of());
                }
                secure_vector<uint8_t> encrypted_data(data, data + length);
                cipher->finish(encrypted_data);

                // concat elements
                std::unique_ptr<MessageAuthenticationCode> mac = m_params.create_mac();
                BOOST_ASSERT_MSG(mac != nullptr, "MAC is found");

                secure_vector<uint8_t> out(m_eph_public_key_bin.size() + encrypted_data.size() + mac->output_length());
                buffer_insert(out, 0, m_eph_public_key_bin);
                buffer_insert(out, m_eph_public_key_bin.size(), encrypted_data);

                // mac
                mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
                mac->update(encrypted_data);
                if (!m_label.empty()) {
                    mac->update(m_label);
                }
                mac->final(out.data() + m_eph_public_key_bin.size() + encrypted_data.size());

                return unlock(out);
            }

            ecies_decryptor::ecies_decryptor(const pk_key_agreement_key &key, const ecies_system_params &ecies_params,
                                             random_number_generator &rng) :
                m_ka(key, ecies_params, false, rng),
                m_params(ecies_params), m_iv(), m_label() {
                // ISO 18033: "If v > 1 and CheckMode = 0, then we must have gcd(u, v) = 1." (v = index, u= order)
                if (!ecies_params.check_mode()) {
                    const number<Backend, ExpressionTemplates> &cofactor = m_params.domain().get_cofactor();
                    if (cofactor > 1 && boost::math::gcd(cofactor, m_params.domain().get_order()) != 1) {
                        throw std::invalid_argument("ECIES: gcd of cofactor and order must be 1 if check_mode is 0");
                    }
                }
            }

            /**
             * ECIES Decryption according to ISO 18033-2
             */
            secure_vector<uint8_t> ecies_decryptor::do_decrypt(uint8_t &valid_mask, const uint8_t in[],
                                                               size_t in_len) const {
                size_t point_size = m_params.domain().get_p_bytes();
                if (m_params.compression_type() != point_gfp::COMPRESSED) {
                    point_size *= 2;    // uncompressed and hybrid contains x AND y
                }
                point_size += 1;    // format byte

                std::unique_ptr<MessageAuthenticationCode> mac = m_params.create_mac();
                BOOST_ASSERT_MSG(mac != nullptr, "MAC is found");

                if (in_len < point_size + mac->output_length()) {
                    throw decoding_error("ECIES decryption: ciphertext is too short");
                }

                // extract data
                const std::vector<uint8_t> other_public_key_bin(
                    in,
                    in + point_size);    // the received (ephemeral) public key
                const std::vector<uint8_t> encrypted_data(in + point_size, in + in_len - mac->output_length());
                const std::vector<uint8_t> mac_data(in + in_len - mac->output_length(), in + in_len);

                // ISO 18033: step a
                point_gfp other_public_key = m_params.domain().os2ecp(other_public_key_bin);

                // ISO 18033: step b
                if (m_params.check_mode() && !other_public_key.on_the_curve()) {
                    throw decoding_error("ECIES decryption: received public key is not on the curve");
                }

                // ISO 18033: step e (and step f because get_affine_x (called by ecdh_ka_operation::raw_agree)
                // throws illegal_transformation if the point is zero)
                const symmetric_key secret_key = m_ka.derive_secret(other_public_key_bin, other_public_key);

                // validate mac
                mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
                mac->update(encrypted_data);
                if (!m_label.empty()) {
                    mac->update(m_label);
                }
                const secure_vector<uint8_t> calculated_mac = mac->final();
                valid_mask = ct::expand_mask<uint8_t>(
                    constant_time_compare(mac_data.data(), calculated_mac.data(), mac_data.size()));

                if (valid_mask) {
                    // isomorphic_decryption_mode data
                    std::unique_ptr<cipher_mode> cipher = m_params.create_cipher(DECRYPTION);
                    BOOST_ASSERT_MSG(cipher != nullptr, "Cipher is found");

                    cipher->set_key(symmetric_key(secret_key.begin(), m_params.dem_keylen()));
                    if (m_iv.size() != 0) {
                        cipher->start(m_iv.bits_of());
                    }

                    try {
                        // the decryption can fail:
                        // e.g. integrity_failure is thrown if GCM is used and the message does not have a valid tag
                        secure_vector<uint8_t> decrypted_data(encrypted_data.begin(), encrypted_data.end());
                        cipher->finish(decrypted_data);
                        return decrypted_data;
                    } catch (...) {
                        valid_mask = 0;
                    }
                }
                return secure_vector<uint8_t>();
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
