#ifndef CRYPTO3_PUBKEY_ECIES_HPP
#define CRYPTO3_PUBKEY_ECIES_HPP

#include <memory>
#include <string>
#include <vector>
#include <limits>

#include <nil/crypto3/pubkey/ecdh.hpp>
#include <nil/crypto3/pubkey/ec_group/ec_group.hpp>
#include <nil/crypto3/pubkey/ec_group/point_gfp.hpp>
#include <nil/crypto3/pubkey/pubkey.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

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
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
