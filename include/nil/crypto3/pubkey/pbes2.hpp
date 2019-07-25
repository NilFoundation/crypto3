#ifndef CRYPTO3_PUBKEY_PBE_PKCS_v20_HPP
#define CRYPTO3_PUBKEY_PBE_PKCS_v20_HPP

#include <nil/crypto3/asn1/alg_id.hpp>

#include <chrono>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                /*
                 * Encode PKCS#5 PBES2 parameters
                 */
                std::vector<uint8_t> encode_pbes2_params(const std::string &cipher, const std::string &prf,
                                                         const secure_vector<uint8_t> &salt,
                                                         const secure_vector<uint8_t> &iv, size_t iterations,
                                                         size_t key_length) {
                    return der_encoder()
                        .start_cons(SEQUENCE)
                        .encode(algorithm_identifier(
                            "PKCS5.PBKDF2",
                            der_encoder()
                                .start_cons(SEQUENCE)
                                .encode(salt, OCTET_STRING)
                                .encode(iterations)
                                .encode(key_length)
                                .encode_if(prf != "HMAC(SHA-160)",
                                           algorithm_identifier(prf, algorithm_identifier::USE_NULL_PARAM))
                                .end_cons()
                                .get_contents_unlocked()))
                        .encode(algorithm_identifier(cipher,
                                                     der_encoder().encode(iv, OCTET_STRING).get_contents_unlocked()))
                        .end_cons()
                        .get_contents_unlocked();
                }

                /*
                 * PKCS#5 v2.0 PBE encryption
                 */
                std::pair<algorithm_identifier, std::vector<uint8_t>>
                    pbes2_encrypt_shared(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                                         size_t *msec_in_iterations_out, size_t iterations_if_msec_null,
                                         const std::string &cipher, const std::string &digest,
                                         RandomNumberGenerator &rng) {
                    const std::string prf = "HMAC(" + digest + ")";

                    const std::vector<std::string> cipher_spec = split_on(cipher, '/');
                    if (cipher_spec.size() != 2) {
                        throw decoding_error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);
                    }

                    const secure_vector<uint8_t> salt = rng.random_vec(12);

                    if (cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM") {
                        throw decoding_error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);
                    }

                    std::unique_ptr<cipher_mode> enc = cipher_mode::create(cipher, ENCRYPTION);

                    if (!enc) {
                        throw decoding_error("PBE-PKCS5 cannot encipher no cipher " + cipher);
                    }

                    std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

                    const size_t key_length = enc->key_spec().maximum_keylength();

                    secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

                    size_t iterations = iterations_if_msec_null;

                    if (msec_in_iterations_out) {
                        std::chrono::milliseconds msec(*msec_in_iterations_out);
                        enc->set_key(
                            pbkdf->derive_key(key_length, passphrase, salt.data(), salt.size(), msec, iterations)
                                .bits_of());
                        *msec_in_iterations_out = iterations;
                    } else {
                        enc->set_key(
                            pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));
                    }

                    enc->start(iv);
                    secure_vector<uint8_t> buf = key_bits;
                    enc->finish(buf);

                    algorithm_identifier id(oids::lookup("PBE-PKCS5v20"),
                                            encode_pbes2_params(cipher, prf, salt, iv, iterations, key_length));

                    return std::make_pair(id, unlock(buf));
                }
            }    // namespace detail

            /**
             * @brief Encrypt with PBES2 from PKCS #5 v2.0
             * @param key_bits the input
             * @param passphrase the passphrase to use for encryption
             * @param msec how many milliseconds to run PBKDF2
             * @param cipher specifies the block cipher to use to encrypt
             * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
             * @param rng a random number generator
             */
            template<typename UniformRandomGenerator>
            std::pair<algorithm_identifier, std::vector<uint8_t>>
                pbes2_encrypt(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                              std::chrono::milliseconds msec, const std::string &cipher, const std::string &digest,
                              UniformRandomGenerator &rng) {
                size_t msec_in_iterations_out = static_cast<size_t>(msec.count());
                return pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);
                // return value msec_in_iterations_out discarded
            }

            /**
             * @brief Encrypt with PBES2 from PKCS #5 v2.0
             * @param key_bits the input
             * @param passphrase the passphrase to use for encryption
             * @param msec how many milliseconds to run PBKDF2
             * @param out_iterations_if_nonnull if not null, set to the number
             * of PBKDF iterations used
             * @param cipher specifies the block cipher to use to encrypt
             * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
             * @param rng a random number generator
             */
            template<typename UniformRandomGenerator>
            std::pair<algorithm_identifier, std::vector<uint8_t>>
                pbes2_encrypt_msec(const secure_vector<uint8_t> &key_bits,
                                   const std::string &passphrase,
                                   std::chrono::milliseconds msec,
                                   size_t *out_iterations_if_nonnull,
                                   const std::string &cipher,
                                   const std::string &digest,
                                   UniformRandomGenerator &rng) {
                size_t msec_in_iterations_out = static_cast<size_t>(msec.count());

                auto ret = pbes2_encrypt_shared(key_bits, passphrase, &msec_in_iterations_out, 0, cipher, digest, rng);

                if (out_iterations_if_nonnull) {
                    *out_iterations_if_nonnull = msec_in_iterations_out;
                }

                return ret;
            }

            /**
             * @brief Encrypt with PBES2 from PKCS #5 v2.0
             * @param key_bits the input
             * @param passphrase the passphrase to use for encryption
             * @param iterations how many iterations to run PBKDF2
             * @param cipher specifies the block cipher to use to encrypt
             * @param digest specifies the PRF to use with PBKDF2 (eg "HMAC(SHA-1)")
             * @param rng a random number generator
             */
            template<typename UniformRandomGenerator>
            std::pair<algorithm_identifier, std::vector<uint8_t>>
                pbes2_encrypt_iter(const secure_vector<uint8_t> &key_bits,
                                   const std::string &passphrase,
                                   size_t pbkdf_iter,
                                   const std::string &cipher,
                                   const std::string &digest,
                                   UniformRandomGenerator &rng) {
                return pbes2_encrypt_shared(key_bits, passphrase, nullptr, pbkdf_iter, cipher, digest, rng);
            }

            /**
             * @brief Decrypt a PKCS #5 v2.0 encrypted stream
             * @param key_bits the input
             * @param passphrase the passphrase to use for decryption
             * @param params the PBES2 parameters
             */
            secure_vector<uint8_t> pbes2_decrypt(const secure_vector<uint8_t> &key_bits, const std::string &passphrase,
                                                 const std::vector<uint8_t> &params) {
                algorithm_identifier kdf_algo, enc_algo;

                ber_decoder(params).start_cons(SEQUENCE).decode(kdf_algo).decode(enc_algo).end_cons();

                algorithm_identifier prf_algo;

                if (kdf_algo.get_oid() != oids::lookup("PKCS5.PBKDF2")) {
                    throw decoding_error("PBE-PKCS5 v2.0: Unknown KDF algorithm " + kdf_algo.get_oid().as_string());
                }

                secure_vector<uint8_t> salt;
                size_t iterations = 0, key_length = 0;

                ber_decoder(kdf_algo.get_parameters())
                    .start_cons(SEQUENCE)
                    .decode(salt, OCTET_STRING)
                    .decode(iterations)
                    .decode_optional(key_length, INTEGER, UNIVERSAL)
                    .decode_optional(prf_algo, SEQUENCE, CONSTRUCTED,
                                     algorithm_identifier("HMAC(SHA-160)", algorithm_identifier::USE_NULL_PARAM))
                    .end_cons();

                const std::string cipher = oids::lookup(enc_algo.get_oid());
                const std::vector<std::string> cipher_spec = split_on(cipher, '/');
                if (cipher_spec.size() != 2) {
                    throw decoding_error("PBE-PKCS5 v2.0: Invalid cipher spec " + cipher);
                }
                if (cipher_spec[1] != "CBC" && cipher_spec[1] != "GCM") {
                    throw decoding_error("PBE-PKCS5 v2.0: Don't know param format for " + cipher);
                }

                if (salt.size() < 8) {
                    throw decoding_error("PBE-PKCS5 v2.0: Encoded salt is too small");
                }

                secure_vector<uint8_t> iv;
                ber_decoder(enc_algo.get_parameters()).decode(iv, OCTET_STRING).verify_end();

                const std::string prf = oids::lookup(prf_algo.get_oid());

                std::unique_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(" + prf + ")"));

                std::unique_ptr<cipher_mode> dec = cipher_mode::create(cipher, DECRYPTION);
                if (!dec) {
                    throw decoding_error("PBE-PKCS5 cannot isomorphic_decryption_mode no cipher " + cipher);
                }

                if (key_length == 0) {
                    key_length = dec->key_spec().maximum_keylength();
                }

                dec->set_key(pbkdf->pbkdf_iterations(key_length, passphrase, salt.data(), salt.size(), iterations));

                dec->start(iv);

                secure_vector<uint8_t> buf = key_bits;
                dec->finish(buf);

                return buf;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
