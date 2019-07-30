#include <nil/crypto3/pkcs8.h>
#include <nil/crypto3/asn1/der_enc.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/asn1/oids.hpp>
#include <nil/crypto3/pubkey/pem.hpp>

#if defined(CRYPTO3_HAS_PKCS5_PBES2)
#include <nil/crypto3/pubkey/pbes2/pbes2.hpp>
#endif

namespace nil {
    namespace crypto3 {

        namespace pkcs8 {

            namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
                secure_vector <uint8_t> PKCS8_extract(data_source &source, algorithm_identifier &pbe_alg_id) {
                    secure_vector <uint8_t> key_data;

                    ber_decoder(source).start_cons(SEQUENCE).decode(pbe_alg_id).decode(key_data,
                                                                                       OCTET_STRING).verify_end();

                    return key_data;
                }

/*
* PEM decode and/or isomorphic_decryption_mode a private key
*/
                secure_vector <uint8_t> PKCS8_decode(data_source &source, std::function<std::string()> get_passphrase,
                                                     algorithm_identifier &pk_alg_id, bool is_encrypted) {
                    algorithm_identifier pbe_alg_id;
                    secure_vector <uint8_t> key_data, key;

                    try {
                        if (asn1::maybe_BER(source) && !pem_code::matches(source)) {
                            if (is_encrypted) {
                                key_data = PKCS8_extract(source, pbe_alg_id);
                            } else {
                                // todo read more efficiently
                                while (!source.end_of_data()) {
                                    uint8_t b;
                                    size_t read = source.read_byte(b);
                                    if (read) {
                                        key_data.push_back(b);
                                    }
                                }
                            }
                        } else {
                            std::string label;
                            key_data = pem_code::decode(source, label);

                            // todo remove autodetect for pem as well?
                            if (label == "PRIVATE KEY") {
                                is_encrypted = false;
                            } else if (label == "ENCRYPTED PRIVATE KEY") {
                                data_source_memory key_source(key_data);
                                key_data = PKCS8_extract(key_source, pbe_alg_id);
                            } else {
                                throw PKCS8_Exception("Unknown PEM label " + label);
                            }
                        }

                        if (key_data.empty()) {
                            throw PKCS8_Exception("No key data found");
                        }
                    } catch (decoding_error &e) {
                        throw decoding_error("PKCS #8 private key decoding failed: " + std::string(e.what()));
                    }

                    try {
                        if (is_encrypted) {
                            if (oids::lookup(pbe_alg_id.get_oid()) != "PBE-PKCS5v20") {
                                throw Exception("Unknown PBE type " + pbe_alg_id.get_oid().as_string());
                            }
#if defined(CRYPTO3_HAS_PKCS5_PBES2)
                                key = pbes2_decrypt(key_data, get_passphrase(), pbe_alg_id.get_parameters());
#else
                            CRYPTO3_UNUSED(get_passphrase);
                            throw decoding_error("Private key is encrypted but PBES2 was disabled in build");
#endif
                        } else {
                            key = key_data;
                        }

                        ber_decoder(key).start_cons(SEQUENCE).decode_and_check<size_t>(0,
                                                                                       "Unknown PKCS #8 version number").decode(
                                pk_alg_id).decode(key, OCTET_STRING).discard_remaining().end_cons();
                    } catch (std::exception &e) {
                        throw decoding_error("PKCS #8 private key decoding failed: " + std::string(e.what()));
                    }
                    return key;
                }

            }

/*
* BER encode a PKCS #8 private key, unencrypted
*/
            secure_vector <uint8_t> ber_encode(const private_key_policy &key) {
                // keeping around for compat
                return key.private_key_info();
            }

/*
* PEM encode a PKCS #8 private key, unencrypted
*/
            std::string pem_encode(const private_key_policy &key) {
                return pem_code::encode(pkcs8::ber_encode(key), "PRIVATE KEY");
            }

#if defined(CRYPTO3_HAS_PKCS5_PBES2)

            namespace {

            std::pair<std::string, std::string>
            choose_pbe_params(const std::string& pbe_algo, const std::string& key_algo)
               {
               if(pbe_algo.empty())
                  {
                  // Defaults:
                  if(key_algo == "Curve25519" || key_algo == "McEliece")
                     return std::make_pair("AES-256/GCM", "SHA-512");
                  else // for everything else (RSA, DSA, ECDSA, GOST, ...)
                     return std::make_pair("AES-256/CBC", "SHA-256");
                  }

               scan_name request(pbe_algo);
               if(request.algo_name() != "PBE-PKCS5v20" || request.arg_count() != 2)
                  throw Exception("Unsupported PBE " + pbe_algo);
               return std::make_pair(request.arg(1), request.arg(0));
               }

            }

#endif

/*
* BER encode a PKCS #8 private key, encrypted
*/
            std::vector<uint8_t> ber_encode(const private_key_policy &key, RandomNumberGenerator &rng,
                                            const std::string &pass, std::chrono::milliseconds msec,
                                            const std::string &pbe_algo) {
#if defined(CRYPTO3_HAS_PKCS5_PBES2)
                const auto pbe_params = choose_pbe_params(pbe_algo, key.algo_name());

                const std::pair<algorithm_identifier, std::vector<uint8_t>> pbe_info =
                   pbes2_encrypt_msec(pkcs8::ber_encode(key), pass, msec, nullptr,
                                      pbe_params.first, pbe_params.second, rng);

                return der_encoder()
                      .start_cons(SEQUENCE)
                         .encode(pbe_info.first)
                         .encode(pbe_info.second, OCTET_STRING)
                      .end_cons()
                   .get_contents_unlocked();
#else
                CRYPTO3_UNUSED(key, rng, pass, msec, pbe_algo);
                throw encoding_error("pkcs8::ber_encode cannot encipher because PBES2 was disabled in build");
#endif
            }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
            std::string pem_encode(const private_key_policy &key, RandomNumberGenerator &rng, const std::string &pass,
                                   std::chrono::milliseconds msec, const std::string &pbe_algo) {
                if (pass.empty()) {
                    return pem_encode(key);
                }

                return pem_code::encode(pkcs8::ber_encode(key, rng, pass, msec, pbe_algo), "ENCRYPTED PRIVATE KEY");
            }

/*
* BER encode a PKCS #8 private key, encrypted
*/
            std::vector<uint8_t> ber_encode_encrypted_pbkdf_iter(const private_key_policy &key,
                                                                 RandomNumberGenerator &rng, const std::string &pass,
                                                                 size_t pbkdf_iterations, const std::string &cipher,
                                                                 const std::string &pbkdf_hash) {
#if defined(CRYPTO3_HAS_PKCS5_PBES2)
                const std::pair<algorithm_identifier, std::vector<uint8_t>> pbe_info =
                   pbes2_encrypt_iter(key.private_key_info(),
                                      pass, pbkdf_iterations,
                                      cipher.empty() ? "AES-256/CBC" : cipher,
                                      pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                                      rng);

                return der_encoder()
                      .start_cons(SEQUENCE)
                         .encode(pbe_info.first)
                         .encode(pbe_info.second, OCTET_STRING)
                      .end_cons()
                   .get_contents_unlocked();
#else
                CRYPTO3_UNUSED(key, rng, pass, pbkdf_iterations, cipher, pbkdf_hash);
                throw encoding_error(
                        "pkcs8::ber_encode_encrypted_pbkdf_iter cannot encipher because PBES2 disabled in build");
#endif
            }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
            std::string pem_encode_encrypted_pbkdf_iter(const private_key_policy &key, RandomNumberGenerator &rng,
                                                        const std::string &pass, size_t pbkdf_iterations,
                                                        const std::string &cipher, const std::string &pbkdf_hash) {
                return pem_code::encode(
                        pkcs8::ber_encode_encrypted_pbkdf_iter(key, rng, pass, pbkdf_iterations, cipher, pbkdf_hash),
                        "ENCRYPTED PRIVATE KEY");
            }

/*
* BER encode a PKCS #8 private key, encrypted
*/
            std::vector<uint8_t> ber_encode_encrypted_pbkdf_msec(const private_key_policy &key,
                                                                 RandomNumberGenerator &rng, const std::string &pass,
                                                                 std::chrono::milliseconds pbkdf_msec,
                                                                 size_t *pbkdf_iterations, const std::string &cipher,
                                                                 const std::string &pbkdf_hash) {
#if defined(CRYPTO3_HAS_PKCS5_PBES2)
                const std::pair<algorithm_identifier, std::vector<uint8_t>> pbe_info =
                   pbes2_encrypt_msec(key.private_key_info(), pass,
                                      pbkdf_msec, pbkdf_iterations,
                                      cipher.empty() ? "AES-256/CBC" : cipher,
                                      pbkdf_hash.empty() ? "SHA-256" : pbkdf_hash,
                                      rng);

                return der_encoder()
                      .start_cons(SEQUENCE)
                         .encode(pbe_info.first)
                         .encode(pbe_info.second, OCTET_STRING)
                      .end_cons()
                   .get_contents_unlocked();
#else
                CRYPTO3_UNUSED(key, rng, pass, pbkdf_msec, pbkdf_iterations, cipher, pbkdf_hash);
                throw encoding_error("ber_encode_encrypted_pbkdf_msec cannot encipher because PBES2 disabled in build");
#endif
            }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
            std::string pem_encode_encrypted_pbkdf_msec(const private_key_policy &key, RandomNumberGenerator &rng,
                                                        const std::string &pass, std::chrono::milliseconds pbkdf_msec,
                                                        size_t *pbkdf_iterations, const std::string &cipher,
                                                        const std::string &pbkdf_hash) {
                return pem_code::encode(
                        pkcs8::ber_encode_encrypted_pbkdf_msec(key, rng, pass, pbkdf_msec, pbkdf_iterations, cipher,
                                                               pbkdf_hash), "ENCRYPTED PRIVATE KEY");
            }

            namespace {

/*
* Extract a private key (encrypted/unencrypted) and return it
*/
                std::unique_ptr<private_key_policy> load_key(data_source &source, std::function<std::string()> get_pass,
                                                      bool is_encrypted) {
                    algorithm_identifier alg_id;
                    secure_vector <uint8_t> pkcs8_key = PKCS8_decode(source, get_pass, alg_id, is_encrypted);

                    const std::string alg_name = oids::lookup(alg_id.get_oid());
                    if (alg_name.empty() || alg_name == alg_id.get_oid().as_string()) {
                        throw PKCS8_Exception("Unknown algorithm oid_t: " + alg_id.get_oid().as_string());
                    }

                    return load_private_key(alg_id, pkcs8_key);
                }

            }

/*
* Extract an encrypted private key and return it
*/
            std::unique_ptr<private_key_policy> load_key(data_source &source, std::function<std::string()> get_pass) {
                return load_key(source, get_pass, true);
            }

/*
* Extract an encrypted private key and return it
*/
            std::unique_ptr<private_key_policy> load_key(data_source &source, const std::string &pass) {
                return load_key(source, [pass]() {
                    return pass;
                }, true);
            }

/*
* Extract an unencrypted private key and return it
*/
            std::unique_ptr<private_key_policy> load_key(data_source &source) {
                auto fail_fn = []() -> std::string {
                    throw PKCS8_Exception("Internal error: Attempt to read password for unencrypted key");
                };

                return load_key(source, fail_fn, false);
            }

/*
* Make a copy of this private key
*/
            std::unique_ptr<private_key_policy> copy_key(const private_key_policy &key) {
                data_source_memory source(pem_encode(key));
                return pkcs8::load_key(source);
            }

/*
* Extract an encrypted private key and return it
*/
            private_key_policy *load_key(data_source &source, RandomNumberGenerator &rng,
                                  std::function<std::string()> get_pass) {
                CRYPTO3_UNUSED(rng);
                return pkcs8::load_key(source, get_pass).release();
            }

/*
* Extract an encrypted private key and return it
*/
            private_key_policy *load_key(data_source &source, RandomNumberGenerator &rng, const std::string &pass) {
                CRYPTO3_UNUSED(rng);
                return pkcs8::load_key(source, pass).release();
            }

/*
* Extract an unencrypted private key and return it
*/
            private_key_policy *load_key(data_source &source, RandomNumberGenerator &rng) {
                CRYPTO3_UNUSED(rng);
                return pkcs8::load_key(source).release();
            }

#if defined(CRYPTO3_TARGET_OS_HAS_FILESYSTEM)

            /*
            * Extract an encrypted private key and return it
            */
            private_key_policy* load_key(const std::string& fsname,
                                  random_number_generator& rng,
                                  std::function<std::string ()> get_pass)
               {
               CRYPTO3_UNUSED(rng);
               data_source_stream in(fsname);
               return pkcs8::load_key(in, get_pass).release();
               }

            /*
            * Extract an encrypted private key and return it
            */
            private_key_policy* load_key(const std::string& fsname,
                                  random_number_generator& rng,
                                  const std::string& pass)
               {
               CRYPTO3_UNUSED(rng);
               data_source_stream in(fsname);
               return pkcs8::load_key(in, [pass]() { return pass; }).release();
               }

            /*
            * Extract an unencrypted private key and return it
            */
            private_key_policy* load_key(const std::string& fsname,
                                  random_number_generator& rng)
               {
               CRYPTO3_UNUSED(rng);
               data_source_stream in(fsname);
               return pkcs8::load_key(in).release();
               }
#endif

/*
* Make a copy of this private key
*/
            private_key_policy *copy_key(const private_key_policy &key, RandomNumberGenerator &rng) {
                CRYPTO3_UNUSED(rng);
                return pkcs8::copy_key(key).release();
            }
        }
    }
}