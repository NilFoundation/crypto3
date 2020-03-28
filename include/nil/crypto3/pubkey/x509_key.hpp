#ifndef CRYPTO3_PUBKEY_X509_PUBLIC_KEY_HPP
#define CRYPTO3_PUBKEY_X509_PUBLIC_KEY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/utilities/types.hpp>

#include <string>
#include <vector>

namespace nil {
    namespace crypto3 {

        class random_number_generator;

        class data_source;

        /**
         * The two types of X509 encoding supported by Botan.
         * This enum is not used anymore, and will be removed in a future major release.
         */
        enum x509_encoding { RAW_BER, PEM };

        /**
         * This namespace contains functions for handling X.509 public keys
         */
        namespace x509 {

            /**
             * BER encode a key
             * @param key the public key to encode
             * @return BER encoding of this key
             */

            std::vector<uint8_t> ber_encode(const public_key_policy &key);

            /**
             * PEM encode a public key into a string.
             * @param key the key to encode
             * @return PEM encoded key
             */

            std::string pem_encode(const public_key_policy &key);

            /**
             * Create a public key from a data source.
             * @param source the source providing the DER or PEM encoded key
             * @return new public key object
             */

            public_key_policy *load_key(data_source &source);

#if defined(CRYPTO3_TARGET_OS_HAS_FILESYSTEM)
            /**
             * Create a public key from a file
             * @param filename pathname to the file to load
             * @return new public key object
             */
            public_key_policy *load_key(const std::string &filename);
#endif

            /**
             * Create a public key from a memory region.
             * @param enc the memory region containing the DER or PEM encoded key
             * @return new public key object
             */

            public_key_policy *load_key(const std::vector<uint8_t> &enc);

            /**
             * Copy a key.
             * @param key the public key to copy
             * @return new public key object
             */

            public_key_policy *copy_key(const public_key_policy &key);

        }    // namespace x509

        namespace x509 {

            std::vector<uint8_t> ber_encode(const public_key_policy &key) {
                // keeping it around for compat
                return key.subject_public_key();
            }

            /*
             * PEM encode a X.509 public key
             */
            std::string pem_encode(const public_key_policy &key) {
                return pem_code::encode(key.subject_public_key(), "PUBLIC KEY");
            }

            /*
             * Extract a public key and return it
             */
            public_key_policy *load_key(data_source &source) {
                try {
                    algorithm_identifier alg_id;
                    std::vector<uint8_t> key_bits;

                    if (asn1::maybe_BER(source) && !pem_code::matches(source)) {
                        ber_decoder(source).start_cons(SEQUENCE).decode(alg_id).decode(key_bits, BIT_STRING).end_cons();
                    } else {
                        data_source_memory ber(pem_code::decode_check_label(source, "PUBLIC KEY"));

                        ber_decoder(ber).start_cons(SEQUENCE).decode(alg_id).decode(key_bits, BIT_STRING).end_cons();
                    }

                    if (key_bits.empty()) {
                        throw decoding_error("X.509 public key decoding failed");
                    }

                    return load_public_key(alg_id, key_bits).release();
                } catch (decoding_error &e) {
                    throw decoding_error("X.509 public key decoding failed: " + std::string(e.what()));
                }
            }

#if defined(CRYPTO3_TARGET_OS_HAS_FILESYSTEM)
            /*
             * Extract a public key and return it
             */
            public_key_policy *load_key(const std::string &fsname) {
                data_source_stream source(fsname, true);
                return x509::load_key(source);
            }
#endif

            /*
             * Extract a public key and return it
             */
            public_key_policy *load_key(const std::vector<uint8_t> &mem) {
                data_source_memory source(mem);
                return x509::load_key(source);
            }

            /*
             * Make a copy of this public key
             */
            public_key_policy *copy_key(const public_key_policy &key) {
                data_source_memory source(pem_encode(key));
                return x509::load_key(source);
            }

        }    // namespace x509
    }        // namespace crypto3
}    // namespace nil

#endif
