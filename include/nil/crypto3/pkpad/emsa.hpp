#ifndef CRYPTO3_PUBKEY_EMSA_HPP
#define CRYPTO3_PUBKEY_EMSA_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/asn1/alg_id.hpp>

namespace nil {
    namespace crypto3 {

        class private_key_policy;

        class random_number_generator;

        template<typename Hash>
        class emsa {
        public:
            typedef Hash hash_type;

            virtual ~emsa() = default;

            emsa(Hash &input_hash) : hash(input_hash) {
            }

        protected:
            Hash &hash;
        };

        /**
         * EMSA, from IEEE 1363s Encoding Method for Signatures, Appendix
         *
         * Any way of encoding/padding signatures
         */
        class emsa {
        public:
            virtual ~emsa() = default;

            /**
             * Add more data to the signature computation
             * @param input some data
             * @param length length of input in bytes
             */
            virtual void update(const uint8_t input[], size_t length) = 0;

            /**
             * @return raw hash
             */
            virtual secure_vector<uint8_t> raw_data() = 0;

            /**
             * Return the encoding of a message
             * @param msg the result of raw_data()
             * @param output_bits the desired output bit size
             * @param rng a random number generator
             * @return encoded signature
             */
            virtual secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &msg, size_t output_bits,
                                                       random_number_generator &rng) = 0;

            /**
             * Verify the encoding
             * @param coded the received (coded) message representative
             * @param raw the computed (local, uncoded) message representative
             * @param key_bits the size of the key in bits
             * @return true if coded is a valid encoding of raw, otherwise false
             */
            virtual bool verify(const secure_vector<uint8_t> &coded, const secure_vector<uint8_t> &raw,
                                size_t key_bits) = 0;

            /**
             * Prepare sig_algo for use in choose_sig_format for x509 certs
             *
             * @param key used for checking compatibility with the encoding scheme
             * @param cert_hash_name is checked to equal the hash for the encoding
             * @return algorithm identifier to signatures created using this key,
             *         padding method and hash.
             */
            virtual algorithm_identifier config_for_x509(const private_key_policy &key,
                                                         const std::string &cert_hash_name) const;

            /**
             * @return a new object representing the same encoding method as *this
             */
            virtual emsa *clone() = 0;

            /**
             * @return the SCAN name of the encoding/padding scheme
             */
            virtual std::string name() const = 0;
        };

        /**
         * Factory method for EMSA (message-encoding methods for signatures
         * with appendix) objects
         * @param algo_spec the name of the EMSA to create
         * @return pointer to newly allocated object of that type
         */

        emsa *get_emsa(const std::string &algo_spec);

        /**
         * Returns the hash function used in the given EMSA scheme
         * If the hash function is not specified or not understood,
         * returns "SHA-512"
         * @param algo_spec the name of the EMSA
         * @return hash function used in the given EMSA scheme
         */

        std::string hash_for_emsa(const std::string &algo_spec);

        algorithm_identifier emsa::config_for_x509(const private_key_policy &, const std::string &) const {
            throw Not_Implemented("Encoding " + name() + " not supported for signing x509 objects");
        }

        emsa *get_emsa(const std::string &algo_spec) {
            scan_name req(algo_spec);

#if defined(CRYPTO3_HAS_EMSA1)
            if (req.algo_name() == "EMSA1" && req.arg_count() == 1) {
                if (auto hash = HashFunction::create(req.arg(0)))
                    return new EMSA1(hash.release());
            }
#endif

#if defined(CRYPTO3_HAS_EMSA_PKCS1)
            if (req.algo_name() == "EMSA_PKCS1" || req.algo_name() == "emsa-PKCS1-v1_5" || req.algo_name() == "EMSA3") {
                if (req.arg_count() == 2 && req.arg(0) == "Raw") {
                    return new EMSA_PKCS1v15_Raw(req.arg(1));
                } else if (req.arg_count() == 1) {
                    if (req.arg(0) == "Raw") {
                        return new EMSA_PKCS1v15_Raw;
                    } else {
                        if (auto hash = HashFunction::create(req.arg(0))) {
                            return new EMSA_PKCS1v15(hash.release());
                        }
                    }
                }
            }
#endif

#if defined(CRYPTO3_HAS_EMSA_PSSR)
            if (req.algo_name() == "PSSR" || req.algo_name() == "emsa-PSS" || req.algo_name() == "PSS-MGF1" ||
                req.algo_name() == "EMSA4" || req.algo_name() == "PSSR_Raw") {
                if (req.arg_count_between(1, 3)) {
                    if (req.arg(1, "MGF1") != "MGF1")
                        return nullptr;    // not supported

                    if (auto h = HashFunction::create(req.arg(0))) {
                        const size_t salt_size = req.arg_as_integer(2, h->output_length());

                        if (req.algo_name() == "PSSR_Raw")
                            return new PSSR_Raw(h.release(), salt_size);
                        else
                            return new PSSR(h.release(), salt_size);
                    }
                }
            }
#endif

#if defined(CRYPTO3_HAS_ISO_9796)
            if (req.algo_name() == "ISO_9796_DS2") {
                if (req.arg_count_between(1, 3)) {
                    if (auto h = HashFunction::create(req.arg(0))) {
                        const size_t salt_size = req.arg_as_integer(2, h->output_length());
                        const bool implicit = req.arg(1, "exp") == "imp";
                        return new ISO_9796_DS2(h.release(), implicit, salt_size);
                    }
                }
            }
            // ISO-9796-2 DS 3 is deterministic and DS2 without a salt
            if (req.algo_name() == "ISO_9796_DS3") {
                if (req.arg_count_between(1, 2)) {
                    if (auto h = HashFunction::create(req.arg(0))) {
                        const bool implicit = req.arg(1, "exp") == "imp";
                        return new ISO_9796_DS3(h.release(), implicit);
                    }
                }
            }
#endif

#if defined(CRYPTO3_HAS_EMSA_X931)
            if (req.algo_name() == "EMSA_X931" || req.algo_name() == "EMSA2" || req.algo_name() == "X9.31") {
                if (req.arg_count() == 1) {
                    if (auto hash = HashFunction::create(req.arg(0))) {
                        return new EMSA_X931(hash.release());
                    }
                }
            }
#endif

#if defined(CRYPTO3_HAS_EMSA_RAW)
            if (req.algo_name() == "Raw") {
                if (req.arg_count() == 0) {
                    return new EMSA_Raw;
                } else {
                    auto hash = HashFunction::create(req.arg(0));
                    if (hash)
                        return new EMSA_Raw(hash->output_length());
                }
            }
#endif

            throw algorithm_not_found(algo_spec);
        }

        std::string hash_for_emsa(const std::string &algo_spec) {
            scan_name emsa_name(algo_spec);

            if (emsa_name.arg_count() > 0) {
                const std::string pos_hash = emsa_name.arg(0);
                return pos_hash;
            }

            return "SHA-512";    // safe default if nothing we understand
        }
    }    // namespace crypto3
}    // namespace nil

#endif
