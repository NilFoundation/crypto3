//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_PK_KEYS_HPP
#define CRYPTO3_PUBKEY_PK_KEYS_HPP

#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/asn1/asn1_oid.hpp>
#include <nil/crypto3/asn1/alg_id.hpp>

namespace nil {
    namespace crypto3 {
        /**
         * Public Key Base Class.
         */
        class public_key_policy {
        public:
            public_key_policy() = default;

            public_key_policy(const public_key_policy &other) = default;

            public_key_policy &operator=(const public_key_policy &other) = default;

            virtual ~public_key_policy() = default;

            /**
             * Get the name of the underlying public key scheme.
             * @return name of the public key scheme
             */
            virtual std::string algo_name() const = 0;

            /**
             * Return the estimated strength of the underlying key against
             * the best currently known attack. Note that this ignores anything
             * but pure attacks against the key itself and do not take into
             * account padding schemes, usage mistakes, etc which might reduce
             * the strength. However it does suffice to provide an upper bound.
             *
             * @return estimated strength in bits
             */
            virtual size_t estimated_strength() const = 0;

            /**
             * Return an integer value best approximating the length of the
             * primary security parameter. For example for RSA this will be
             * the size of the modulus, for ECDSA the size of the ECC group,
             * and for McEliece the size of the code will be returned.
             */
            virtual size_t key_length() const = 0;

            /**
             * Test the key values for consistency.
             * @param rng rng to use
             * @param strong whether to perform strong and lengthy version
             * of the test
             * @return true if the test is passed
             */
            virtual bool check_key(random_number_generator &rng, bool strong) const = 0;

            /**
             * @return X.509 algorithm_identifier for this key
             */
            virtual algorithm_identifier get_algorithm_identifier() const = 0;

            /**
             * @return BER encoded public key bits
             */
            virtual std::vector<uint8_t> public_key_bits() const = 0;

            /**
             * @return X.509 subject key encoding for this key object
             */
            std::vector<uint8_t> subject_public_key() const;

            /**
             * @return Hash of the subject public key
             */
            std::string fingerprint_public(const std::string &alg = "SHA-256") const;

            // Internal or non-public declarations follow

            /**
             * Returns more than 1 if the output of this algorithm
             * (ciphertext, signature) should be treated as more than one
             * value. This is used for algorithms like DSA and ECDSA, where
             * the (r,s) output pair can be encoded as either a plain binary
             * list or a TLV tagged DER encoding depending on the protocol.
             *
             * This function is public but applications should have few
             * reasons to ever call this.
             *
             * @return number of message parts
             */
            virtual size_t message_parts() const {
                return 1;
            }

            /**
             * Returns how large each of the message parts refered to
             * by message_parts() is
             *
             * This function is public but applications should have few
             * reasons to ever call this.
             *
             * @return size of the message parts in bits
             */
            virtual size_t message_part_size() const {
                return 0;
            }

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return an encryption operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::encryption> create_encryption_op(random_number_generator &rng,
                                                                                    const std::string &params,
                                                                                    const std::string &provider) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return a KEM encryption operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::kem_encryption>
                create_kem_encryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return a verification operation for this key/params or throw
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::verification>
                create_verification_op(const std::string &params, const std::string &provider) const;
        };

        /**
         * Private Key Base Class
         */
        class private_key_policy : public virtual public_key_policy {
        public:
            private_key_policy() = default;

            private_key_policy(const private_key_policy &other) = default;

            private_key_policy &operator=(const private_key_policy &other) = default;

            virtual ~private_key_policy() = default;

            /**
             * @return BER encoded private key bits
             */
            virtual secure_vector<uint8_t> private_key_bits() const = 0;

            /**
             * @return PKCS #8 private key encoding for this key object
             */
            secure_vector<uint8_t> private_key_info() const;

            /**
             * @return PKCS #8 algorithm_identifier for this key
             * Might be different from the X.509 identifier, but normally is not
             */
            virtual algorithm_identifier pkcs8_algorithm_identifier() const {
                return get_algorithm_identifier();
            }

            // Internal or non-public declarations follow

            /**
             * @return Hash of the PKCS #8 encoding for this key object
             */
            std::string fingerprint_private(const std::string &alg) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return an decryption operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             *
             */
            virtual std::unique_ptr<pk_operations::decryption> create_decryption_op(random_number_generator &rng,
                                                                                    const std::string &params,
                                                                                    const std::string &provider) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return a KEM decryption operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::kem_decryption>
                create_kem_decryption_op(random_number_generator &rng,
                                         const std::string &params,
                                         const std::string &provider) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return a signature operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::signature> create_signature_op(random_number_generator &rng,
                                                                                  const std::string &params,
                                                                                  const std::string &provider) const;

            /**
             * This is an internal library function exposed on key types.
             * In almost all cases applications should use wrappers in pubkey.h
             *
             * Return a key agreement operation for this key/params or throw
             *
             * @param rng a random number generator. The PK_Op may maintain a
             * reference to the RNG and use it many times. The rng must outlive
             * any operations which reference it.
             * @param params additional parameters
             * @param provider the provider to use
             */
            virtual std::unique_ptr<pk_operations::key_agreement>
                create_key_agreement_op(random_number_generator &rng,
                                        const std::string &params,
                                        const std::string &provider) const;
        };

        /**
         * PK Secret Value Derivation Key
         */
        class pk_key_agreement_key : public virtual private_key_policy {
        public:
            /*
             * @return public component of this key
             */
            virtual std::vector<uint8_t> public_value() const = 0;

            pk_key_agreement_key() = default;

            pk_key_agreement_key(const pk_key_agreement_key &) = default;

            pk_key_agreement_key &operator=(const pk_key_agreement_key &) = default;

            virtual ~pk_key_agreement_key() = default;
        };

        std::string create_hex_fingerprint(const uint8_t bits[], size_t len, const std::string &hash_name);

        template<typename Alloc>
        std::string create_hex_fingerprint(const std::vector<uint8_t, Alloc> &vec, const std::string &hash_name) {
            return create_hex_fingerprint(vec.data(), vec.size(), hash_name);
        }

        std::string create_hex_fingerprint(const uint8_t bits[], size_t bits_len, const std::string &hash_name) {
            std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_name));
            const std::string hex_hash = encode<codec::hex<>>(hash_fn->process(bits, bits_len));

            std::string fprint;

            for (size_t i = 0; i != hex_hash.size(); i += 2) {
                if (i != 0) {
                    fprint.push_back(':');
                }

                fprint.push_back(hex_hash[i]);
                fprint.push_back(hex_hash[i + 1]);
            }

            return fprint;
        }

        std::vector<uint8_t> public_key_policy::subject_public_key() const {
            return der_encoder()
                .start_cons(SEQUENCE)
                .encode(get_algorithm_identifier())
                .encode(public_key_bits(), BIT_STRING)
                .end_cons()
                .get_contents_unlocked();
        }

        secure_vector<uint8_t> private_key_policy::private_key_info() const {
            const size_t PKCS8_VERSION = 0;

            return der_encoder()
                .start_cons(SEQUENCE)
                .encode(PKCS8_VERSION)
                .encode(pkcs8_algorithm_identifier())
                .encode(private_key_bits(), OCTET_STRING)
                .end_cons()
                .get_contents();
        }

        /*
         * Hash of the X.509 subjectPublicKey encoding
         */
        std::string public_key_policy::fingerprint_public(const std::string &hash_algo) const {
            return create_hex_fingerprint(subject_public_key(), hash_algo);
        }

        /*
         * Hash of the PKCS #8 encoding for this key object
         */
        std::string private_key_policy::fingerprint_private(const std::string &hash_algo) const {
            return create_hex_fingerprint(private_key_bits(), hash_algo);
        }

        std::unique_ptr<pk_operations::encryption>
            public_key_policy::create_encryption_op(random_number_generator & /*random*/,
                                                    const std::string & /*params*/,
                                                    const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support encryption");
        }

        std::unique_ptr<pk_operations::kem_encryption>
            public_key_policy::create_kem_encryption_op(random_number_generator & /*random*/,
                                                        const std::string & /*params*/,
                                                        const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support KEM encryption");
        }

        std::unique_ptr<pk_operations::verification>
            public_key_policy::create_verification_op(const std::string & /*params*/,
                                                      const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support verification");
        }

        std::unique_ptr<pk_operations::decryption>
            private_key_policy::create_decryption_op(random_number_generator & /*random*/,
                                                     const std::string & /*params*/,
                                                     const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support decryption");
        }

        std::unique_ptr<pk_operations::kem_decryption>
            private_key_policy::create_kem_decryption_op(random_number_generator & /*random*/,
                                                         const std::string & /*params*/,
                                                         const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support KEM decryption");
        }

        std::unique_ptr<pk_operations::signature>
            private_key_policy::create_signature_op(random_number_generator & /*random*/,
                                                    const std::string & /*params*/,
                                                    const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support signatures");
        }

        std::unique_ptr<pk_operations::key_agreement>
            private_key_policy::create_key_agreement_op(random_number_generator & /*random*/,
                                                        const std::string & /*params*/,
                                                        const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support key agreement");
        }
    }    // namespace crypto3
}    // namespace nil

#endif
