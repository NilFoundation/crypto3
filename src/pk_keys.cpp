#include <nil/crypto3/pubkey/pk_keys.hpp>

#include <nil/crypto3/asn1/oids.hpp>
#include <nil/crypto3/asn1/ber_dec.hpp>
#include <nil/crypto3/asn1/der_enc.hpp>

#include <nil/crypto3/codec/hex.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

namespace nil {
    namespace crypto3 {

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
            return der_encoder().start_cons(SEQUENCE).encode(get_algorithm_identifier()).encode(public_key_bits(),
                                                                                                BIT_STRING).end_cons().get_contents_unlocked();
        }

        secure_vector<uint8_t> private_key_policy::private_key_info() const {
            const size_t PKCS8_VERSION = 0;

            return der_encoder().start_cons(SEQUENCE).encode(PKCS8_VERSION).encode(pkcs8_algorithm_identifier()).encode(
                    private_key_bits(), OCTET_STRING).end_cons().get_contents();
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

        std::unique_ptr<pk_operations::encryption> public_key_policy::create_encryption_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support encryption");
        }

        std::unique_ptr<pk_operations::kem_encryption> public_key_policy::create_kem_encryption_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support KEM encryption");
        }

        std::unique_ptr<pk_operations::verification> public_key_policy::create_verification_op(
                const std::string & /*params*/, const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support verification");
        }

        std::unique_ptr<pk_operations::decryption> private_key_policy::create_decryption_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support decryption");
        }

        std::unique_ptr<pk_operations::kem_decryption> private_key_policy::create_kem_decryption_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support KEM decryption");
        }

        std::unique_ptr<pk_operations::signature> private_key_policy::create_signature_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support signatures");
        }

        std::unique_ptr<pk_operations::key_agreement> private_key_policy::create_key_agreement_op(
                random_number_generator & /*random*/, const std::string & /*params*/,
                const std::string & /*provider*/) const {
            throw lookup_error(algo_name() + " does not support key agreement");
        }
    }
}
