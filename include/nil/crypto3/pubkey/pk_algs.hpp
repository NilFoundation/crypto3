#ifndef CRYPTO3_PUBKEY_PK_KEY_FACTORY_HPP
#define CRYPTO3_PUBKEY_PK_KEY_FACTORY_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/asn1/alg_id.hpp>

#include <memory>

namespace nil {
    namespace crypto3 {

        std::unique_ptr<public_key_policy> load_public_key(const algorithm_identifier &alg_id,
                                                           const std::vector<uint8_t> &key_bits);

        std::unique_ptr<private_key_policy> load_private_key(const algorithm_identifier &alg_id,
                                                             const secure_vector<uint8_t> &key_bits);

        /**
         * Create a new key
         * For ECC keys, algo_params specifies EC group (eg, "secp256r1")
         * For DH/DSA/ElGamal keys, algo_params is DL group (eg, "modp/ietf/2048")
         * For RSA, algo_params is integer keylength
         * For McEliece, algo_params is n,t
         * If algo_params is left empty, suitable default parameters are chosen.
         */

        std::unique_ptr<private_key_policy> create_private_key(const std::string &algo_name,
                                                               random_number_generator &rng,
                                                               const std::string &algo_params = "",
                                                               const std::string &provider = "");

        std::vector<std::string> probe_provider_private_key(const std::string &algo_name,
                                                            const std::vector<std::string> &possible);

        std::unique_ptr<public_key_policy> load_public_key(const algorithm_identifier &alg_id,
                                                           const std::vector<uint8_t> &key_bits) {
            const std::vector<std::string> alg_info = split_on(oids::lookup(alg_id.get_oid()), '/');

            if (alg_info.empty()) {
                throw decoding_error("Unknown algorithm oid_t: " + alg_id.get_oid().as_string());
            }

            const std::string alg_name = alg_info[0];

#if defined(CRYPTO3_HAS_RSA)
            if (alg_name == "RSA") {
                return std::unique_ptr<public_key_policy>(new rsa_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_CURVE_25519)
            if (alg_name == "Curve25519") {
                return std::unique_ptr<public_key_policy>(new Curve25519_PublicKey(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_MCELIECE)
            if (alg_name == "McEliece") {
                return std::unique_ptr<public_key_policy>(new McEliece_PublicKey(key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECDSA)
            if (alg_name == "ECDSA") {
                return std::unique_ptr<public_key_policy>(new ecdsa_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECDH)
            if (alg_name == "ECDH") {
                return std::unique_ptr<public_key_policy>(new ECDH_PublicKey(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_DIFFIE_HELLMAN)
            if (alg_name == "DH") {
                return std::unique_ptr<public_key_policy>(new DH_PublicKey(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_DSA)
            if (alg_name == "DSA") {
                return std::unique_ptr<public_key_policy>(new dsa_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ELGAMAL)
            if (alg_name == "ElGamal") {
                return std::unique_ptr<public_key_policy>(new el_gamal_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECGDSA)
            if (alg_name == "ECGDSA") {
                return std::unique_ptr<public_key_policy>(new ecgdsa_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECKCDSA)
            if (alg_name == "ECKCDSA")
                return std::unique_ptr<public_key_policy>(new ECKCdsa_public_key(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_ED25519)
            if (alg_name == "Ed25519")
                return std::unique_ptr<public_key_policy>(new Ed25519_PublicKey(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_GOST_34_10_2001)
            if (alg_name == "GOST-34.10") {
                return std::unique_ptr<public_key_policy>(new gost_3410_public_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_SM2)
            if (alg_name == "SM2_Sig")
                return std::unique_ptr<public_key_policy>(new sm2_signature_public_key(alg_id, key_bits));
            if (alg_name == "SM2_Enc")
                return std::unique_ptr<public_key_policy>(new sm2_encryption_public_key(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_XMSS)
            if (alg_name == "XMSS")
                return std::unique_ptr<public_key_policy>(new XMSS_PublicKey(key_bits));
#endif

            throw decoding_error("Unhandled PK algorithm " + alg_name);
        }

        std::unique_ptr<private_key_policy> load_private_key(const algorithm_identifier &alg_id,
                                                             const secure_vector<uint8_t> &key_bits) {
            const std::string alg_name = oids::lookup(alg_id.get_oid());
            if (alg_name == "") {
                throw decoding_error("Unknown algorithm oid_t: " + alg_id.get_oid().as_string());
            }

#if defined(CRYPTO3_HAS_RSA)
            if (alg_name == "RSA") {
                return std::unique_ptr<private_key_policy>(new rsa_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_CURVE_25519)
            if (alg_name == "Curve25519") {
                return std::unique_ptr<private_key_policy>(new Curve25519_PrivateKey(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECDSA)
            if (alg_name == "ECDSA") {
                return std::unique_ptr<private_key_policy>(new ecdsa_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECDH)
            if (alg_name == "ECDH") {
                return std::unique_ptr<private_key_policy>(new ecdh_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_DIFFIE_HELLMAN)
            if (alg_name == "DH") {
                return std::unique_ptr<private_key_policy>(new DH_PrivateKey(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_DSA)
            if (alg_name == "DSA") {
                return std::unique_ptr<private_key_policy>(new dsa_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_MCELIECE)
            if (alg_name == "McEliece") {
                return std::unique_ptr<private_key_policy>(new mceliece_private_key(key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECGDSA)
            if (alg_name == "ECGDSA") {
                return std::unique_ptr<private_key_policy>(new ecgdsa_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_ECKCDSA)
            if (alg_name == "ECKCDSA")
                return std::unique_ptr<private_key_policy>(new eckcdsa_private_key(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_ED25519)
            if (alg_name == "Ed25519")
                return std::unique_ptr<private_key_policy>(new Ed25519_PrivateKey(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_GOST_34_10_2001)
            if (alg_name == "GOST-34.10") {
                return std::unique_ptr<private_key_policy>(new gost_3410_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_SM2)
            if (alg_name == "SM2_Sig")
                return std::unique_ptr<private_key_policy>(new sm2_signature_private_key(alg_id, key_bits));
            if (alg_name == "SM2_Enc")
                return std::unique_ptr<private_key_policy>(new sm2_encryption_private_key(alg_id, key_bits));
#endif

#if defined(CRYPTO3_HAS_ELGAMAL)
            if (alg_name == "ElGamal") {
                return std::unique_ptr<private_key_policy>(new el_gamal_private_key(alg_id, key_bits));
            }
#endif

#if defined(CRYPTO3_HAS_XMSS)
            if (alg_name == "XMSS")
                return std::unique_ptr<private_key_policy>(new XMSS_PrivateKey(key_bits));
#endif

            throw decoding_error("Unhandled PK algorithm " + alg_name);
        }

#if defined(CRYPTO3_HAS_ECC_GROUP)

        namespace {

            std::string default_ec_group_for(const std::string &alg_name) {
                if (alg_name == "SM2_Enc" || alg_name == "SM2_Sig")
                    return "sm2p256v1";
                if (alg_name == "GOST-34.10")
                    return "gost_256A";
                if (alg_name == "ECGDSA")
                    return "brainpool256r1";
                return "secp256r1";
            }

        }    // namespace

#endif

        std::unique_ptr<private_key_policy> create_private_key(const std::string &alg_name,
                                                               random_number_generator &rng, const std::string &params,
                                                               const std::string &provider) {
            /*
             * Default paramaters are chosen for work factor > 2**128 where possible
             */

#if defined(CRYPTO3_HAS_CURVE_25519)
            if (alg_name == "Curve25519") {
                return std::unique_ptr<private_key_policy>(new Curve25519_PrivateKey(rng));
            }
#endif

#if defined(CRYPTO3_HAS_RSA)
            if (alg_name == "RSA") {
                const size_t rsa_bits = (params.empty() ? 3072 : to_u32bit(params));
#if defined(CRYPTO3_HAS_OPENSSL)
                if (provider.empty() || provider == "openssl") {
                    std::unique_ptr<nil::crypto3::private_key_policy> pk;
                    if ((pk = make_openssl_rsa_private_key(rng, rsa_bits)))
                        return pk;

                    if (!provider.empty())
                        return nullptr;
                }
#endif
                return std::unique_ptr<private_key_policy>(new rsa_private_key(rng, rsa_bits));
            }
#endif

#if defined(CRYPTO3_HAS_MCELIECE)
            if (alg_name == "McEliece") {
                std::vector<std::string> mce_param = nil::crypto3::split_on(params.empty() ? "2960,57" : params, ',');

                if (mce_param.size() != 2) {
                    throw std::invalid_argument("create_private_key bad McEliece parameters " + params);
                }

                size_t mce_n = nil::crypto3::to_u32bit(mce_param[0]);
                size_t mce_t = nil::crypto3::to_u32bit(mce_param[1]);

                return std::unique_ptr<nil::crypto3::private_key_policy>(
                    new nil::crypto3::mceliece_private_key(rng, mce_n, mce_t));
            }
#endif

#if defined(CRYPTO3_HAS_XMSS)
            if (alg_name == "XMSS") {
                return std::unique_ptr<private_key_policy>(new XMSS_PrivateKey(
                    XMSS_Parameters(params.empty() ? "XMSS_SHA2-512_W16_H10" : params).oid_t(), rng));
            }
#endif

#if defined(CRYPTO3_HAS_ED25519)
            if (alg_name == "Ed25519") {
                return std::unique_ptr<private_key_policy>(new Ed25519_PrivateKey(rng));
            }
#endif

            // ECC crypto3
#if defined(CRYPTO3_HAS_ECC_PUBLIC_KEY_CRYPTO)

            if (alg_name == "ECDSA" || alg_name == "ECDH" || alg_name == "ECKCDSA" || alg_name == "ECGDSA" ||
                alg_name == "SM2_Sig" || alg_name == "SM2_Enc" || alg_name == "GOST-34.10") {
                const ec_group ec_group(params.empty() ? default_ec_group_for(alg_name) : params);

#if defined(CRYPTO3_HAS_ECDSA)
                if (alg_name == "ECDSA")
                    return std::unique_ptr<private_key_policy>(new ecdsa_private_key(rng, ec_group));
#endif

#if defined(CRYPTO3_HAS_ECDH)
                if (alg_name == "ECDH")
                    return std::unique_ptr<private_key_policy>(new ecdh_private_key(rng, ec_group));
#endif

#if defined(CRYPTO3_HAS_ECKCDSA)
                if (alg_name == "ECKCDSA")
                    return std::unique_ptr<private_key_policy>(new eckcdsa_private_key(rng, ec_group));
#endif

#if defined(CRYPTO3_HAS_GOST_34_10_2001)
                if (alg_name == "GOST-34.10")
                    return std::unique_ptr<private_key_policy>(new gost_3410_private_key(rng, ec_group));
#endif

#if defined(CRYPTO3_HAS_SM2)
                if (alg_name == "SM2_Sig")
                    return std::unique_ptr<private_key_policy>(new sm2_signature_private_key(rng, ec_group));
                if (alg_name == "SM2_Enc")
                    return std::unique_ptr<private_key_policy>(new sm2_encryption_private_key(rng, ec_group));
#endif

#if defined(CRYPTO3_HAS_ECGDSA)
                if (alg_name == "ECGDSA")
                    return std::unique_ptr<private_key_policy>(new ecgdsa_private_key(rng, ec_group));
#endif
            }
#endif

            // DL crypto3
#if defined(CRYPTO3_HAS_DL_GROUP)
            if (alg_name == "DH" || alg_name == "DSA" || alg_name == "ElGamal") {
                std::string default_group = (alg_name == "DSA") ? "dsa/botan/2048" : "modp/ietf/2048";
                dl_group modp_group(params.empty() ? default_group : params);

#if defined(CRYPTO3_HAS_DIFFIE_HELLMAN)
                if (alg_name == "DH")
                    return std::unique_ptr<private_key_policy>(new dh_private_key(rng, modp_group));
#endif

#if defined(CRYPTO3_HAS_DSA)
                if (alg_name == "DSA")
                    return std::unique_ptr<private_key_policy>(new dsa_private_key_policy(rng, modp_group));
#endif

#if defined(CRYPTO3_HAS_ELGAMAL)
                if (alg_name == "ElGamal")
                    return std::unique_ptr<private_key_policy>(new el_gamal_private_key(rng, modp_group));
#endif
            }
#endif

            CRYPTO3_UNUSED(alg_name, rng, params, provider);

            return std::unique_ptr<private_key_policy>();
        }

        std::vector<std::string> probe_provider_private_key(const std::string &alg_name,
                                                            const std::vector<std::string> &possible) {
            std::vector<std::string> providers;
            for (auto &&prov : possible) {
                if (prov == "core" ||
#if defined(CRYPTO3_HAS_OPENSSL)
                    (prov == "openssl" && alg_name == "RSA") ||
#endif
                    0) {
                    providers.push_back(prov);    // available
                }
            }

            CRYPTO3_UNUSED(alg_name);

            return providers;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
