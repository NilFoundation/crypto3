#ifndef CRYPTO3_PUBKEY_XMSS_WOTS_PRIVATEKEY_HPP
#define CRYPTO3_PUBKEY_XMSS_WOTS_PRIVATEKEY_HPP

#include <cstddef>
#include <memory>

#include <nil/crypto3/asn1/alg_id.hpp>

#include <nil/crypto3/utilities/exceptions.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/random/random.hpp>

#include <nil/crypto3/pubkey/xmss/xmss_wots_parameters.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_address.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_publickey.hpp>

namespace nil {
    namespace crypto3 {

        /** A Winternitz One Time Signature private key for use with Extended Hash-Based
         * Signatures.
         **/
        class XMSS_WOTS_PrivateKey final : public virtual XMSS_WOTS_PublicKey, public virtual private_key_policy {
        public:
            /**
             * Creates a WOTS private key for the chosen XMSS WOTS signature method.
             * Members need to be initialized manually.
             *
             * @param oid Identifier for the selected signature method.
             **/
            XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters::ots_algorithm_t oid) : XMSS_WOTS_PublicKey(oid) {
            }

            /**
             * Creates a WOTS private key for the chosen XMSS WOTS signature method.
             *
             * @param oid Identifier for the selected signature method.
             * @param rng A random number generator to use for key generation.
             **/
            XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters::ots_algorithm_t oid, RandomNumberGenerator &rng) :
                XMSS_WOTS_PublicKey(oid, rng), m_private_seed(rng.random_vec(m_wots_params.element_size())) {
                set_key_data(generate(m_private_seed));
            }

            /**
             * Constructs a WOTS private key. Chains will be generated on demand
             * applying a hash function to a unique value generated from a secret
             * seed and a counter. The secret seed of length n, will be
             * automatically generated using AutoSeeded_RNG(). "n" equals
             * the element size of the chosen WOTS security parameter set.
             *
             * @param oid Identifier for the selected signature method.
             * @param public_seed A public seed used for the pseudo random generation
             *        of public keys derived from this private key.
             * @param rng A random number generator to use for key generation.
             **/
            XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters::ots_algorithm_t oid, const secure_vector<uint8_t> &public_seed,
                                 RandomNumberGenerator &rng) :
                XMSS_WOTS_PublicKey(oid, public_seed),
                m_private_seed(rng.random_vec(m_wots_params.element_size())) {
                set_key_data(generate(m_private_seed));
            }

            /**
             * Constructs a WOTS private key. Chains will be generated on demand
             * applying a hash function to a unique value generated from a secret
             * seed and a counter. The secret seed of length n, will be
             * automatically generated using AutoSeeded_RNG(). "n" equals
             * the element size of the chosen WOTS security parameter set.
             *
             * @param oid Identifier for the selected signature method.
             * @param public_seed A public seed used for the pseudo random generation
             *        of public keys derived from this private key.
             **/
            XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters::ots_algorithm_t oid, const secure_vector<uint8_t> &public_seed) :
                XMSS_WOTS_PublicKey(oid, public_seed) {
            }

            /**
             * Constructs a WOTS private key. Chains will be generated on demand
             * applying a hash function to a unique value generated from the
             * secret seed and a counter.
             *
             * @param oid Identifier for the selected signature method.
             * @param public_seed A public seed used for the pseudo random generation
             *        of public keys derived from this private key.
             * @param private_seed A secret uniformly random n-byte value.
             **/
            XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters::ots_algorithm_t oid, const secure_vector<uint8_t> &public_seed,
                                 const secure_vector<uint8_t> &private_seed) :
                XMSS_WOTS_PublicKey(oid, public_seed),
                m_private_seed(private_seed) {
                set_key_data(generate(private_seed));
            }

            /**
             * Retrieves the i-th WOTS private key using pseudo random key
             * (re-)generation.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each
             * thread.
             *
             * @param i Index of the key to retrieve.
             * @param hash Instance of XMSS_Hash, that may only be used by the
             *        thead executing at.
             *
             * @return WOTS secret key.
             **/
            wots_keysig_t at(size_t i, XMSS_Hash &hash) {
                secure_vector<uint8_t> idx_bytes;
                XMSS_Tools::concat(idx_bytes, i, m_wots_params.element_size());
                hash.h(idx_bytes, m_private_seed, idx_bytes);
                return generate(idx_bytes, hash);
            }

            /**
             * Retrieves the i-th WOTS private key using pseudo random key
             * (re-)generation.
             *
             * @param i Index of the key to retrieve.
             *
             * @return WOTS secret key.
             **/
            inline wots_keysig_t operator[](size_t i) {
                return this->at(i, m_hash);
            }

            /**
             * Retrieves the i-th WOTS private key using pseudo random key
             * (re-)generation.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each
             * thread.
             *
             * @param adrs The address of the key to retrieve.
             * @param hash Instance of XMSS_Hash, that may only be used by the
             *        thead executing at.
             *
             * @return WOTS secret key.
             **/
            wots_keysig_t at(const XMSS_Address &adrs, XMSS_Hash &hash) {
                secure_vector<uint8_t> result;
                hash.prf(result, m_private_seed, adrs.bytes());
                return generate(result, hash);
            }

            inline wots_keysig_t operator[](const XMSS_Address &adrs) {
                return this->at(adrs, m_hash);
            }

            wots_keysig_t generate_private_key(const secure_vector<uint8_t> &priv_seed);

            /**
             * Algorithm 4: "WOTS_genPK"
             * Generates a Winternitz One Time Signature+ (WOTS+) Public Key from a
             * given private key.
             *
             * @param adrs Hash function address encoding the address of the WOTS+
             *             key pair within a greater structure.
             *
             * @return A XMSS_WOTS_PublicKey.
             **/
            XMSS_WOTS_PublicKey generate_public_key(XMSS_Address &adrs);

            /**
             * Algorithm 4: "WOTS_genPK"
             * Initializes a Winternitz One Time Signature+ (WOTS+) Public Key's
             * key_data() member, with data derived from in_key_data using the
             * WOTS chaining function.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each
             * thread.
             *
             * @param[out] pub_key Public key to initialize key_data() member on.
             * @param in_key_data Input key material from private key used for
             *        public key generation.
             * @param adrs Hash function address encoding the address of
             *        the WOTS+ key pair within a greater structure.
             * @param hash Instance of XMSS_Hash, that may only by the thead
             *        executing generate_public_key.
             **/
            void generate_public_key(XMSS_WOTS_PublicKey &pub_key, wots_keysig_t &&in_key_data, XMSS_Address &adrs,
                                     XMSS_Hash &hash);

            /**
             * Algorithm 4: "WOTS_genPK"
             * Initializes a Winternitz One Time Signature+ (WOTS+) Public Key's
             * key_data() member, with data derived from in_key_data using the
             * WOTS chaining function.
             *
             * @param[out] pub_key Public key to initialize key_data() member on.
             * @param in_key_data Input key material from private key used for
             *        public key generation.
             * @param adrs Hash function address encoding the address of
             *        the WOTS+ key pair within a greater structure.
             **/
            inline void generate_public_key(XMSS_WOTS_PublicKey &pub_key, wots_keysig_t &&in_key_data,
                                            XMSS_Address &adrs) {
                generate_public_key(pub_key, std::forward<wots_keysig_t>(in_key_data), adrs, m_hash);
            }

            /**
             * Algorithm 5: "WOTS_sign"
             * Generates a signature from a private key and a message.
             *
             * @param msg A message to sign.
             * @param adrs An OTS hash address identifying the WOTS+ key pair
             *        used for signing.
             *
             * @return signature for msg.
             **/
            inline wots_keysig_t sign(const secure_vector<uint8_t> &msg, XMSS_Address &adrs) {
                return sign(msg, adrs, m_hash);
            }

            /**
             * Algorithm 5: "WOTS_sign"
             * Generates a signature from a private key and a message.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each
             * thread.
             *
             * @param msg A message to sign.
             * @param adrs An OTS hash address identifying the WOTS+ key pair
             *        used for signing.
             * @param hash Instance of XMSS_Hash, that may only be used by the
             *        thead executing sign.
             *
             * @return signature for msg.
             **/
            wots_keysig_t sign(const secure_vector<uint8_t> &msg, XMSS_Address &adrs, XMSS_Hash &hash);

            /**
             * Retrieves the secret seed used to generate WOTS+ chains. The seed
             * should be a uniformly random n-byte value.
             *
             * @return secret seed.
             **/
            const secure_vector<uint8_t> &private_seed() const {
                return m_private_seed;
            }

            /**
             * Sets the secret seed used to generate WOTS+ chains. The seed
             * should be a uniformly random n-byte value.
             *
             * @param private_seed Uniformly random n-byte value.
             **/
            void set_private_seed(const secure_vector<uint8_t> &private_seed) {
                m_private_seed = private_seed;
            }

            /**
             * Sets the secret seed used to generate WOTS+ chains. The seed
             * should be a uniformly random n-byte value.
             *
             * @param private_seed Uniformly random n-byte value.
             **/
            void set_private_seed(secure_vector<uint8_t> &&private_seed) {
                m_private_seed = std::move(private_seed);
            }

            algorithm_identifier pkcs8_algorithm_identifier() const override {
                throw Not_Implemented("No algorithm_identifier available for XMSS-WOTS.");
            }

            secure_vector<uint8_t> private_key_bits() const override {
                throw Not_Implemented("No PKCS8 key format defined for XMSS-WOTS.");
            }

        private:
            /**
             * Algorithm 3: "Generating a WOTS+ Private Key".
             * Generates a private key.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each thread.
             *
             * @param private_seed Uniformly random n-byte value.
             * @param[in] hash Instance of XMSS_Hash, that may only be used by the
             *            thead executing generate.
             *
             * @returns a vector of length key_size() of vectors of n bytes length
             *          containing uniformly random data.
             **/
            wots_keysig_t generate(const secure_vector<uint8_t> &private_seed, XMSS_Hash &hash);

            inline wots_keysig_t generate(const secure_vector<uint8_t> &private_seed) {
                return generate(private_seed, m_hash);
            }

            secure_vector<uint8_t> m_private_seed;
        };

        wots_keysig_t XMSS_WOTS_PrivateKey::generate(const secure_vector<uint8_t> &priv_seed, XMSS_Hash &hash) {
            wots_keysig_t priv_key(m_wots_params.len(), secure_vector<uint8_t>(0));

            for (size_t i = 0; i < m_wots_params.len(); i++) {
                XMSS_Tools::concat<size_t>(priv_key[i], i, 32);
                hash.prf(priv_key[i], priv_seed, priv_key[i]);
            }
            return priv_key;
        }

        XMSS_WOTS_PublicKey XMSS_WOTS_PrivateKey::generate_public_key(XMSS_Address &adrs) {
            XMSS_WOTS_PublicKey pub_key(m_wots_params.oid(), public_seed());
            generate_public_key(pub_key, wots_keysig_t((*this)[adrs]), adrs);
            return pub_key;
        }

        void XMSS_WOTS_PrivateKey::generate_public_key(XMSS_WOTS_PublicKey &pub_key, wots_keysig_t &&in_key_data,
                                                       XMSS_Address &adrs, XMSS_Hash &hash) {
            BOOST_ASSERT_MSG(wots_parameters() == pub_key.wots_parameters() && public_seed() == pub_key.public_seed(),
                             "Conflicting public key data.");

            pub_key.set_key_data(std::move(in_key_data));
            for (size_t i = 0; i < m_wots_params.len(); i++) {
                adrs.set_chain_address(i);
                chain(pub_key[i], 0, m_wots_params.wots_parameter() - 1, adrs, public_seed(), hash);
            }
        }

        wots_keysig_t XMSS_WOTS_PrivateKey::sign(const secure_vector<uint8_t> &msg, XMSS_Address &adrs,
                                                 XMSS_Hash &hash) {
            secure_vector<uint8_t> msg_digest {m_wots_params.base_w(msg, m_wots_params.len_1())};

            m_wots_params.append_checksum(msg_digest);
            wots_keysig_t sig(this->at(adrs, hash));

            for (size_t i = 0; i < m_wots_params.len(); i++) {
                adrs.set_chain_address(i);
                chain(sig[i], 0, msg_digest[i], adrs, m_public_seed, hash);
            }

            return sig;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
