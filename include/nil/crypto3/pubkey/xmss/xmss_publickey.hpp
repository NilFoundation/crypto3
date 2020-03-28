#ifndef CRYPTO3_PUBKEY_XMSS_PUBLICKEY_HPP
#define CRYPTO3_PUBKEY_XMSS_PUBLICKEY_HPP

#include <cstddef>
#include <iterator>
#include <memory>
#include <string>

#include <nil/crypto3/asn1/alg_id.hpp>
#include <nil/crypto3/asn1/asn1_oid.hpp>
#include <nil/crypto3/asn1/der_enc.hpp>

#include <nil/crypto3/utilities/exceptions.hpp>

#include <nil/crypto3/random/random.hpp>

#include <nil/crypto3/utilities/types.h>

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_parameters.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_wots_parameters.hpp>
#include <nil/crypto3/pubkey/pk_operations.hpp>

namespace nil {
    namespace crypto3 {

        class XMSS_Verification_Operation;

        /**
         * An XMSS: Extended Hash-Based Signature public key.
         * The XMSS public key does not support the X509 standard. Instead the
         * raw format described in [1] is used.
         *
         *   [1] XMSS: Extended Hash-Based Signatures,
         *       draft-itrf-cfrg-xmss-hash-based-signatures-06
         *       Release: July 2016.
         *       https://datatracker.ietf.org/doc/
         *       draft-irtf-cfrg-xmss-hash-based-signatures/?include_text=1
         **/
        class XMSS_PublicKey : public virtual public_key_policy {
        public:
            /**
             * Creates a new XMSS public key for the chosen XMSS signature method.
             * New public and prf seeds are generated using rng. The appropriate WOTS
             * signature method will be automatically set based on the chosen XMSS
             * signature method.
             *
             * @param xmss_oid Identifier for the selected XMSS signature method.
             * @param rng A random number generator to use for key generation.
             **/
            XMSS_PublicKey(XMSS_Parameters::xmss_algorithm_t xmss_oid, RandomNumberGenerator &rng) :

                m_xmss_params(xmss_oid), m_wots_params(m_xmss_params.ots_oid()), m_root(m_xmss_params.element_size()),
                m_public_seed(rng.random_vec(m_xmss_params.element_size())) {
            }

            /**
             * Creates an XMSS public key from a byte sequence produced by
             * raw_private_key().
             **/
            XMSS_PublicKey(const std::vector<uint8_t> &raw_key);

            /**
             * Creates a new XMSS public key for a chosen XMSS signature method as
             * well as pre-computed root node and public_seed values.
             *
             * @param xmss_oid Identifier for the selected XMSS signature method.
             * @param root Root node value.
             * @param public_seed Public seed value.
             **/
            XMSS_PublicKey(XMSS_Parameters::xmss_algorithm_t xmss_oid, const secure_vector<uint8_t> &root,
                           const secure_vector<uint8_t> &public_seed) :

                m_xmss_params(xmss_oid),
                m_wots_params(m_xmss_params.ots_oid()), m_root(root), m_public_seed(public_seed) {
            }

            /**
             * Creates a new XMSS public key for a chosen XMSS signature method as
             * well as pre-computed root node and public_seed values.
             *
             * @param xmss_oid Identifier for the selected XMSS signature method.
             * @param root Root node value.
             * @param public_seed Public seed value.
             **/
            XMSS_PublicKey(XMSS_Parameters::xmss_algorithm_t xmss_oid, secure_vector<uint8_t> &&root,
                           secure_vector<uint8_t> &&public_seed) :

                m_xmss_params(xmss_oid),
                m_wots_params(m_xmss_params.ots_oid()), m_root(std::move(root)), m_public_seed(std::move(public_seed)) {
            }

            /**
             * Retrieves the chosen XMSS signature method.
             *
             * @return XMSS signature method identifier.
             **/
            XMSS_Parameters::xmss_algorithm_t xmss_oid() const {
                return m_xmss_params.oid();
            }

            /**
             * Sets the chosen XMSS signature method
             **/
            void set_xmss_oid(XMSS_Parameters::xmss_algorithm_t xmss_oid) {
                m_xmss_params = XMSS_Parameters(xmss_oid);
                m_wots_params = XMSS_WOTS_Parameters(m_xmss_params.ots_oid());
            }

            /**
             * Retrieves the XMSS parameters determined by the chosen XMSS Signature
             * method.
             *
             * @return XMSS parameters.
             **/
            const XMSS_Parameters &xmss_parameters() const {
                return m_xmss_params;
            }

            /**
             * Retrieves the Winternitz One Time Signature (WOTS) method,
             * corrseponding to the chosen XMSS signature method.
             *
             * @return XMSS WOTS signature method identifier.
             **/
            XMSS_WOTS_Parameters::ots_algorithm_t wots_oid() const {
                return m_wots_params.oid();
            }

            /**
             * Retrieves the Winternitz One Time Signature (WOTS) parameters
             * corresponding to the chosen XMSS signature method.
             *
             * @return XMSS WOTS signature method parameters.
             **/
            const XMSS_WOTS_Parameters &wots_parameters() const {
                return m_wots_params;
            }

            secure_vector<uint8_t> &root() {
                return m_root;
            }

            void set_root(const secure_vector<uint8_t> &root) {
                m_root = root;
            }

            void set_root(secure_vector<uint8_t> &&root) {
                m_root = std::move(root);
            }

            const secure_vector<uint8_t> &root() const {
                return m_root;
            }

            virtual secure_vector<uint8_t> &public_seed() {
                return m_public_seed;
            }

            virtual void set_public_seed(const secure_vector<uint8_t> &public_seed) {
                m_public_seed = public_seed;
            }

            virtual void set_public_seed(secure_vector<uint8_t> &&public_seed) {
                m_public_seed = std::move(public_seed);
            }

            virtual const secure_vector<uint8_t> &public_seed() const {
                return m_public_seed;
            }

            std::string algo_name() const

                override {
                return "XMSS";
            }

            algorithm_identifier algorithm_identifier() const

                override {
                return

                    algorithm_identifier(get_oid(), algorithm_identifier::USE_NULL_PARAM

                    );
            }

            bool check_key(RandomNumberGenerator &, bool) const

                override {
                return true;
            }

            std::unique_ptr<pk_operations::verification> create_verification_op(const std::string &,
                                                                                const std::string &provider) const

                override;

            size_t estimated_strength() const

                override {
                return m_xmss_params.

                    estimated_strength();
            }

            size_t key_length() const

                override {
                return m_xmss_params.

                    estimated_strength();
            }

            /**
             * Returns a raw byte sequence as defined in [1].
             * This method acts as an alias for raw_public_key().
             *
             * @return raw public key bits.
             **/
            std::vector<uint8_t> public_key_bits() const

                override {
                return

                    raw_public_key();
            }

            /**
             * Size in bytes of the serialized XMSS public key produced by
             * raw_public_key().
             *
             * @return size in bytes of serialized Public Key.
             **/
            virtual size_t size() const {
                return sizeof(uint32_t) + 2 * m_xmss_params.element_size();
            }

            /**
             * Generates a non standardized byte sequence representing the XMSS
             * public key, as defined in [1] (p. 23, "XMSS Public Key")
             *
             * @return 4-byte OID, followed by n-byte root node, followed by
             *         public seed.
             **/
            virtual std::vector<uint8_t> raw_public_key() const;

        protected:
            XMSS_Parameters m_xmss_params;
            XMSS_WOTS_Parameters m_wots_params;
            secure_vector<uint8_t> m_root;
            secure_vector<uint8_t> m_public_seed;

        private:
            XMSS_Parameters::xmss_algorithm_t deserialize_xmss_oid(const std::vector<uint8_t> &raw_key);
        };

        XMSS_PublicKey::XMSS_PublicKey(const std::vector <uint8_t> &raw_key) : m_xmss_params(
            XMSS_PublicKey::deserialize_xmss_oid(raw_key)), m_wots_params(m_xmss_params.ots_oid()) {
            if (raw_key.size() < size()) {
                throw Integrity_Failure("Invalid XMSS public key size detected.");
            }

            // extract & copy root from raw key.
            m_root.clear();
            m_root.reserve(m_xmss_params.element_size());
            auto begin = raw_key.begin() + sizeof(uint32_t);
            auto end = begin + m_xmss_params.element_size();
            std::copy(begin, end, std::back_inserter(m_root));

            // extract & copy public seed from raw key.
            begin = end;
            end = begin + m_xmss_params.element_size();
            m_public_seed.clear();
            m_public_seed.reserve(m_xmss_params.element_size());
            std::copy(begin, end, std::back_inserter(m_public_seed));
        }

        XMSS_Parameters::xmss_algorithm_t XMSS_PublicKey::deserialize_xmss_oid(const std::vector <uint8_t> &raw_key) {
            if (raw_key.size() < 4) {
                throw Integrity_Failure("XMSS signature OID missing.");
            }

            // extract and convert algorithm id to enum type
            uint32_t raw_id = 0;
            for (size_t i = 0; i < 4; i++) {
                raw_id = ((raw_id << 8) | raw_key[i]);
            }

            return static_cast<XMSS_Parameters::xmss_algorithm_t>(raw_id);
        }

        std::unique_ptr <pk_operations::verification> XMSS_PublicKey::create_verification_op(const std::string &,
                                                                                             const std::string &provider) const {
            if (provider == "core" || provider.empty()) {
                return std::unique_ptr<pk_operations::verification>(new XMSS_Verification_Operation(*this));
            }
            throw Provider_Not_Found(algo_name(), provider);
        }

        std::vector <uint8_t> XMSS_PublicKey::raw_public_key() const {
            std::vector <uint8_t> result{static_cast<uint8_t>(m_xmss_params.oid() >> 24),
                                         static_cast<uint8_t>(m_xmss_params.oid() >> 16),
                                         static_cast<uint8_t>(m_xmss_params.oid() >> 8),
                                         static_cast<uint8_t>(m_xmss_params.oid())};

            std::copy(m_root.begin(), m_root.end(), std::back_inserter(result));
            std::copy(m_public_seed.begin(), m_public_seed.end(), std::back_inserter(result));

            return result;
        }
    }    // namespace crypto3
}    // namespace nil

#endif