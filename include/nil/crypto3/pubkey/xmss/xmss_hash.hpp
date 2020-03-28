#ifndef CRYPTO3_PUBKEY_XMSS_HASH_HPP
#define CRYPTO3_PUBKEY_XMSS_HASH_HPP

namespace nil {
    namespace crypto3 {

        /**
         * A collection of pseudorandom hash functions required for XMSS and WOTS
         * computations.
         **/
        class XMSS_Hash final {
        public:
            XMSS_Hash(const std::string &h_func_name);

            XMSS_Hash(const XMSS_Hash &hash);

            /**
             * Pseudoranom function creating a hash out of a key and data using
             * a cryptographic hash function.
             *
             * @param[out] result The hash calculated using key and data.
             * @param[in] key An n-byte key value.
             * @param[in] data A 32-byte XMSS_Address data value
             **/
            inline void prf(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &key,
                            const secure_vector<uint8_t> &data) {
                m_hash->update(m_zero_padding);
                m_hash->update(m_id_prf);
                m_hash->update(key);
                m_hash->update(data);
                m_hash->final(result);
            }

            /**
             * Pseudoranom function creating a hash out of a key and data using
             * a cryptographic hash function.
             *
             * @param[in] key An n-byte key value.
             * @param[in] data A 32-byte XMSS_Address data value
             * @return result The hash calculated using key and data.
             **/
            inline secure_vector<uint8_t> prf(const secure_vector<uint8_t> &key, const secure_vector<uint8_t> &data) {
                m_hash->update(m_zero_padding);
                m_hash->update(m_id_prf);
                m_hash->update(key);
                m_hash->update(data);
                return m_hash->final();
            }

            /**
             * F is a keyed cryptographic hash function used by the WOTS+ algorithm.
             *
             * @param[out] result The hash calculated using key and data.
             * @param[in] key key of length n bytes.
             * @param[in] data string of arbitrary length.
             **/
            void f(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &key,
                   const secure_vector<uint8_t> &data) {
                m_hash->update(m_zero_padding);
                m_hash->update(m_id_f);
                m_hash->update(key);
                m_hash->update(data);
                m_hash->final(result);
            }

            /**
             * Cryptographic hash function h accepting n byte keys and 2n byte
             * strings of data.
             *
             * @param[out] result The hash calculated using key and data.
             * @param[in] key key of length n bytes.
             * @param[in] data string of 2n bytes length.
             **/
            void h(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &key,
                   const secure_vector<uint8_t> &data);

            /**
             * Cryptographic hash function h accepting 3n byte keys and data
             * strings of arbitrary length.
             *
             * @param randomness n-byte value.
             * @param root n-byte root node.
             * @param index_bytes Index value padded with leading zeros.
             * @param data string of arbitrary length.
             *
             * @return hash value of n-bytes length.
             **/
            secure_vector<uint8_t> h_msg(const secure_vector<uint8_t> &randomness,
                                         const secure_vector<uint8_t> &root,
                                         const secure_vector<uint8_t> &index_bytes,
                                         const secure_vector<uint8_t> &data);

            /**
             * Initializes buffered h_msg computation with prefix data.
             *
             * @param randomness random n-byte value.
             * @param root n-byte root node.
             * @param index_bytes Index value padded with leading zeros.
             **/
            void h_msg_init(const secure_vector<uint8_t> &randomness, const secure_vector<uint8_t> &root,
                            const secure_vector<uint8_t> &index_bytes);

            /**
             * Adds a message block to buffered h_msg computation.
             *
             * @param data A message block
             **/
            void h_msg_update(const secure_vector<uint8_t> &data);

            /**
             * Adds a message block to buffered h_msg computation.
             *
             * @param data A message block
             * @param size Length of the message block in bytes.
             **/
            void h_msg_update(const uint8_t data[], size_t size);

            /**
             * Finalizes buffered h_msg computation and retrieves the result.
             *
             * @return Hash calculated using the prefix set by h_msg_init() and
             *         message blocks provided through calls to h_msg_update().
             **/
            secure_vector<uint8_t> h_msg_final();

            size_t output_length() const {
                return m_output_length;
            }

        private:
            static const uint8_t m_id_f = 0x00;
            static const uint8_t m_id_h = 0x01;
            static const uint8_t m_id_hmsg = 0x02;
            static const uint8_t m_id_prf = 0x03;

            std::unique_ptr<HashFunction> m_hash;
            std::unique_ptr<HashFunction> m_msg_hash;
            // 32 byte id prefixes prepended to the hash input.
            std::vector<uint8_t> m_zero_padding;
            size_t m_output_length;
            const std::string m_hash_func_name;
        };

        XMSS_Hash::XMSS_Hash(const XMSS_Hash &hash) : XMSS_Hash(hash.m_hash_func_name) {
        }

        XMSS_Hash::XMSS_Hash(const std::string &h_func_name) :
            m_hash(HashFunction::create(h_func_name)), m_hash_func_name(h_func_name) {
            if (!m_hash) {
                throw Lookup_Error("XMSS cannot use hash " + h_func_name + " because it is unavailable");
            }

            m_output_length = m_hash->output_length();
            BOOST_ASSERT_MSG(m_output_length > 0, "Hash output length of zero is invalid.");

            m_zero_padding.resize(m_output_length - 1);
            m_msg_hash.reset(m_hash->clone());
        }

        void XMSS_Hash::h(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &key,
                          const secure_vector<uint8_t> &data) {
            m_hash->update(m_zero_padding);
            m_hash->update(m_id_h);
            m_hash->update(key);
            m_hash->update(data);
            m_hash->final(result);
        }

        void XMSS_Hash::h_msg_init(const secure_vector<uint8_t> &randomness, const secure_vector<uint8_t> &root,
                                   const secure_vector<uint8_t> &index_bytes) {
            m_msg_hash->clear();
            m_msg_hash->update(m_zero_padding);
            m_msg_hash->update(m_id_hmsg);
            m_msg_hash->update(randomness);
            m_msg_hash->update(root);
            m_msg_hash->update(index_bytes);
        }

        void XMSS_Hash::h_msg_update(const secure_vector<uint8_t> &data) {
            m_msg_hash->update(data);
        }

        void XMSS_Hash::h_msg_update(const uint8_t data[], size_t size) {
            m_msg_hash->update(data, size);
        }

        secure_vector<uint8_t> XMSS_Hash::h_msg_final() {
            return m_msg_hash->final();
        }

        secure_vector<uint8_t> XMSS_Hash::h_msg(const secure_vector<uint8_t> &randomness,
                                                const secure_vector<uint8_t> &root,
                                                const secure_vector<uint8_t> &index_bytes,
                                                const secure_vector<uint8_t> &data) {
            h_msg_init(randomness, root, index_bytes);
            m_msg_hash->update(data);
            return m_msg_hash->final();
        }
    }    // namespace crypto3
}    // namespace nil

#endif
