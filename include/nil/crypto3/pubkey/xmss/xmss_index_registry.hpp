//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_XMSS_INDEX_REGISTRY_HPP
#define CRYPTO3_PUBKEY_XMSS_INDEX_REGISTRY_HPP

#include <nil/crypto3/utilities/secmem.hpp>
#include <nil/crypto3/utilities/mutex.hpp>

#include <nil/crypto3/pubkey/xmss/atomic.hpp>

namespace nil {
    namespace crypto3 {

        /**
         * A registry for XMSS private keys, keeps track of the leaf index for
         * independend copies of the same key.
         **/
        class XMSS_Index_Registry final {
        public:
            XMSS_Index_Registry(const XMSS_Index_Registry &) = delete;

            XMSS_Index_Registry &operator=(const XMSS_Index_Registry &) = delete;

            /**
             * Retrieves a handle to the process-wide unique XMSS index registry.
             *
             * @return Reference to unique XMSS index registry.
             **/
            static XMSS_Index_Registry &get_instance() {
                static XMSS_Index_Registry self;
                return self;
            }

            /**
             * Retrieves the last unused leaf index for the private key identified
             * by private_seed and prf. The leaf index will be updated properly
             * across independent copies of private_key.
             *
             * @param private_seed Part of the unique identifier for an
             *                     XMSS_PrivateKey.
             * @param prf Part of the unique identifier for an XMSS_PrivateKey.
             *
             * @return last unused leaf index for private_key.
             **/
            std::shared_ptr<Atomic<size_t>> get(const secure_vector<uint8_t> &private_seed,
                                                const secure_vector<uint8_t> &prf);

        private:
            XMSS_Index_Registry() = default;

            static const std::string m_index_hash_function;

            /**
             * Creates a unique 64-bit id for an XMSS_Private key, by interpreting
             * the first 64-bit of HASH(PRIVATE_SEED || PRF) as 64 bit integer
             * value.
             *
             * @return unique integral identifier for an XMSS private key.
             **/
            uint64_t make_key_id(const secure_vector<uint8_t> &private_seed, const secure_vector<uint8_t> &prf) const;

            /**
             * Retrieves the index position of a key within the registry or
             * max(size_t) if key has not been found.
             *
             * @param id unique id of the XMSS private key (see make_key_id()).
             *
             * @return index position of key or max(size_t) if key not found.
             **/
            size_t get(uint64_t id) const;

            /**
             * If XMSS_PrivateKey identified by id is already registered, the
             * position of the according registry entry is returned. If last_unused
             * is bigger than the last unused index stored for the key identified by
             * id the unused leaf index for this key is set to last_unused. If no key
             * matching id is registed yet, an entry of id is added, with the last
             * unused leaf index initialized to the value of last_unused.
             *
             * @last_unused Initial value for the last unused leaf index of the
             *              registered key.
             *
             * @return positon of leaf index registry entry for key identified
             *         by id.
             **/
            size_t add(uint64_t id, size_t last_unused = 0);

            std::vector<uint64_t> m_key_ids;
            std::vector<std::shared_ptr<Atomic<size_t>>> m_leaf_indices;
            mutex_type m_mutex;
        };

        const std::string XMSS_Index_Registry::m_index_hash_function = "SHA-256";

        uint64_t XMSS_Index_Registry::make_key_id(const secure_vector<uint8_t> &private_seed,
                                                  const secure_vector<uint8_t> &prf) const {
            std::unique_ptr<HashFunction> hash = HashFunction::create(m_index_hash_function);
            BOOST_ASSERT_MSG(hash != nullptr, "XMSS_Index_Registry requires SHA-256");
            hash->update(private_seed);
            hash->update(prf);
            secure_vector<uint8_t> result = hash->final();
            uint64_t key_id = 0;
            for (size_t i = 0; i < sizeof(key_id); i++) {
                key_id = ((key_id << 8) | result[i]);
            }

            return key_id;
        }

        std::shared_ptr<Atomic<size_t>>

            XMSS_Index_Registry::get(const secure_vector<uint8_t> &private_seed, const secure_vector<uint8_t> &prf) {
            size_t pos = get(make_key_id(private_seed, prf));

            if (pos < std::numeric_limits<size_t>::max()) {
                return m_leaf_indices[pos];
            } else {
                return m_leaf_indices[add(make_key_id(private_seed, prf))];
            }
        }

        size_t XMSS_Index_Registry::get(uint64_t id) const {
            for (size_t i = 0; i < m_key_ids.size(); i++) {
                if (m_key_ids[i] == id) {
                    return i;
                }
            }

            return std::numeric_limits<size_t>::max();
        }

        size_t XMSS_Index_Registry::add(uint64_t id, size_t last_unused) {
            lock_guard_type<mutex_type> lock(m_mutex);
            size_t pos = get(id);
            if (pos < m_key_ids.size()) {
                if (last_unused > *(m_leaf_indices[pos])) {
                    m_leaf_indices[pos] = std::make_shared<Atomic<size_t>>(last_unused);
                }
                return pos;
            }

            m_key_ids.push_back(id);
            m_leaf_indices.push_back(std::make_shared<Atomic<size_t>>(last_unused));
            return m_key_ids.size() - 1;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
