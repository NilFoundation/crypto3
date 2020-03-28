//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_XMSS_COMMON_OPS_HPP
#define CRYPTO3_PUBKEY_XMSS_COMMON_OPS_HPP

#include <vector>
#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/pubkey/xmss/xmss_parameters.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_address.hpp>
#include <nil/crypto3/pubkey/xmss/xmss_hash.hpp>

namespace nil {
    namespace crypto3 {

        typedef std::vector<secure_vector<uint8_t>> wots_keysig_t;

        /**
         * Operations shared by XMSS signature generation and verification operations.
         **/
        class XMSS_Common_Ops {
        public:
            XMSS_Common_Ops(XMSS_Parameters::xmss_algorithm_t oid) :
                m_xmss_params(oid), m_hash(m_xmss_params.hash_function_name()) {
            }

        protected:
            /**
             * Algorithm 7: "RAND_HASH"
             *
             * Generates a randomized hash.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each
             * thread.
             *
             * @param[out] result The resulting randomized hash.
             * @param[in] left Left half of the hash function input.
             * @param[in] right Right half of the hash function input.
             * @param[in] adrs Adress of the hash function call.
             * @param[in] seed The seed for G.
             * @param[in] hash Instance of XMSS_Hash, that may only by the thead
             *            executing generate_public_key.
             **/
            void randomize_tree_hash(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &left,
                                     const secure_vector<uint8_t> &right, XMSS_Address &adrs,
                                     const secure_vector<uint8_t> &seed, XMSS_Hash &hash);

            /**
             * Algorithm 7: "RAND_HASH"
             *
             * Generates a randomized hash.
             *
             * @param[out] result The resulting randomized hash.
             * @param[in] left Left half of the hash function input.
             * @param[in] right Right half of the hash function input.
             * @param[in] adrs Adress of the hash function call.
             * @param[in] seed The seed for G.
             **/
            inline void randomize_tree_hash(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &left,
                                            const secure_vector<uint8_t> &right, XMSS_Address &adrs,
                                            const secure_vector<uint8_t> &seed) {
                randomize_tree_hash(result, left, right, adrs, seed, m_hash);
            }

            /**
             * Algorithm 8: "ltree"
             * Create an L-tree used to compute the leaves of the binary hash tree.
             * Takes a WOTS+ public key and compresses it to a single n-byte value.
             *
             * This overload is used in multithreaded scenarios, where it is
             * required to provide seperate instances of XMSS_Hash to each thread.
             *
             * @param[out] result Public key compressed to a single n-byte value
             *             pk[0].
             * @param[in] pk Winternitz One Time Signatures+ public key.
             * @param[in] adrs Address encoding the address of the L-Tree
             * @param[in] seed The seed generated during the public key generation.
             * @param[in] hash Instance of XMSS_Hash, that may only be used by the
             *            thead executing create_l_tree.
             **/
            void create_l_tree(secure_vector<uint8_t> &result, wots_keysig_t pk, XMSS_Address &adrs,
                               const secure_vector<uint8_t> &seed, XMSS_Hash &hash);

            /**
             * Algorithm 8: "ltree"
             * Create an L-tree used to compute the leaves of the binary hash tree.
             * Takes a WOTS+ public key and compresses it to a single n-byte value.
             *
             * @param[out] result Public key compressed to a single n-byte value
             *             pk[0].
             * @param[in] pk Winternitz One Time Signatures+ public key.
             * @param[in] adrs Address encoding the address of the L-Tree
             * @param[in] seed The seed generated during the public key generation.
             **/
            inline void create_l_tree(secure_vector<uint8_t> &result, wots_keysig_t pk, XMSS_Address &adrs,
                                      const secure_vector<uint8_t> &seed) {
                create_l_tree(result, pk, adrs, seed, m_hash);
            }

        protected:
            XMSS_Parameters m_xmss_params;
            XMSS_Hash m_hash;
        };

        void XMSS_Common_Ops::randomize_tree_hash(secure_vector<uint8_t> &result, const secure_vector<uint8_t> &left,
                                                  const secure_vector<uint8_t> &right, XMSS_Address &adrs,
                                                  const secure_vector<uint8_t> &seed, XMSS_Hash &hash) {
            adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
            secure_vector<uint8_t> key {hash.prf(seed, adrs.bytes())};

            adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_MSB_Mode);
            secure_vector<uint8_t> bitmask_l {hash.prf(seed, adrs.bytes())};

            adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_LSB_Mode);
            secure_vector<uint8_t> bitmask_r {hash.prf(seed, adrs.bytes())};

            BOOST_ASSERT_MSG(bitmask_l.size() == left.size() && bitmask_r.size() == right.size(),
                             "Bitmask size doesn't match node size.");

            secure_vector<uint8_t> concat_xor(m_xmss_params.element_size() * 2);
            for (size_t i = 0; i < left.size(); i++) {
                concat_xor[i] = left[i] ^ bitmask_l[i];
                concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
            }

            hash.h(result, key, concat_xor);
        }

        void XMSS_Common_Ops::create_l_tree(secure_vector<uint8_t> &result, wots_keysig_t pk, XMSS_Address &adrs,
                                            const secure_vector<uint8_t> &seed, XMSS_Hash &hash) {
            size_t l = m_xmss_params.len();
            adrs.set_tree_height(0);

            while (l > 1) {
                for (size_t i = 0; i<l>> 1; i++) {
                    adrs.set_tree_index(i);
                    randomize_tree_hash(pk[i], pk[2 * i], pk[2 * i + 1], adrs, seed, hash);
                }
                if (l & 0x01) {
                    pk[l >> 1] = pk[l - 1];
                }
                l = (l >> 1) + (l & 0x01);
                adrs.set_tree_height(adrs.get_tree_height() + 1);
            }
            result = pk[0];
        }
    }    // namespace crypto3
}    // namespace nil

#endif
