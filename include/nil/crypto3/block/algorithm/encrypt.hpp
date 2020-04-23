//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_ENCRYPT_HPP
#define CRYPTO3_BLOCK_ENCRYPT_HPP

//#include <nil/crypto3/block/algorithm/block.hpp>

#include <nil/crypto3/block/cipher_value.hpp>
#include <nil/crypto3/block/cipher_state.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {

        template<typename Cipher>
        struct nop_padding {
            typedef std::size_t size_type;

            typedef Cipher cipher_type;

            constexpr static const size_type block_bits = cipher_type::block_bits;
            constexpr static const size_type block_words = cipher_type::block_words;
            typedef typename cipher_type::block_type block_type;
        };

        template<typename BlockCipher>
        using policy_type = typename block::modes::isomorphic<BlockCipher, nop_padding>::encryption_policy;

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         * @param out
         *
         * @return
         */
        template<typename BlockCipher, typename InputIterator, typename KeyIterator, typename OutputIterator>
        OutputIterator encrypt(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last,
                               OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, nop_padding>::template bind<
                policy_type<BlockCipher>>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), CiperState(BlockCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename BlockCipher, typename InputIterator,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename block::modes::isomorphic<BlockCipher, nop_padding>::template bind<
                         typename block::modes::isomorphic<BlockCipher, nop_padding>::encryption_policy>::type>>
        OutputAccumulator &encrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        /*
        template<
            typename BlockCipher, typename SinglePassRange,
            typename OutputAccumulator = typename block::accumulator_set<typename block::modes::isomorphic <
        BlockCipher, nop_padding>::template bind <typename block::modes::isomorphic<BlockCipher,
        nop_padding>::encryption_policy>::type>> OutputAccumulator &encrypt(const SinglePassRange &r, OutputAccumulator
        &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }*/

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam CipherAccumulator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         *
         * @return
         */
        template<typename BlockCipher, typename InputIterator, typename KeyIterator,
                 typename CipherAccumulator = typename block::accumulator_set<
                     typename block::modes::isomorphic<BlockCipher, nop_padding>::template bind<
                         typename block::modes::isomorphic<BlockCipher, nop_padding>::encryption_policy>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last) {

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, CipherAccumulator(BlockCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename KeyRange, typename OutputIterator>
        OutputIterator encrypt(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, nop_padding>::template bind<
                typename block::modes::isomorphic<BlockCipher, nop_padding>::encryption_policy>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), CipherState(BlockCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam CipherAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */

        template<typename BlockCipher, typename SinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, nop_padding>::template bind<policy_type<BlockCipher>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(const SinglePassRange &r, typename BlockCipher::key_type &key) {

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, CipherState(BlockCipher(key)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
