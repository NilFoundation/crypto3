//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MODES_ENCRYPT_HPP
#define CRYPTO3_MODES_ENCRYPT_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/block/algorithm/block.hpp>

#include <nil/crypto3/block/cipher_value.hpp>
#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/cipher_key.hpp>

#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename CipherMode>
            using encryption_policy = typename CipherMode::encryption_policy;
        }

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
        template<typename CipherMode, typename InputIterator, typename KeyInputIterator, typename OutputIterator>
        OutputIterator encrypt(InputIterator first, InputIterator last, KeyInputIterator key_first,
                               KeyInputIterator key_last, OutputIterator out) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(
                first, last, std::move(out),
                CipherAccumulator(EncryptionMode(
                    BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key_first, key_last)))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeySinglePassRange, typename OutputIterator>
        OutputIterator encrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key,
                               OutputIterator out) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out),
                                 CipherAccumulator(EncryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
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
        template<typename CipherMode, typename InputIterator,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            encrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

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

        template<typename CipherMode, typename SinglePassRange,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<typename CipherMode::encryption_policy>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            encrypt(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }

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
        template<typename CipherMode, typename InputIterator, typename KeyInputIterator,
                 typename CipherAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                first, last,
                CipherAccumulator(EncryptionMode(
                    BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key_first, key_last)))));
        }

        /*!
         * @brief
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam CipherAccumulator
         *
         * @param first
         * @param last
         * @param key
         *
         * @return
         */
        template<typename CipherMode, typename InputIterator, typename KeySinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<
                     typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last,
                                 CipherAccumulator(EncryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
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
        template<typename CipherMode, typename SinglePassRange, typename KeyPassRange, typename OutputIterator>
        OutputIterator encrypt(const SinglePassRange &rng, const KeyPassRange &key, OutputIterator out) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out),
                                 CipherAccumulator(EncryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
        }

        /*!
         * @brief
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeyPassRange
         * @tparam OutputRange
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename CipherMode, typename SinglePassRange, typename KeyPassRange, typename OutputRange>
        OutputRange &encrypt(const SinglePassRange &rng, const KeyPassRange &key, OutputRange &out) {

            typedef typename CipherMode::template bind<block::encryption_policy<CipherMode>>::type EncryptionMode;
            typedef typename block::accumulator_set<EncryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out),
                                 CipherAccumulator(EncryptionMode(
                                     BlockCipher(block::detail::key_value<typename CipherMode::cipher_type>(key)))));
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

        template<typename BlockCipher, typename SinglePassRange, typename KeyPassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::encryption_policy<BlockCipher>>::type>>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(const SinglePassRange &r, const KeyPassRange &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::encryption_policy<BlockCipher>>::type EncryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef block::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                r, CipherAccumulator(EncryptionMode(BlockCipher(block::detail::key_value<BlockCipher>(key)))));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
