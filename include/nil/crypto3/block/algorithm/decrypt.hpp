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

#ifndef CRYPTO3_BLOCK_DECRYPT_HPP
#define CRYPTO3_BLOCK_DECRYPT_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/block/algorithm/block.hpp>

#include <nil/crypto3/block/cipher_value.hpp>
#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/cipher_key.hpp>

#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename BlockCipher>
            using decryption_policy = typename modes::isomorphic<BlockCipher, nop_padding>::decryption_policy;
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
        template<typename BlockCipher, typename InputIterator, typename KeyInputIterator, typename OutputIterator,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        OutputIterator decrypt(InputIterator first, InputIterator last, KeyInputIterator key_first,
                               KeyInputIterator key_last, OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(first, last, std::move(out),
                CipherAccumulator(DecryptionMode(
                    BlockCipher(block::cipher_key<BlockCipher>(key_first, key_last).key))));
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
        template<typename BlockCipher, typename InputIterator, typename KeySinglePassRange, typename OutputIterator,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        OutputIterator decrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key,
                               OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(
                first, last, std::move(out),
                CipherAccumulator(DecryptionMode(BlockCipher(block::cipher_key<BlockCipher>(key).key))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key
         * @param out
         *
         * @return
         */
        template<typename BlockCipher, typename InputIterator, typename OutputIterator,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        OutputIterator decrypt(InputIterator first, InputIterator last, const block::cipher_key<BlockCipher> &key,
                               OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(first, last, std::move(out), CipherAccumulator(DecryptionMode(BlockCipher(key.key))));
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
                 typename OutputAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
        decrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last, std::forward<OutputAccumulator>(acc));
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

        template<typename BlockCipher, typename SinglePassRange,
                 typename OutputAccumulator = typename block::accumulator_set<
                     typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                         typename block::modes::isomorphic<BlockCipher, block::nop_padding>::decryption_policy>::type>,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
        decrypt(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef block::detail::ref_cipher_impl<OutputAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(r, acc);
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
        template<typename BlockCipher, typename InputIterator, typename KeyInputIterator,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
        decrypt(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last,
                CipherAccumulator(DecryptionMode(
                    BlockCipher(block::cipher_key<BlockCipher>(key_first, key_last).key))));
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
        template<typename BlockCipher, typename InputIterator, typename KeySinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
        decrypt(InputIterator first, InputIterator last, const KeySinglePassRange &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(
                first, last, CipherAccumulator(DecryptionMode(BlockCipher(block::cipher_key<BlockCipher>(key).key))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam CipherAccumulator
         * @param first
         * @param last
         * @param key
         * @return
         */
        template<typename BlockCipher, typename InputIterator,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_iterator<InputIterator>::value>::type>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
        decrypt(InputIterator first, InputIterator last, const block::cipher_key<BlockCipher> &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last, CipherAccumulator(DecryptionMode(BlockCipher(key.key))));
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
        template<typename BlockCipher, typename SinglePassRange, typename KeySinglePassRange, typename OutputIterator,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        OutputIterator decrypt(const SinglePassRange &rng, const KeySinglePassRange &key, OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(
                rng, std::move(out),
                CipherAccumulator(DecryptionMode(BlockCipher(block::cipher_key<BlockCipher>(key).key))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename OutputIterator,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        OutputIterator decrypt(const SinglePassRange &rng, const block::cipher_key<BlockCipher> &key,
                               OutputIterator out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::itr_cipher_impl<StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out), CipherAccumulator(DecryptionMode(BlockCipher(key.key))));
        }

        /*!
         * @brief
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam KeySinglePassRange
         * @tparam OutputRange
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename KeySinglePassRange, typename OutputRange,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        OutputRange &decrypt(const SinglePassRange &rng, const KeySinglePassRange &key, OutputRange &out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(
                rng, std::move(out),
                CipherAccumulator(DecryptionMode(BlockCipher(block::cipher_key<BlockCipher>(key).key))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam OutputRange
         * @param rng
         * @param key
         * @param out
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename OutputRange,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        OutputRange &decrypt(const SinglePassRange &rng, const block::cipher_key<BlockCipher> &key, OutputRange &out) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;
            typedef typename block::accumulator_set<DecryptionMode> CipherAccumulator;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out), CipherAccumulator(DecryptionMode(BlockCipher(key.key))));
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
        template<typename BlockCipher, typename SinglePassRange, typename KeySinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
        decrypt(const SinglePassRange &r, const KeySinglePassRange &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(
                r, CipherAccumulator(DecryptionMode(BlockCipher(block::cipher_key<BlockCipher>(key).key))));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam CipherAccumulator
         * @param r
         * @param key
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange,
                 typename CipherAccumulator = typename block::accumulator_set<typename block::modes::isomorphic<
                     BlockCipher, block::nop_padding>::template bind<block::decryption_policy<BlockCipher>>::type>,
                 typename = typename std::enable_if<detail::is_range<SinglePassRange>::value>::type>
        block::detail::range_cipher_impl<block::detail::value_cipher_impl<CipherAccumulator>>
        decrypt(const SinglePassRange &r, const block::cipher_key<BlockCipher> &key) {

            typedef typename block::modes::isomorphic<BlockCipher, block::nop_padding>::template bind<
                block::decryption_policy<BlockCipher>>::type DecryptionMode;

            typedef block::detail::value_cipher_impl<CipherAccumulator> StreamDecrypterImpl;
            typedef block::detail::range_cipher_impl<StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(r, CipherAccumulator(DecryptionMode(BlockCipher(key.key))));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
