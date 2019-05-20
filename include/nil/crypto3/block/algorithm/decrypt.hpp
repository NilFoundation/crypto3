//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_DECRYPT_HPP
#define CRYPTO3_BLOCK_DECRYPT_HPP

#include <nil/crypto3/block/detail/cipher_value.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup block_algorithms Algorithms
         * @ingroup block
         * @brief Algorithms are meant to provide encryption interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamEncrypter
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename BlockCipher, typename InputIterator, typename InputKeyIterator, typename OutputIterator>
        OutputIterator decrypt(InputIterator first, InputIterator last, InputKeyIterator key_first,
                               InputKeyIterator key_last, OutputIterator out) {

            typedef typename detail::itr_stream_encrypter_traits<BlockCipher, InputIterator>::type CipherState;

            typedef detail::value_encrypter_impl<CipherState> StreamEncrypterImpl;
            typedef detail::itr_encrypter_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), CipherState(BlockCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam InputIterator
         * @tparam CipherState
         * @param first
         * @param last
         * @return
         */
        template<typename BlockCipher, typename InputIterator, typename InputKeyIterator,
                 typename CipherState = typename detail::itr_stream_encrypter_traits<
                         typename BlockCipher::stream_encrypter_type, InputIterator>::type>
        detail::range_encrypter_impl<detail::value_encrypter_impl<CipherState>> decrypt(InputIterator first,
                                                                                        InputIterator last,
                                                                                        InputKeyIterator key_first,
                                                                                        InputKeyIterator key_last) {

            typedef detail::value_encrypter_impl<CipherState> StreamEncrypterImpl;
            typedef detail::range_encrypter_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, CipherState(BlockCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamEncrypter
         * @param rng
         * @param out
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename KeyRange, typename OutputIterator>
        OutputIterator encrypt(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {
            typedef typename detail::range_stream_encrypter_traits<typename BlockCipher::stream_decrypter_type,
                                                                   SinglePassRange>::type CipherState;

            typedef detail::value_encrypter_impl<CipherState> StreamEncrypterImpl;
            typedef detail::itr_encrypter_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), CipherState(BlockCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup block_algorithms
         *
         * @tparam BlockCipher
         * @tparam SinglePassRange
         * @tparam StreamEncrypter
         * @param r
         * @return
         */
        template<typename BlockCipher, typename SinglePassRange, typename KeyRange,
                 typename StreamEncrypter = typename detail::range_stream_encrypter_traits<
                         typename BlockCipher::stream_decrypter_type, SinglePassRange>::type>
        detail::range_encrypter_impl<detail::value_encrypter_impl<StreamEncrypter>> encrypt(const SinglePassRange &r,
                                                                                            const KeyRange &key) {

            typedef detail::value_encrypter_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::range_encrypter_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, StreamEncrypter(BlockCipher(key)));
        }
    } // namespace crypto3
} // namespace nil

#endif // include guard