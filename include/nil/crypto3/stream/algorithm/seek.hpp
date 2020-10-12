//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_SEEK_HPP
#define CRYPTO3_STREAM_SEEK_HPP

#include <nil/crypto3/stream/algorithm/stream.hpp>

#include <nil/crypto3/stream/cipher_value.hpp>
#include <nil/crypto3/stream/cipher_state.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename StreamCipher, typename InputIterator, typename KeyIterator, typename OutputIterator>
        OutputIterator seek(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last,
                            OutputIterator out) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), CiperState(StreamCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename StreamCipher, typename InputIterator,
                 typename OutputAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        OutputAccumulator &seek(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::ref_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, acc);
        }

        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam SinglePassRange
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        template<typename StreamCipher, typename SinglePassRange,
                 typename OutputAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        OutputAccumulator &seek(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::ref_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }

        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam InputIterator
         * @tparam CipherState
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         *
         * @return
         */
        template<typename StreamCipher, typename InputIterator, typename KeyIterator,
                 typename CipherAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        stream::detail::range_cipher_impl<stream::detail::value_cipher_impl<CipherAccumulator>>
            seek(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last) {
            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, CipherAccumulator(StreamCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
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
        template<typename StreamCipher, typename SinglePassRange, typename KeyRange, typename OutputIterator>
        OutputIterator seek(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), CipherState(StreamCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam CipherAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename StreamCipher, typename SinglePassRange, typename KeyRange,
                 typename CipherAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        stream::detail::range_cipher_impl<stream::detail::value_cipher_impl<CipherAccumulator>>
            seek(const SinglePassRange &r, const KeyRange &key) {

            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, CipherState(StreamCipher(key)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
