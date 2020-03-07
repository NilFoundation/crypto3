//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_ENCRYPT_HPP
#define CRYPTO3_STREAM_ENCRYPT_HPP

#include <nil/crypto3/stream/algorithm/stream.hpp>

#include <nil/crypto3/stream/cipher_value.hpp>
#include <nil/crypto3/stream/cipher_state.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @brief
         *
         * @addtogroup stream_algorithms
         *
         * @tparam StreamCipher
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
        template<typename StreamCipher, typename InputIterator, typename KeyIterator, typename OutputIterator>
        OutputIterator encrypt(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last,
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
         * @addtogroup stream_algorithms
         *
         * @tparam StreamCipher
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename StreamCipher, typename InputIterator,
                 typename OutputAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        OutputAccumulator &encrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::ref_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, acc);
        }

        /*!
         * @brief
         *
         * @addtogroup stream_algorithms
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
        OutputAccumulator &encrypt(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::ref_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }

        /*!
         * @brief
         *
         * @addtogroup stream_algorithms
         *
         * @tparam StreamCipher
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
        template<typename StreamCipher, typename InputIterator, typename KeyIterator,
                 typename CipherAccumulator =
                     typename stream::stream_accumulator<typename StreamCipher::stream_encrypter_type>>
        stream::detail::range_cipher_impl<stream::detail::value_cipher_impl<CipherAccumulator>>
            encrypt(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last) {
            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, CipherAccumulator(StreamCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @addtogroup stream_algorithms
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
        OutputIterator encrypt(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {

            typedef typename StreamCipher::stream_encrypter_type EncryptionMode;
            typedef typename stream::stream_accumulator<EncryptionMode> CipherAccumulator;

            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::itr_cipher_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), CipherState(StreamCipher(key)));
        }

        /*!
         * @brief
         *
         * @addtogroup stream_algorithms
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
            encrypt(const SinglePassRange &r, const KeyRange &key) {

            typedef stream::detail::value_cipher_impl<CipherAccumulator> StreamEncrypterImpl;
            typedef stream::detail::range_cipher_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, CipherState(StreamCipher(key)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
