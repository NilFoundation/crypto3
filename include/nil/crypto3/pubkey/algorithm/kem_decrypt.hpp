//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ENCRYPT_HPP
#define CRYPTO3_PUBKEY_ENCRYPT_HPP

#include <nil/crypto3/pubkey/scheme_value.hpp>
#include <nil/crypto3/pubkey/scheme_state.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam PublicKeyIterator
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
        template<typename PublicKeyCipher, typename InputIterator, typename PublicKeyIterator, typename OutputIterator>
        OutputIterator encrypt(InputIterator first, InputIterator last, PublicKeyIterator key_first,
                               PublicKeyIterator key_last, OutputIterator out) {

            typedef typename PublicKeyCipher::stream_encrypter_type EncryptionMode;
            typedef typename pubkey::accumulator_set<EncryptionMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), CiperState(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename PublicKeyCipher, typename InputIterator,
                 typename OutputAccumulator =
                     typename pubkey::accumulator_set<typename PublicKeyCipher::stream_encrypter_type>>
        OutputAccumulator &encrypt(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, acc);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange,
                 typename OutputAccumulator =
                     typename pubkey::accumulator_set<typename PublicKeyCipher::stream_encrypter_type>>
        OutputAccumulator &encrypt(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam PublicKeyIterator
         * @tparam SchemeAccumulator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         *
         * @return
         */
        template<typename PublicKeyCipher, typename InputIterator, typename PublicKeyIterator,
                 typename SchemeAccumulator =
                     typename pubkey::accumulator_set<typename PublicKeyCipher::stream_encrypter_type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
            encrypt(InputIterator first, InputIterator last, PublicKeyIterator key_first, PublicKeyIterator key_last) {

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, SchemeAccumulator(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam PublicKeyRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PublicKeyRange, typename OutputIterator>
        OutputIterator encrypt(const SinglePassRange &rng, const PublicKeyRange &key, OutputIterator out) {

            typedef typename PublicKeyCipher::stream_encrypter_type EncryptionMode;
            typedef typename pubkey::accumulator_set<EncryptionMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), CipherState(PublicKeyCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam PublicKeyRange
         * @tparam SchemeAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PublicKeyRange,
                 typename SchemeAccumulator =
                     typename pubkey::accumulator_set<typename PublicKeyCipher::stream_encrypter_type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
            encrypt(const SinglePassRange &r, const PublicKeyRange &key) {

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, CipherState(PublicKeyCipher(key)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard