#ifndef CRYPTO3_PUBKEY_ENCRYPT_HPP
#define CRYPTO3_PUBKEY_ENCRYPT_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/detail/stream_postprocessor.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @addtogroup encrypt_algorithms Algorithms
         * @addtogroup encrypt
         * @brief Algorithms are meant to provide encrypting interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
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
        template<
            typename PublicKeyCipher, typename InputIterator, typename PublicKeyIterator, typename OutputIterator,
            typename StreamEncrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        OutputIterator encrypt(InputIterator first, InputIterator last, PublicKeyIterator key_first,
                               PublicKeyIterator key_last, OutputIterator out) {

            typedef detail::value_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), StreamEncrypter(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamEncrypter
         * @param first
         * @param last
         * @param out
         * @param sh
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator, typename OutputIterator,
            typename StreamEncrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        OutputIterator encrypt(InputIterator first, InputIterator last, OutputIterator out,
                               const public_key<PublicKeyCipher> &pk) {

            typedef detail::ref_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam StreamEncrypter
         * @param first
         * @param last
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator, typename PublicKeyIterator,
            typename StreamEncrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::value_encrypt_impl<StreamEncrypter>>
            encrypt(InputIterator first, InputIterator last, PublicKeyIterator key_first, PublicKeyIterator key_last) {
            typedef detail::value_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, StreamEncrypter(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam StreamEncrypter
         * @param first
         * @param last
         * @param sh
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator,
            typename StreamEncrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::ref_encrypt_impl<StreamEncrypter>>
            encrypt(InputIterator first, InputIterator last, const public_key<PublicKeyCipher> &pk) {
            typedef detail::ref_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, sh);
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamEncrypter
         * @param rng
         * @param out
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PublicKeyRange, typename OutputIterator,
                 typename StreamEncrypter =
                     typename detail::range_stream_encrypt_traits<PublicKeyCipher, SinglePassRange>::type>
        OutputIterator encrypt(const SinglePassRange &rng, const PublicKeyRange &key, OutputIterator out) {

            typedef detail::value_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), StreamEncrypter(PublicKeyCipher(key)));
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam Encrypter
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamEncrypter
         * @param rng
         * @param out
         * @param sh
         * @return
         */
        template<typename Encrypter, typename SinglePassRange, typename OutputIterator>
        OutputIterator encrypt(const SinglePassRange &rng, const public_key<Encrypter> &pk, OutputIterator out) {

            typedef detail::ref_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::itr_encrypt_impl<Encrypter, StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(rng, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam StreamEncrypter
         * @param r
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PublicKeyRange>
        detail::range_encrypt_impl<PublicKeyCipher, detail::value_encrypt_impl<StreamEncrypter>>
            encrypt(const SinglePassRange &r, const PublicKeyRange &key) {

            typedef detail::value_encrypt_impl<StreamEncrypter> StreamEncrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, StreamEncrypter(PublicKeyCipher(key)));
        }

        /*!
         * @brief
         *
         * @addtogroup encrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam StreamHash
         * @param rng
         * @param sh
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange>
        detail::range_encrypt_impl<PublicKeyCipher, detail::ref_encrypt_impl<StreamHash>>
            encrypt(const SinglePassRange &rng, const public_key<PublicKeyCipher> &pk) {
            typedef detail::ref_encrypt_impl<StreamHash> StreamEncrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(rng, sh);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard