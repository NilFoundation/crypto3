#ifndef CRYPTO3_PUBKEY_DECRYPT_HPP
#define CRYPTO3_PUBKEY_DECRYPT_HPP

#include <nil/crypto3/pubkey/detail/stream_postprocessor.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup decrypt_algorithms Algorithms
         * @ingroup decrypt
         * @brief Algorithms are meant to provide decrypting interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamDecrypter
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator, typename PrivateKeyIterator, typename OutputIterator,
            typename StreamDecrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        OutputIterator decrypt(InputIterator first, InputIterator last, PrivateKeyIterator key_first,
                               PrivateKeyIterator key_last, OutputIterator out) {

            typedef detail::value_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(first, last, std::move(out), StreamDecrypter(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamDecrypter
         * @param first
         * @param last
         * @param out
         * @param sh
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator, typename OutputIterator,
            typename StreamDecrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        OutputIterator decrypt(InputIterator first, InputIterator last, OutputIterator out,
                               const private_key<PublicKeyCipher> &key) {

            typedef detail::ref_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(first, last, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam StreamDecrypter
         * @param first
         * @param last
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator, typename PrivateKeyIterator,
            typename StreamDecrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::value_encrypt_impl<StreamDecrypter>>
            decrypt(InputIterator first, InputIterator last, PrivateKeyIterator key_first,
                    PrivateKeyIterator key_last) {
            typedef detail::value_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last, StreamDecrypter(PublicKeyCipher(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam InputIterator
         * @tparam StreamDecrypter
         * @param first
         * @param last
         * @param sh
         * @return
         */
        template<
            typename PublicKeyCipher, typename InputIterator,
            typename StreamDecrypter = typename detail::itr_stream_encrypt_traits<PublicKeyCipher, InputIterator>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::ref_encrypt_impl<StreamDecrypter>>
            decrypt(InputIterator first, InputIterator last, const private_key<PublicKeyCipher> &key) {
            typedef detail::ref_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(first, last, sh);
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamDecrypter
         * @param rng
         * @param out
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PrivateKeyRange, typename OutputIterator,
                 typename StreamDecrypter =
                     typename detail::range_stream_encrypt_traits<PublicKeyCipher, SinglePassRange>::type>
        OutputIterator decrypt(const SinglePassRange &rng, const PrivateKeyRange &key, OutputIterator out) {

            typedef detail::value_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::itr_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out), StreamDecrypter(PublicKeyCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam Decrypter
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamDecrypter
         * @param rng
         * @param out
         * @param sh
         * @return
         */
        template<
            typename Decrypter, typename SinglePassRange, typename OutputIterator,
            typename StreamDecrypter = typename detail::range_stream_encrypt_traits<Decrypter, SinglePassRange>::type>
        OutputIterator decrypt(const SinglePassRange &rng, OutputIterator out, StreamDecrypter &sh) {

            typedef detail::ref_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::itr_encrypt_impl<Decrypter, StreamDecrypterImpl, OutputIterator> DecrypterImpl;

            return DecrypterImpl(rng, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam StreamDecrypter
         * @param r
         * @return
         */
        template<typename PublicKeyCipher, typename SinglePassRange, typename PrivateKeyRange,
                 typename StreamDecrypter =
                     typename detail::range_stream_encrypt_traits<PublicKeyCipher, SinglePassRange>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::value_encrypt_impl<StreamDecrypter>>
            decrypt(const SinglePassRange &r, const PrivateKeyRange &key) {

            typedef detail::value_encrypt_impl<StreamDecrypter> StreamDecrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(r, StreamDecrypter(PublicKeyCipher(key)));
        }

        /*!
         * @brief
         *
         * @ingroup decrypt_algorithms
         *
         * @tparam PublicKeyCipher
         * @tparam SinglePassRange
         * @tparam StreamHash
         * @param rng
         * @param sh
         * @return
         */
        template<
            typename PublicKeyCipher, typename SinglePassRange,
            typename StreamHash = typename detail::range_stream_encrypt_traits<PublicKeyCipher, SinglePassRange>::type>
        detail::range_encrypt_impl<PublicKeyCipher, detail::ref_encrypt_impl<StreamHash>>
            decrypt(const SinglePassRange &rng, StreamHash &sh) {
            typedef detail::ref_encrypt_impl<StreamHash> StreamDecrypterImpl;
            typedef detail::range_encrypt_impl<PublicKeyCipher, StreamDecrypterImpl> DecrypterImpl;

            return DecrypterImpl(rng, sh);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
