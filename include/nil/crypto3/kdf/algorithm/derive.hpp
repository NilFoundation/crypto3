#ifndef CRYPTO3_KDF_HPP
#define CRYPTO3_KDF_HPP

#include <nil/crypto3/kdf/kdf_value.hpp>
#include <nil/crypto3/kdf/kdf_state.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @defgroup kdf Key Derivation Functions
             *
             * @brief Key derivation function (KDF) derives one or more secret keys
             * from a secret value such as a master key, a password, or a passphrase
             * using a pseudorandom function. KDFs can be used to stretch keys into
             * longer keys or to obtain keys of a required format, such as converting
             * a group element that is the result of a Diffie–Hellman key exchange
             * into a symmetric key for use with AES. Keyed cryptographic hash
             * functions are popular examples of pseudorandom functions used for key
             * derivation.
             *
             * @defgroup kdf_algorithms Algorithms
             * @ingroup kdf
             * @brief Algorithms are meant to provide key derivation interface similar to STL algorithms' one.
             */

            /*!
             * @brief
             *
             * @ingroup kdf_algorithms
             *
             * @tparam Kdf
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam StreamKdf
             * @param first
             * @param last
             * @param out
             * @param sh
             * @return
             */
            template<typename Kdf, typename InputIterator, typename OutputIterator>
            typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                    OutputIterator>::type
                derive(InputIterator first, InputIterator last, OutputIterator out) {
            }

            /*!
             * @brief
             *
             * @ingroup kdf_algorithms
             *
             * @tparam Kdf
             * @tparam InputIterator
             * @tparam StreamKdf
             * @param first
             * @param last
             * @param sh
             * @return
             */
            template<typename Kdf, typename InputIterator, typename KdfAccumulator = typename kdf::accumulator_set<Kdf>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<KdfAccumulator>::value,
                                    KdfAccumulator>::type &
                derive(InputIterator first, InputIterator last, KdfAccumulator &acc) {
            }

            /*!
             * @brief
             *
             * @ingroup kdf_algorithms
             *
             * @tparam Kdf
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam StreamKdf
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Kdf, typename SinglePassRange, typename OutputIterator>
            OutputIterator derive(const SinglePassRange &rng, OutputIterator out) {
            }

            /*!
             * @brief
             *
             * @ingroup kdf_algorithms
             *
             * @tparam Kdf
             * @tparam SinglePassRange
             * @tparam StreamKdf
             * @param rng
             * @param sh
             * @return
             */
            template<typename Kdf, typename SinglePassRange,
                     typename KdfAccumulator = typename kdf::accumulator_set<Kdf>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<KdfAccumulator>::value,
                                    KdfAccumulator>::type &
                derive(const SinglePassRange &rng, KdfAccumulator &kdf) {
            }
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KDF_HPP
