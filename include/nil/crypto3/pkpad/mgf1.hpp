#ifndef CRYPTO3_MGF1_HPP
#define CRYPTO3_MGF1_HPP

#include <nil/crypto3/utilities/types.hpp>

namespace nil {
    namespace crypto3 {

        /*!
         * @brief MGF1 from PKCS #1 v2.0
         * @tparam Hasher Hash function type to use
         * @tparam InputIterator Input buffer iterator type
         * @tparam OutputIterator Output buffer iterator type
         * @param first Input buffer first iterator
         * @param last Input buffer last iterator
         * @param out Output buffer first iterator
         * @param sh Stream hash function instance
         */
        template<typename Hasher, typename InputIterator, typename OutputIterator,
                 typename StreamHasher = typename Hasher::template stream_hash<
                     std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                     std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type>
        OutputIterator mgf1_mask(InputIterator first, InputIterator last, OutputIterator out,
                                 StreamHasher sh = StreamHasher()) {
            typename Hasher::digest_type result;

            while (out) {
                sh.update(first, last);
                result = sh.end_message();

                out = std::transform(result.begin(), result.end(), out,
                                     [&](const typename Hasher::digest_type::value_type &v) { *out++ = v ^ *out; });
            }

            return out;
        }
    }    // namespace crypto3
}    // namespace nil

#endif
