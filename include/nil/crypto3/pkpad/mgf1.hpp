//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MGF1_HPP
#define CRYPTO3_MGF1_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {

                /*!
                 * @brief MGF1 from PKCS #1 v2.0
                 * @tparam Hash Hash function type to use
                 * @tparam InputIterator Input buffer iterator type
                 * @tparam OutputIterator Output buffer iterator type
                 * @param first Input buffer first iterator
                 * @param last Input buffer last iterator
                 * @param out Output buffer first iterator
                 * @param sh Stream hash function instance
                 */
                template<
                    typename Hash, typename InputIterator, typename OutputIterator,
                    typename StreamHash = typename Hash::template stream_hash<
                        std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                        std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type>
                OutputIterator mgf1_mask(InputIterator first, InputIterator last, OutputIterator out,
                                         StreamHash sh = StreamHash()) {
                    typename Hash::digest_type result;

                    while (out) {
                        sh.update(first, last);
                        result = sh.end_message();

                        out =
                            std::transform(result.begin(), result.end(), out,
                                           [&](const typename Hash::digest_type::value_type &v) { *out++ = v ^ *out; });
                    }

                    return out;
                }
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif
