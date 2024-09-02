//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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
