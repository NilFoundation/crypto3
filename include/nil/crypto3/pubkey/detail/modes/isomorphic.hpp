//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_SCHEME_MODES_HPP
#define CRYPTO3_SCHEME_MODES_HPP

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/pubkey/agreement_key.hpp>
#include <nil/crypto3/pubkey/no_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, typename Padding>
                struct isomorphic_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                    typedef Padding padding_type;
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_agreement_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename isomorphic_policy<Scheme, Padding>::number_type number_type;

                    typedef agreement_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::agree(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_encryption_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename isomorphic_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::encrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_decryption_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename isomorphic_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::decrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_signing_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef private_key<scheme_type> key_type;

                    constexpr static const auto input_block_bits = key_type::input_block_bits;
                    typedef typename key_type::input_block_type input_block_type;

                    constexpr static const auto input_value_bits = key_type::input_value_bits;
                    typedef typename key_type::input_value_type input_value_type;

                    typedef typename key_type::signature_type result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key.sign(args...);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_verification_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef public_key<scheme_type> key_type;

                    constexpr static const auto input_block_bits = key_type::input_block_bits;
                    typedef typename key_type::input_block_type input_block_type;

                    constexpr static const auto input_value_bits = key_type::input_value_bits;
                    typedef typename key_type::input_value_type input_value_type;

                    typedef bool result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key.verify(args...);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_aggregation_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef no_key<Scheme> key_type;

                    constexpr static const auto input_block_bits = key_type::input_block_bits;
                    typedef typename key_type::input_block_type input_block_type;

                    constexpr static const auto input_value_bits = key_type::input_value_bits;
                    typedef typename key_type::input_value_type input_value_type;

                    typedef typename key_type::signature_type result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key.aggregate(args...);
                    }
                };

                template<typename Policy>
                class isomorphic {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::scheme_type scheme_type;
                    typedef typename policy_type::padding_type padding_type;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const auto input_block_bits = policy_type::input_block_bits;
                    typedef typename policy_type::input_block_type input_block_type;

                    constexpr static const auto input_value_bits = policy_type::input_value_bits;
                    typedef typename policy_type::input_value_type input_value_type;

                    typedef typename policy_type::result_type result_type;

                    template<typename... Args>
                    inline static result_type process(const Args &...args) {
                        return policy_type::process(args...);
                    }
                };
            }    // namespace detail

            namespace modes {
                /*!
                 * @defgroup scheme_modes Scheme Modes
                 * @brief
                 *
                 * @defgroup pubkey_scheme_modes Public Key Cryptography Schemes Modes
                 * @ingroup scheme_modes
                 * @brief
                 */

                /*!
                 * @brief
                 * @tparam Scheme
                 * @tparam Padding
                 */
                template<typename Scheme, template<typename> class Padding>
                struct isomorphic {
                    typedef Scheme scheme_type;
                    typedef Padding<Scheme> padding_type;

                    typedef detail::isomorphic_agreement_policy<scheme_type, padding_type> agreement_policy;
                    typedef detail::isomorphic_encryption_policy<scheme_type, padding_type> encryption_policy;
                    typedef detail::isomorphic_decryption_policy<scheme_type, padding_type> decryption_policy;
                    typedef detail::isomorphic_signing_policy<scheme_type, padding_type> signing_policy;
                    typedef detail::isomorphic_verification_policy<scheme_type, padding_type> verification_policy;
                    typedef detail::isomorphic_aggregation_policy<scheme_type, padding_type> aggregation_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::isomorphic<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHER_MODES_HPP
