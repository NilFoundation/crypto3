//---------------------------------------------------------------------------//
// Copyright (c) 2019-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP
#define CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP

#include <nil/crypto3/pubkey/modes/detail/threshold_scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, typename Padding>
                struct threshold_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                    typedef Padding padding_type;
                };

                template<typename Scheme, typename Padding>
                struct threshold_agreement_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::number_type number_type;

                    typedef agreement_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::agree(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_encryption_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::encrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_decryption_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::decrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_signing_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::threshold_scheme_type
                        threshold_scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef private_key<scheme_type> key_type;

                    typedef typename key_type::signature_type result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key_type::sign(key, args...);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_verification_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::threshold_scheme_type
                        threshold_scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef public_key<scheme_type> key_type;

                    typedef bool result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key_type::verify(key, args...);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_part_verification_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::threshold_scheme_type
                        threshold_scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef public_key<scheme_type> key_type;

                    typedef bool result_type;

                    template<typename... Args>
                    inline static result_type process(const key_type &key, const Args &...args) {
                        return key_type::part_verify(key, args...);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_aggregation_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::threshold_scheme_type
                        threshold_scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;

                    typedef typename scheme_type::signature_type result_type;

                    template<typename... Args>
                    inline static result_type process(const Args &...args) {
                        return threshold_scheme_type::aggregate(args...);
                    }
                };

                template<typename Policy>
                class threshold {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    typedef typename policy_type::policy_type scheme_type;
                    typedef typename policy_type::padding_type padding_type;

                    typedef typename scheme_type::key_type key_type;

                    threshold(const scheme_type &cipher) : cipher(cipher) {
                    }

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return policy_type::process(key, plaintext);
                    }

                protected:
                    scheme_type cipher;
                };
            }    // namespace detail

            namespace modes {
                template<typename Scheme, template<typename> class SecretSharingScheme, template<typename> class Padding>
                struct threshold {
                    typedef Scheme base_scheme_type;
                    typedef typename detail::threshold_scheme<base_scheme_type, SecretSharingScheme>::type scheme_type;
                    typedef Padding<Scheme> padding_type;

                    typedef detail::threshold_agreement_policy<scheme_type, padding_type> agreement_policy;
                    typedef detail::threshold_encryption_policy<scheme_type, padding_type> encryption_policy;
                    typedef detail::threshold_decryption_policy<scheme_type, padding_type> decryption_policy;
                    typedef detail::threshold_signing_policy<scheme_type, padding_type>
                        signing_policy;
                    typedef detail::threshold_part_verification_policy<scheme_type, padding_type>
                        part_verification_policy;
                    typedef detail::threshold_verification_policy<scheme_type, padding_type>
                        verification_policy;
                    typedef detail::threshold_aggregation_policy<scheme_type, padding_type>
                        aggregation_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::threshold<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_THRESHOLD_MODE_HPP
