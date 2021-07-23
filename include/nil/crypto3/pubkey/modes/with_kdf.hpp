//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_SCHEME_MODES_WITH_KDF_HPP
#define CRYPTO3_SCHEME_MODES_WITH_KDF_HPP

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/pubkey/agreement_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, typename Padding>
                struct with_kdf_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                    typedef Padding padding_type;
                };

                template<typename Scheme, typename Padding>
                struct with_kdf_agreement_policy : public with_kdf_policy<Scheme, Padding> {
                    typedef typename with_kdf_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename with_kdf_policy<Scheme, Padding>::number_type number_type;

                    typedef agreement_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::agree(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct with_kdf_encryption_policy : public with_kdf_policy<Scheme, Padding> {
                    typedef typename with_kdf_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename with_kdf_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::encrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct with_kdf_decryption_policy : public with_kdf_policy<Scheme, Padding> {
                    typedef typename with_kdf_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename with_kdf_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::decrypt(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct with_kdf_signing_policy : public with_kdf_policy<Scheme, Padding> {
                    typedef typename with_kdf_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename with_kdf_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::sign(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct with_kdf_verification_policy : public with_kdf_policy<Scheme, Padding> {
                    typedef typename with_kdf_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename with_kdf_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::verify(key, plaintext);
                    }
                };

                template<typename Policy>
                class with_kdf {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    typedef typename policy_type::policy_type scheme_type;
                    typedef typename policy_type::padding_type padding_type;

                    typedef typename scheme_type::key_type key_type;

                    with_kdf(const scheme_type &cipher) : cipher(cipher) {
                    }

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return policy_type::process(key, plaintext);
                    }

                protected:
                    scheme_type cipher;
                };
            }    // namespace detail

            namespace modes {
                template<typename Scheme, template<typename> class Padding>
                struct with_kdf {
                    typedef Scheme scheme_type;
                    typedef Padding<Scheme> padding_type;

                    typedef detail::with_kdf_agreement_policy<scheme_type, padding_type> agreement_policy;
                    typedef detail::with_kdf_encryption_policy<scheme_type, padding_type> encryption_policy;
                    typedef detail::with_kdf_decryption_policy<scheme_type, padding_type> decryption_policy;
                    typedef detail::with_kdf_signing_policy<scheme_type, padding_type> signing_policy;
                    typedef detail::with_kdf_verification_policy<scheme_type, padding_type> verification_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::with_kdf<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHER_MODES_HPP
