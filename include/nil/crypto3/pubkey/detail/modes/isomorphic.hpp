//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SCHEME_MODES_HPP
#define CRYPTO3_SCHEME_MODES_HPP

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/pubkey/agreement_key.hpp>

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
                    typedef typename isomorphic_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::sign(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct isomorphic_verification_policy : public isomorphic_policy<Scheme, Padding> {
                    typedef typename isomorphic_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename isomorphic_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::verify(key, plaintext);
                    }
                };

                template<typename Policy>
                class isomorphic {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    typedef typename policy_type::policy_type scheme_type;
                    typedef typename policy_type::padding_type padding_type;

                    typedef typename scheme_type::key_type key_type;

                    isomorphic(const scheme_type &cipher) : cipher(cipher) {
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
                struct isomorphic {
                    typedef Scheme scheme_type;
                    typedef Padding<Scheme> padding_type;

                    typedef detail::isomorphic_agreement_policy<scheme_type, padding_type> agreement_policy;
                    typedef detail::isomorphic_encryption_policy<scheme_type, padding_type> encryption_policy;
                    typedef detail::isomorphic_decryption_policy<scheme_type, padding_type> decryption_policy;
                    typedef detail::isomorphic_signing_policy<scheme_type, padding_type> signing_policy;
                    typedef detail::isomorphic_verification_policy<scheme_type, padding_type> verification_policy;

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
