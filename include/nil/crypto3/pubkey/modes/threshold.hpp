//---------------------------------------------------------------------------//
// Copyright (c) 2019-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_THRESHOLD_SCHEME_MODE_HPP
#define CRYPTO3_PUBKEY_THRESHOLD_SCHEME_MODE_HPP

#include <nil/crypto3/pubkey/agreement_key.hpp>

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
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::sign(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct threshold_verification_policy : public threshold_policy<Scheme, Padding> {
                    typedef typename threshold_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename threshold_policy<Scheme, Padding>::number_type number_type;

                    typedef public_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::verify(key, plaintext);
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
                template<typename Scheme, template<typename> class Padding>
                struct threshold {
                    typedef Scheme scheme_type;
                    typedef Padding<Scheme> padding_type;

                    typedef detail::threshold_agreement_policy<scheme_type, padding_type> agreement_policy;
                    typedef detail::threshold_encryption_policy<scheme_type, padding_type> encryption_policy;
                    typedef detail::threshold_decryption_policy<scheme_type, padding_type> decryption_policy;
                    typedef detail::threshold_signing_policy<scheme_type, padding_type> signing_policy;
                    typedef detail::threshold_verification_policy<scheme_type, padding_type> verification_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::threshold<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MODE_HPP
