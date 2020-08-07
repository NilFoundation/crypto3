//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SCHEME_MODE_RFC6979_HPP
#define CRYPTO3_SCHEME_MODE_RFC6979_HPP

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pkpad/emsa.hpp>

#include <nil/crypto3/pubkey/agreement_key.hpp>

#include <nil/crypto3/pubkey/detail/nonce_generator.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Scheme, typename Padding>
                struct rfc6979_policy {
                    typedef std::size_t size_type;

                    typedef Scheme scheme_type;
                    typedef Padding padding_type;
                };

                template<typename Scheme, typename Padding>
                struct rfc6979_agreement_policy : public rfc6979_policy<Scheme, Padding> {
                    typedef typename rfc6979_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename rfc6979_policy<Scheme, Padding>::number_type number_type;

                    typedef agreement_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::agree(key, plaintext);
                    }
                };

                template<typename Scheme, typename Padding>
                struct rfc6979_signing_policy : public rfc6979_policy<Scheme, Padding> {
                    typedef typename rfc6979_policy<Scheme, Padding>::scheme_type scheme_type;
                    typedef typename rfc6979_policy<Scheme, Padding>::number_type number_type;

                    typedef private_key<scheme_type> key_type;

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return scheme_type::sign<detail::nonce_generator<typename Padding::hash_type>>(key, plaintext);
                    }
                };

                template<typename Policy>
                class rfc6979 {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    typedef typename policy_type::policy_type scheme_type;
                    typedef typename policy_type::padding_type padding_type;

                    typedef typename scheme_type::key_type key_type;

                    rfc6979(const scheme_type &scheme) : scheme(scheme) {
                    }

                    inline static number_type process(const key_type &key, const number_type &plaintext) {
                        return policy_type::process(key, plaintext);
                    }

                protected:
                    scheme_type scheme;
                };
            }    // namespace detail

            namespace modes {
                template<typename Scheme, template<typename> class Padding>
                struct rfc6979 {
                    BOOST_STATIC_ASSERT_MSG(std::is_same<Padding, emsa>::value,
                                  "RFC6979 nonce initialization is only defined "
                                  "for EMSA-compliant usage");
                };

                template<typename Scheme, typename Hash>
                struct rfc6979<Scheme, emsa<Hash>> {
                    typedef Scheme scheme_type;
                    typedef emsa<Hash> padding_type;

                    typedef detail::rfc6979_signing_policy<scheme_type, padding_type> signing_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::rfc6979<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHER_MODES_HPP
