//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_SECRET_SHARING_HPP
#define CRYPTO3_PUBKEY_SECRET_SHARING_HPP

#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename PubkeyScheme, template<typename Group> SecretSharingScheme>
                struct secret_sharing_scheme_policy {
                    typedef PubkeyScheme pubkey_scheme_type;
                    typedef typename pubkey_scheme_type::signature_type signature_type;
                    typedef typename signature_type::group_type group_type;
                    typedef SecretSharingScheme<group_type> scheme_type;
                };

                template<typename PubkeyScheme, template<typename Group> SecretSharingScheme>
                struct secret_sharing_policy : secret_sharing_scheme_policy<PubkeyScheme, SecretSharingScheme> {
                    typedef secret_sharing_policy<PubkeyScheme, SecretSharingScheme> policy_type;
                    typedef policy_type::pubkey_scheme_type pubkey_scheme_type;
                    typedef policy_type::scheme_type scheme_type;

                    typedef std::vector<private_key<pubkey_scheme_type>> result_type;

                    template<typename... Args>
                    static inline result_type process(const Args &...args) {
                        auto secrets = scheme_type::deal_shares(args...);
                        result_type result;
                        for (const auto &s : secrets) {
                            result.emplace_back(s);
                        }
                        return result;
                    }
                };

                template<typename PubkeyScheme, template<typename Group> SecretSharingScheme>
                struct secret_reconstructing_policy : secret_sharing_scheme_policy<PubkeyScheme, SecretSharingScheme> {
                    typedef secret_sharing_policy<PubkeyScheme, SecretSharingScheme> policy_type;
                    typedef policy_type::pubkey_scheme_type pubkey_scheme_type;
                    typedef policy_type::scheme_type scheme_type;

                    typedef private_key<pubkey_scheme_type> result_type;
                };

                template<typename PubkeyScheme, template<typename Group> SecretSharingScheme>
                struct secret_verification_policy : secret_sharing_scheme_policy<PubkeyScheme, SecretSharingScheme> {
                    typedef secret_sharing_policy<PubkeyScheme, SecretSharingScheme> policy_type;
                    typedef policy_type::pubkey_scheme_type pubkey_scheme_type;
                    typedef policy_type::scheme_type scheme_type;

                    typedef public_key<pubkey_scheme_type> pubkey_type;

                    typedef bool result_type;

                    template<typename... Args>
                    static inline result_type process(const pubkey_type &pubkey, const Args &...args) {
                        return pubkey.verify_share(args...);
                    }
                };
            }    // namespace detail

            template<typename PubkeyScheme, template<typename Group> SecretSharingScheme>
            struct secret_sharing_scheme : detail::secret_sharing_scheme_policy<PubkeyScheme, SecretSharingScheme> {
                typedef secret_sharing_policy<PubkeyScheme, SecretSharingScheme> policy_type;
                typedef policy_type::scheme_type scheme_type;

                typedef detail::secret_sharing_policy<PubkeyScheme, SecretSharingScheme> sharing_policy;
                typedef detail::secret_reconstructing_policy<PubkeyScheme, SecretSharingScheme> reconstructing_policy;
                typedef typename detail::secret_verification_policy<PubkeyScheme, SecretSharingScheme> verification_policy;
            };


        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SECRET_SHARING_HPP
