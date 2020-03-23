//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PASSHASH_PASSHASH9_POLICY_HPP
#define CRYPTO3_PASSHASH_PASSHASH9_POLICY_HPP

#include <cstdlib>

#include <nil/crypto3/passhash/detail/passhash9/passhash9_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            struct blowfish;
        }

        namespace hash {
            struct sha1;

            template<std::size_t Version>
            struct sha2;
        }    // namespace hash

        namespace mac {
            template<typename Hash>
            struct hmac;

            template<typename BlockCipher>
            struct cmac;
        }    // namespace mac

        namespace passhash {
            namespace detail {
                template<typename MessageAuthenticationCode, std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy : passhash9_functions<MessageAuthenticationCode, Workfactor, ParamsType> {
                    typedef MessageAuthenticationCode mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };

                template<std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy<mac::hmac<hash::sha1>, Workfactor, ParamsType>
                    : passhash9_functions<mac::hmac<hash::sha1>, Workfactor, ParamsType> {
                    typedef mac::hmac<hash::sha1> mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid = 0;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };

                template<std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy<mac::hmac<hash::sha2<256>>, Workfactor, ParamsType>
                    : passhash9_functions<mac::hmac<hash::sha2<256>>, Workfactor, ParamsType> {
                    typedef mac::hmac<hash::sha2<256>> mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid = 1;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };

                template<std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy<mac::cmac<block::blowfish>, Workfactor, ParamsType>
                    : passhash9_functions<mac::cmac<block::blowfish>, Workfactor, ParamsType> {
                    typedef mac::cmac<block::blowfish> mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid = 2;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };

                template<std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy<mac::hmac<hash::sha2<384>>, Workfactor, ParamsType>
                    : passhash9_functions<mac::hmac<hash::sha2<384>>, Workfactor, ParamsType> {
                    typedef mac::hmac<hash::sha2<384>> mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid = 3;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };

                template<std::size_t Workfactor, typename ParamsType>
                struct passhash9_policy<mac::hmac<hash::sha2<512>>, Workfactor, ParamsType>
                    : passhash9_functions<mac::hmac<hash::sha2<512>>, Workfactor, ParamsType> {
                    typedef mac::hmac<hash::sha2<512>> mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t algid = 4;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };
            }    // namespace detail
        }        // namespace passhash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PASSHASH9_POLICY_HPP
