//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PASSHASH_BCRYPT_FUNCTIONS_HPP
#define CRYPTO3_PASSHASH_BCRYPT_FUNCTIONS_HPP

#include <nil/crypto3/passhash/detail/bcrypt/bcrypt_policy.hpp>

#include <nil/crypto3/codec/base.hpp>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            namespace detail {
                template<typename BlockCipher>
                struct bcrypt_functions : public bcrypt_policy<BlockCipher> {
                    typedef bcrypt_policy<BlockCipher> policy_type;

                    typedef typename policy_type::cipher_type cipher_type;

                    std::string bcrypt_base64_encode(const uint8_t input[], size_t length) {
                        std::string b64 = base64_encode(input, length);

                        while (!b64.empty() && b64[b64.size() - 1] == '=') {
                            b64 = b64.substr(0, b64.size() - 1);
                        }

                        for (size_t i = 0; i != b64.size(); ++i) {
                            b64[i] = policy_type::substitution()[static_cast<uint8_t>(b64[i])];
                        }

                        return b64;
                    }

                    std::vector<uint8_t> bcrypt_base64_decode(const std::string& input) {
                        for (size_t i = 0; i != input.size(); ++i) {
                            input[i] = policy_type::inverted_substitution()[static_cast<uint8_t>(input[i])];
                        }

                        return unlock(base64_decode(input));
                    }
                };
            }    // namespace detail
        }        // namespace passhash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BCRYPT_FUNCTIONS_HPP
