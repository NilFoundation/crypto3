//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP
#define CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/detail/bls/bls_basic_key_policy.hpp>

#include <cstdint>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename CurveType, typename SignatureHash>
                struct bls_functions {
                    typedef detail::bls_basic_key_policy<CurveType, SignatureHash> basic_key_policy_type;

                    typedef typename basic_key_policy_type::number_type number_type;
                    typedef typename basic_key_policy_type::private_key_type private_key_type;

                    template<typename SeedType>
                    inline static private_key_type key_gen_impl(const SeedType &seed) {
                        // "BLS-SIG-KEYGEN-SALT-"
                        std::array<uint8_t, 20> salt = {66, 76, 83, 45, 83, 73, 71, 45, 75, 69,
                                                        89, 71, 69, 78, 45, 83, 65, 76, 84, 45};
                        number_type sk(0);
                        // TODO: will work when hkdf finished
                        while (sk != 0) {
                            salt = hash<hashes::sha2<512>>(salt);
                            sk = hkdf_extract_expand(salt, seed);
                        }
                        return key_type(sk);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PUBKEY_BLS_FUNCTIONS_HPP
