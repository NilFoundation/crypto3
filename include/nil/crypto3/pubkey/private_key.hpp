//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PRIVATE_KEY_HPP
#define CRYPTO3_PRIVATE_KEY_HPP

#include <nil/crypto3/pubkey/public_key.hpp>

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            struct private_key : public public_key<Scheme> {
                typedef typename public_key<Scheme>::scheme_type scheme_type;
                typedef typename public_key<Scheme>::public_key_policy_type public_key_policy_type;
                typedef typename public_key<Scheme>::public_key_type public_key_type;

                typedef typename scheme_type::private_key_policy_type private_key_policy_type;
                typedef typename private_key_policy_type::key_type private_key_type;

                explicit private_key(const private_key_type &key) : privkey(key) {
                    this->pubkey = public_key_policy_type::key_gen(privkey);
                }

                template<typename SeedType>
                explicit private_key(const SeedType &seed) {
                    privkey = private_key_policy_type::key_gen(seed);
                    this->pubkey = public_key_policy_type::key_gen(privkey);
                }

                template<typename ...Args>
                explicit private_key(const Args&... args) {
                    privkey = private_key_policy_type::key_gen(args...);
                    this->pubkey = public_key_policy_type::key_gen(privkey);
                }

            private:
                private_key_type privkey;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PRIVATE_KEY_HPP
