//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_KDF_PRF_X942_FUNCTIONS_HPP
#define CRYPTO3_KDF_PRF_X942_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/prf_x942/prf_x942_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct prf_x942_functions : public prf_x942_policy<Hash> {
                    typedef prf_x942_policy<Hash> policy_type;

                    typedef typename policy_type::hash_type hash_type;

                    std::vector<uint8_t> encode_x942_int(uint32_t n) {
                        uint8_t n_buf[4] = {0};
                        store_be(n, n_buf);
                        return der_encoder().encode(n_buf, 4, OCTET_STRING).get_contents_unlocked();
                    }
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
