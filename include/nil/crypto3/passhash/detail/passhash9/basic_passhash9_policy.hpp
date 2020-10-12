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

#ifndef CRYPTO3_PASSHASH_BASIC_PASSHASH9_POLICY_HPP
#define CRYPTO3_PASSHASH_BASIC_PASSHASH9_POLICY_HPP

#include <cstdlib>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            namespace detail {
                template<typename MessageAuthenticationCode, std::size_t Workfactor, typename ParamsType>
                struct basic_passhash9_policy {
                    typedef MessageAuthenticationCode mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };
            }    // namespace detail
        }        // namespace passhash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PASSHASH9_POLICY_HPP
