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

#ifndef CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP
#define CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP

#include <cstddef>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename CurveType, typename SignatureHash>
                struct bls_basic_key_policy {
                    typedef CurveType curve_type;

                    typedef typename curve_type::number_type number_type;

                    constexpr static const std::size_t private_key_bits = curve_type::scalar_field_type::modulus_bits;
                    typedef typename curve_type::scalar_field_type::value_type private_key_type;

                    constexpr static const std::size_t public_key_bits = curve_type::g2_type::modulus_bits;
                    constexpr static const number_type pubkey_subgroup_ord = curve_type::q;
                    typedef typename curve_type::g2_type::value_type public_key_type;

                    constexpr static const std::size_t signature_bits = curve_type::g1_type::modulus_bits;
                    typedef typename curve_type::g1_type::value_type signature_type;
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP
