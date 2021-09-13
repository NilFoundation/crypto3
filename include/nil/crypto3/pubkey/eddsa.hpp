//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_EDDSA_HPP
#define CRYPTO3_PUBKEY_EDDSA_HPP

#include <array>

#include <nil/crypto3/algebra/curves/curve25529.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include <nil/crypto3/pkpad/emsa/emsa_raw.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            enum class EddsaVariant { basic, ph, ctx };

            template<typename CurveGroup, EddsaVariant>
            struct eddsa_policy;

            template<>
            struct eddsa_policy<algebra::curves::curve25519::template g1_type<
                                    algebra::coordinates::extended_with_a_minus_1, algebra::forms::twisted_edwards>,
                                EddsaVariant::basic> { };

            template<>
            struct eddsa_policy<algebra::curves::curve25519::template g1_type<
                                    algebra::coordinates::extended_with_a_minus_1, algebra::forms::twisted_edwards>,
                                EddsaVariant::ph> { };

            template<>
            struct eddsa_policy<algebra::curves::curve25519::template g1_type<
                                    algebra::coordinates::extended_with_a_minus_1, algebra::forms::twisted_edwards>,
                                EddsaVariant::ctx> { };

            template<typename CurveGroup, EddsaVariant eddsa_variant, typename Params>
            struct eddsa {

            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_EDDSA_HPP
