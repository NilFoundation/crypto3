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

#ifndef CRYPTO3_PUBKEY_NO_KEY_HPP
#define CRYPTO3_PUBKEY_NO_KEY_HPP

#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            struct no_key {
                typedef Scheme scheme_type;
                typedef no_key<scheme_type> self_type;
                typedef typename scheme_type::no_key_policy_type no_key_policy_type;

                constexpr static const auto input_block_bits = no_key_policy_type::input_block_bits;
                typedef typename no_key_policy_type::input_block_type input_block_type;

                constexpr static const auto input_value_bits = no_key_policy_type::input_value_bits;
                typedef typename no_key_policy_type::input_value_type input_value_type;

                typedef typename no_key_policy_type::signature_type signature_type;

                template<typename SignatureRange>
                static inline signature_type aggregate(const SignatureRange &sigs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SignatureRange>));

                    return no_key_policy_type::aggregate(sigs);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_NO_KEY_HPP
