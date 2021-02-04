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

#ifndef CRYPTO3_PUBKEY_PUBLIC_KEY_HPP
#define CRYPTO3_PUBKEY_PUBLIC_KEY_HPP

#include <vector>
#include <type_traits>

#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            struct public_key {
                typedef Scheme scheme_type;
                typedef public_key<scheme_type> self_type;
                typedef typename scheme_type::public_key_policy_type public_key_policy_type;

                typedef typename public_key_policy_type::public_key_type public_key_type;
                typedef typename public_key_policy_type::private_key_type private_key_type;
                typedef typename public_key_policy_type::signature_type signature_type;
                typedef typename public_key_policy_type::public_params public_params;

                constexpr static const auto input_block_bits = public_key_policy_type::input_block_bits;
                typedef typename public_key_policy_type::input_block_type input_block_type;

                constexpr static const auto input_value_bits = public_key_policy_type::input_value_bits;
                typedef typename public_key_policy_type::input_value_type input_value_type;

                typedef bool result_type;

                typedef std::vector<public_key_type> public_keys_type;

                public_key(const public_key_type &key, const public_params &pp) : pp(pp) {
                    pubkeys.emplace_back(key);
                }

                public_key(const public_key_type &key, const signature_type &signature, const public_params &pp) :
                    pp(pp), sig(signature) {
                    pubkeys.emplace_back(key);
                }

                template<typename PubkeyRange>
                public_key(const PubkeyRange &keys, const public_params &pp) : pp(pp) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PubkeyRange>));

                    for (const auto &key : keys) {
                        pubkeys.emplace_back(key);
                    }
                }

                template<typename PubkeyRange>
                public_key(const PubkeyRange &keys, const signature_type &signature, const public_params &pp) :
                    pp(pp), sig(signature) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PubkeyRange>));

                    for (const auto &key : keys) {
                        pubkeys.emplace_back(key);
                    }
                }

                template<typename MsgType>
                inline bool verify(const MsgType &msg) const {
                    return public_key_policy_type::verify(msg, pubkeys.front(), sig, pp);
                }

                template<typename MsgRange>
                inline bool aggregate_verify(const MsgRange &msgs) {
                    return public_key_policy_type::aggregate_verify(msgs, pubkeys, sig, pp);
                }

                inline void set_signature(const signature_type &signature) {
                    sig = signature;
                }

                public_keys_type pubkeys;
                signature_type sig;
                public_params pp;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_PUBLIC_KEY_HPP
