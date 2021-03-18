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
#include <iterator>
#include <utility>
#include <unordered_map>

#include <boost/container_hash/hash.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            struct _public_key {
                typedef Scheme scheme_type;
                typedef _public_key<scheme_type> self_type;
                typedef typename scheme_type::public_key_policy_type public_key_policy_type;

                typedef typename public_key_policy_type::public_key_type public_key_type;
                typedef typename public_key_policy_type::private_key_type private_key_type;
                typedef typename public_key_policy_type::signature_type signature_type;
                typedef typename public_key_policy_type::public_params public_params;
                typedef typename public_key_policy_type::pubkey_id_type pubkey_id_type;

                constexpr static const auto input_block_bits = public_key_policy_type::input_block_bits;
                typedef typename public_key_policy_type::input_block_type input_block_type;

                constexpr static const auto input_value_bits = public_key_policy_type::input_value_bits;
                typedef typename public_key_policy_type::input_value_type input_value_type;

                typedef std::unordered_map<pubkey_id_type, std::pair<self_type, input_block_type>,
                                           boost::hash<pubkey_id_type>>
                    aggregate_verification_type;

                // typedef bool result_type;

                _public_key(const public_key_type &key, const public_params &pp) :
                    pubkey(key), pp(pp), pubkey_id(public_key_policy_type::get_id(pubkey)) {
                }

                _public_key(const public_key_type &key, const public_params &pp, const signature_type &signature) :
                    pubkey(key), pp(pp), sig(signature), pubkey_id(public_key_policy_type::get_id(pubkey)) {
                }

                inline bool verify(const aggregate_verification_type &in_data) const {
                    assert(!in_data.empty());

                    if (in_data.size() == 1) {
                        return public_key_policy_type::verify(in_data.cbegin()->second.second, pubkey, sig, pp);
                    } else {
                        std::vector<public_key_type> pubkeys;
                        std::vector<input_block_type> msgs;
                        for (const auto &[key, value] : in_data) {
                            pubkeys.emplace_back(value.first.pubkey);
                            msgs.emplace_back(value.second);
                        }
                        return public_key_policy_type::aggregate_verify(msgs, pubkeys, sig, pp);
                    }
                }

                inline void set_signature(const signature_type &signature) {
                    sig = signature;
                }

                template<typename InputIterator,
                         typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                         typename = typename std::enable_if<std::is_same<input_value_type, ValueType>::value>::type>
                inline void append_aggregated_msg(aggregate_verification_type &agg_data, InputIterator first,
                                                  InputIterator last) const {
                    if (!agg_data.count(pubkey_id)) {
                        agg_data.emplace(pubkey_id, std::make_pair(*this, input_block_type(first, last)));
                    } else {
                        std::copy(first, last, std::back_inserter(agg_data.at(pubkey_id).second));
                    }
                }

                template<
                    typename SinglePassRange,
                    typename ValueType = typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                    typename = typename std::enable_if<std::is_same<input_value_type, ValueType>::value>::type>
                inline void append_aggregated_msg(aggregate_verification_type &agg_data,
                                                  const SinglePassRange &block) const {
                    append_aggregated_msg(agg_data, block.begin(), block.end());
                }

                inline void append_aggregated_msg(aggregate_verification_type &agg_data,
                                                  const input_value_type &value) const {
                    if (!agg_data.count(pubkey_id)) {
                        agg_data.emplace(pubkey_id, std::make_pair(*this, input_block_type()));
                    }
                    agg_data.at(pubkey_id).second.emplace_back(value);
                }

                inline const public_key_type &get_raw_pubkey() const {
                    return pubkey;
                }

                inline const pubkey_id_type &get_pubkey_id() const {
                    return pubkey_id;
                }

                public_key_type pubkey;
                signature_type sig;
                public_params pp;
                pubkey_id_type pubkey_id;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_PUBLIC_KEY_HPP
