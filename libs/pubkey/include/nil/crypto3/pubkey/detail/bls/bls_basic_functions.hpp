//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_CORE_FUNCTIONS_HPP
#define CRYPTO3_PUBKEY_BLS_CORE_FUNCTIONS_HPP

#include <utility>
#include <vector>
#include <array>
#include <type_traits>
#include <iterator>
#include <algorithm>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename policy_type>
                struct bls_basic_functions {
                    typedef typename policy_type::curve_type curve_type;
                    typedef typename policy_type::gt_value_type gt_value_type;
                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;
                    typedef typename policy_type::h2c_policy h2c_policy;

                    typedef typename policy_type::bls_serializer bls_serializer;
                    typedef typename policy_type::public_key_serialized_type public_key_serialized_type;
                    typedef typename policy_type::signature_serialized_type signature_serialized_type;

                    typedef typename policy_type::internal_accumulator_type internal_accumulator_type;
                    typedef std::pair<std::vector<public_key_type>, std::vector<internal_accumulator_type>>
                        internal_aggregation_accumulator_type;
                    typedef std::pair<std::vector<public_key_type>, internal_accumulator_type>
                        internal_fast_aggregation_accumulator_type;

                    constexpr static const std::size_t private_key_bits = policy_type::private_key_bits;
                    constexpr static const std::size_t L = static_cast<std::size_t>((3 * private_key_bits) / 16) +
                                                           static_cast<std::size_t>((3 * private_key_bits) % 16 != 0);
                    static_assert(L < 0x10000, "L is required to fit in 2 octets");
                    constexpr static const std::array<std::uint8_t, 2> L_os = {static_cast<std::uint8_t>(L >> 8u),
                                                                               static_cast<std::uint8_t>(L % 0x100)};

                    // TODO: implement key_gen
                    // template<typename IkmType, typename KeyInfoType>
                    // static inline private_key_type key_gen(const IkmType &ikm, const KeyInfoType &key_info) {}

                    static inline bool validate_private_key(const private_key_type &sk) {
                        return !sk.is_zero();
                    }

                    static inline public_key_type privkey_to_pubkey(const private_key_type &sk) {
                        BOOST_ASSERT(validate_private_key(sk));

                        return sk * public_key_type::one();
                    }

                    static inline bool validate_public_key(const public_key_type &pk) {
                        return !(pk.is_zero() || !pk.is_well_formed());
                    }

                    template<typename InputRange>
                    static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputRange>));

                        hash<h2c_policy>(range, acc);
                    }

                    template<typename InputIterator>
                    static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        hash<h2c_policy>(first, last, acc);
                    }

                    static inline signature_type sign(const internal_accumulator_type &acc,
                                                      const private_key_type &sk) {
                        BOOST_ASSERT(validate_private_key(sk));

                        signature_type Q = nil::crypto3::accumulators::extract::hash<h2c_policy>(acc);
                        return sk * Q;
                    }

                    static inline bool verify(const internal_accumulator_type &acc, const public_key_type &pk,
                                              const signature_type &sig) {
                        /// check if signature point is on the curve
                        if (!sig.is_well_formed()) {
                            return false;
                        }
                        if (!validate_public_key(pk)) {
                            return false;
                        }
                        signature_type Q = nil::crypto3::accumulators::extract::hash<h2c_policy>(acc);
                        auto C1 = policy_type::pairing(Q, pk);
                        auto C2 = policy_type::pairing(sig, public_key_type::one());
                        return C1 == C2;
                    }

                    template<
                        typename SignatureIterator,
                        typename = typename std::enable_if<std::is_same<
                            signature_type, typename std::iterator_traits<SignatureIterator>::value_type>::value>::type>
                    static inline void aggregate(signature_type &acc, SignatureIterator sig_first,
                                                 SignatureIterator sig_last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SignatureIterator>));
                        assert(std::distance(sig_first, sig_last) > 0);

                        while (sig_first != sig_last) {
                            signature_type next_p = *sig_first++;
                            acc = acc + next_p;
                        }
                    }

                    template<typename SignatureRange,
                             typename = typename std::enable_if<std::is_same<
                                 signature_type, typename std::iterator_traits<
                                                     typename SignatureRange::iterator>::value_type>::value>::type>
                    static inline void aggregate(signature_type &acc, const SignatureRange &sig_n) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SignatureRange>));

                        aggregate(acc, std::cbegin(sig_n), std::cend(sig_n));
                    }

                    static inline bool aggregate_verify(const internal_aggregation_accumulator_type &acc,
                                                        const signature_type &sig) {
                        const typename internal_aggregation_accumulator_type::first_type &pk_n = acc.first;
                        const typename internal_aggregation_accumulator_type::second_type &acc_n = acc.second;
                        assert(std::distance(pk_n.begin(), pk_n.end()) > 0 &&
                               std::distance(pk_n.begin(), pk_n.end()) == std::distance(acc_n.begin(), acc_n.end()));

                        if (!sig.is_well_formed()) {
                            return false;
                        }
                        auto pk_n_iter = std::cbegin(pk_n);
                        auto acc_n_iter = std::cbegin(acc_n);
                        gt_value_type C1 = gt_value_type::one();
                        while (pk_n_iter != std::cend(pk_n) && acc_n_iter != std::cend(acc_n)) {
                            if (!validate_public_key(*pk_n_iter)) {
                                return false;
                            }
                            signature_type Q = nil::crypto3::accumulators::extract::hash<h2c_policy>(*acc_n_iter++);
                            C1 = C1 * policy_type::pairing(Q, *pk_n_iter++);
                        }
                        return C1 == policy_type::pairing(sig, public_key_type::one());
                    }

                    static inline bool aggregate_verify(const internal_fast_aggregation_accumulator_type &acc,
                                                        const signature_type &sig) {
                        const typename internal_fast_aggregation_accumulator_type::first_type &pk_n = acc.first;
                        const typename internal_fast_aggregation_accumulator_type::second_type &msg_acc = acc.second;
                        assert(std::distance(pk_n.begin(), pk_n.end()) > 0);

                        auto pk_n_iter = pk_n.begin();
                        public_key_type aggregate_p = *pk_n_iter++;
                        while (pk_n_iter != pk_n.end()) {
                            public_key_type next_p = *pk_n_iter++;
                            aggregate_p = aggregate_p + next_p;
                        }
                        return verify(msg_acc, aggregate_p, sig);
                    }

                    static inline signature_type pop_prove(const private_key_type &sk) {
                        assert(validate_private_key(sk));

                        public_key_type pk = privkey_to_pubkey(sk);
                        signature_type Q = hash<h2c_policy>(point_to_pubkey(pk));
                        return sk * Q;
                    }

                    static inline bool pop_verify(const public_key_type &pk, const signature_type &pop) {
                        if (!pop.is_well_formed()) {
                            return false;
                        }
                        if (!validate_public_key(pk)) {
                            return false;
                        }
                        signature_type Q = hash<h2c_policy>(point_to_pubkey(pk));
                        auto C1 = policy_type::pairing(Q, pk);
                        auto C2 = policy_type::pairing(pop, public_key_type::one());
                        return C1 == C2;
                    }

                    static inline public_key_serialized_type point_to_pubkey(const public_key_type &pk) {
                        return bls_serializer::point_to_octets_compress(pk);
                    }

                    static inline signature_serialized_type point_to_signature(const signature_type &sig) {
                        return bls_serializer::point_to_octets_compress(sig);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_CORE_FUNCTIONS_HPP
