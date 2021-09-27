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

#ifndef CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
#define CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP

#include <nil/crypto3/pubkey/secret_sharing/feldman.hpp>
#include <nil/crypto3/pubkey/operations/deal_share_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            //
            // "A threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
            // https://dl.acm.org/citation.cfm?id=1754929
            //
            template<typename Group>
            struct pedersen_dkg : feldman_sss<Group> {
                typedef feldman_sss<Group> base_type;
                typedef typename base_type::share_type share_type;

                // typedef typename base_type::private_element_type private_element_type;
                // typedef typename base_type::public_element_type public_element_type;
                //
                // template<typename Shares,
                //          typename base_type::template check_indexed_private_element_type<
                //              typename std::iterator_traits<typename Shares::iterator>::value_type> = true>
                // static inline share_type deal_share(const Shares &shares) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                //     return deal_share(shares.begin(), shares.end());
                // }
                //
                // template<typename SharesIterator,
                //          typename base_type::template check_indexed_private_element_type<
                //              typename std::iterator_traits<SharesIterator>::value_type> = true>
                // static inline share_type deal_share(SharesIterator first, SharesIterator last) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIterator>));
                //     auto n = std::distance(first, last);
                //     assert(base_type::check_minimal_size(n));
                //     auto index = first->first;
                //     assert(base_type::check_participant_index(index, n));
                //
                //     private_element_type share = private_element_type::zero();
                //     for (auto it = first; it != last; it++) {
                //         assert(index == it->first);
                //         share = share + it->second;
                //     }
                //     return share_type(index, share);
                // }

                static inline share_type partial_eval_share(const share_type &renewing_share,
                                                            const share_type &init_share_value) {
                    assert(renewing_share.first == init_share_value.first);

                    return share_type(init_share_value.first, init_share_value.second + renewing_share.second);
                }
            };

            template<typename Group>
            struct public_share_sss<pedersen_dkg<Group>> : public virtual public_share_sss<shamir_sss<Group>> {
                typedef public_share_sss<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;

                public_share_sss() = default;

                public_share_sss(const typename base_type::public_share_type &in_public_share) :
                    public_share_sss<shamir_sss<Group>>(in_public_share) {
                }

                public_share_sss(typename base_type::public_share_type::first_type i,
                                 const typename base_type::public_share_type::second_type &ps) :
                    base_type(i, ps) {
                }
            };

            template<typename Group>
            struct share_sss<pedersen_dkg<Group>> : public virtual public_share_sss<pedersen_dkg<Group>>,
                                                    public virtual share_sss<shamir_sss<Group>> {
                typedef public_share_sss<shamir_sss<Group>> base_type1;
                typedef public_share_sss<pedersen_dkg<Group>> base_type2;
                typedef share_sss<shamir_sss<Group>> base_type3;
                typedef pedersen_dkg<Group> scheme_type;
                typedef typename base_type3::share_type share_type;

                share_sss(const share_type &in_share) : share_sss(in_share.first, in_share.second) {
                }

                share_sss(typename share_type::first_type i, const typename share_type::second_type &s) :
                    base_type1(i, s * base_type2::public_share_type::second_type::one()),
                    /// no need to initialize base_type2 as it virtually derived from base_type1
                    base_type2(), base_type3(i, s) {
                }

                inline share_type get_data() const {
                    return this->share;
                }
            };

            template<typename Group>
            struct secret_sss<pedersen_dkg<Group>> : public secret_sss<shamir_sss<Group>> {
                typedef secret_sss<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;

                template<typename Shares>
                secret_sss(const Shares &shares, const typename base_type::indexes_type &indexes,
                           std::size_t id_i = 0) :
                    secret_sss(std::cbegin(shares), std::cend(shares), indexes, id_i) {
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last, const typename base_type::indexes_type &indexes,
                           std::size_t id_i = 0) :
                    base_type(first, last, indexes, id_i) {
                }
            };

            template<typename Group>
            struct deal_shares_op<pedersen_dkg<Group>> : public deal_shares_op<shamir_sss<Group>> {
                typedef deal_shares_op<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef std::vector<typename share_type::share_type> internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t) {
                    base_type::template _init_accumulator<share_type>(acc, n, t);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    base_type::_update(acc, exp, coeff);
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<shares_type>(acc);
                }
            };

            template<typename Group>
            struct deal_share_op<pedersen_dkg<Group>> {
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef typename share_type::share_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    assert(scheme_type::check_participant_index(i));
                    acc = internal_accumulator_type(i, internal_accumulator_type::second_type::zero());
                }

                static inline void update(internal_accumulator_type &acc, const share_type &renewing_share) {
                    acc.second = scheme_type::partial_eval_share(renewing_share.get_data(), acc).second;
                }

                static inline share_type process(const internal_accumulator_type &acc) {
                    return acc;
                }
            };

            template<typename Group>
            struct verify_share_op<pedersen_dkg<Group>> : public verify_share_op<feldman_sss<Group>> {
                typedef verify_share_op<feldman_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef public_share_sss<scheme_type> public_share_type;
                typedef typename public_share_type::public_share_type internal_accumulator_type;

            public:
                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    base_type::template _init_accumulator<public_share_type>(acc, i);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::public_coeff_type &public_coeff) {
                    base_type::_update(acc, exp, public_coeff);
                }

                static inline bool process(const internal_accumulator_type &acc,
                                           const public_share_type &verified_public_share) {
                    return base_type::template _process<public_share_type>(acc, verified_public_share);
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<pedersen_dkg<Group>> : public reconstruct_secret_op<shamir_sss<Group>> {
                typedef reconstruct_secret_op<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::pair<typename scheme_type::indexes_type, std::vector<share_type>>
                    internal_accumulator_type;

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    base_type::_update(acc, share);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<secret_type>(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
