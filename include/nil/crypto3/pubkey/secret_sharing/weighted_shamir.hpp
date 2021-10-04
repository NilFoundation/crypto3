//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP

#include <nil/crypto3/pubkey/secret_sharing/weighted_basic_policy.hpp>
#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct weighted_shamir_sss : public sss_weighted_basic_policy<Group>, public shamir_sss<Group> {
                typedef sss_weighted_basic_policy<Group> basic_policy;
                typedef shamir_sss<Group> base_type;
            };

            template<typename Group>
            struct public_share_sss<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef std::pair<std::size_t, std::vector<public_share_sss<shamir_sss<Group>>>> public_share_type;
                typedef typename scheme_type::indexes_type indexes_type;

                public_share_sss() = default;

                template<typename PublicShares>
                public_share_sss(std::size_t i, const PublicShares &i_public_shares) :
                    public_share_sss(i, std::cbegin(i_public_shares), std::cend(i_public_shares)) {
                }

                template<typename PublicShareIt>
                public_share_sss(const std::size_t i, PublicShareIt first, PublicShareIt last) {
                    public_share.first = i;
                    assert(scheme_type::check_participant_index(get_index()));
                    for (auto iter = first; iter != last; ++iter) {
                        public_share.second.emplace_back(*iter);
                        assert(indexes.emplace(public_share.second.back().get_index()).second);
                    }
                }

                inline typename public_share_type::first_type get_index() const {
                    return public_share.first;
                }

                inline const typename public_share_type::second_type &get_value() const {
                    return public_share.second;
                }

                inline const indexes_type &get_indexes() const {
                    return indexes;
                }

                bool operator==(const public_share_sss &other) const {
                    return this->public_share == other.public_share;
                }

                bool operator<(const public_share_sss &other) const {
                    return this->get_index() < other.get_index();
                }

            private:
                indexes_type indexes;
                public_share_type public_share;
            };

            template<typename Group>
            struct share_sss<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef std::pair<std::size_t, std::vector<share_sss<shamir_sss<Group>>>> share_type;
                typedef typename scheme_type::indexes_type indexes_type;

                share_sss() = default;

                share_sss(std::size_t i, std::size_t w, std::size_t t) {
                    share.first = i;
                    assert(scheme_type::check_participant_index(get_index()));
                    assert(scheme_type::check_weight(w));
                    for (std::size_t j = 1; j <= w; ++j) {
                        share.second.emplace_back(i * t + j);
                        assert(indexes.emplace(share.second.back().get_index()).second);
                    }
                }

                inline typename share_type::first_type get_index() const {
                    return share.first;
                }

                inline const typename share_type::second_type &get_value() const {
                    return share.second;
                }

                inline const share_type &get_data() const {
                    return share;
                }

                inline const indexes_type &get_indexes() const {
                    return indexes;
                }

                operator public_share_sss<scheme_type>() const {
                    using To = public_share_sss<scheme_type>;

                    return To(share.first, share.second);
                }

                bool operator==(const share_sss &other) const {
                    return this->share == other.share;
                }

                bool operator<(const share_sss &other) const {
                    return this->get_index() < other.get_index();
                }

                //
                //  0 <= k < t
                //
                inline void update(const typename scheme_type::coeff_type &coeff, std::size_t exp) {
                    for (auto &share_j : share.second) {
                        share_j.update(coeff, exp);
                    }
                }

            private:
                indexes_type indexes;
                share_type share;
            };

            template<typename Group>
            struct secret_sss<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef typename scheme_type::private_element_type secret_type;

                template<typename Shares>
                secret_sss(const Shares &shares) : secret_sss(std::cbegin(shares), std::cend(shares)) {
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last) : secret(reconstruct_secret(first, last)) {
                }

                // template<typename Shares>
                // secret_sss(const Shares &shares, const indexes_type &indexes) :
                //     secret_sss(std::cbegin(shares), std::cend(shares), indexes) {
                // }
                //
                // template<typename ShareIt>
                // secret_sss(ShareIt first, ShareIt last, const indexes_type &indexes) :
                //     secret(reconstruct_secret(first, last, indexes)) {
                // }

                inline const secret_type &get_value() const {
                    return secret;
                }

                bool operator==(const secret_sss &other) const {
                    return this->secret == other.secret;
                }

            private:
                template<typename ShareIt,
                         typename std::enable_if<
                             std::is_same<typename std::remove_cv<typename std::remove_reference<
                                              typename std::iterator_traits<ShareIt>::value_type>::type>::type,
                                          share_sss<scheme_type>>::value,
                             bool>::type = true>
                static inline secret_type reconstruct_secret(ShareIt first, ShareIt last) {
                    typename share_sss<scheme_type>::share_type::second_type _shares;
                    for (auto iter = first; iter != last; iter++) {
                        std::copy(std::cbegin(iter->get_value()), std::cend(iter->get_value()),
                                  std::back_inserter(_shares));
                    }

                    return reconstruct_secret(std::cbegin(_shares), std::cend(_shares),
                                              get_indexes(std::cbegin(_shares), std::cend(_shares)));
                }

                template<typename ShareIt>
                static inline secret_type reconstruct_secret(ShareIt first, ShareIt last,
                                                             const typename scheme_type::indexes_type &indexes) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    secret_type secret = secret_type::zero();
                    for (auto it = first; it != last; it++) {
                        secret = secret + it->get_value() * scheme_type::eval_basis_poly(indexes, it->get_index());
                    }

                    return secret;
                }

                template<typename ShareIt>
                static inline typename scheme_type::indexes_type get_indexes(ShareIt first, ShareIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    typename scheme_type::indexes_type indexes;
                    for (auto it = first; it != last; it++) {
                        assert(scheme_type::check_participant_index(it->get_index()) &&
                               indexes.emplace(it->get_index()).second);
                    }
                    return indexes;
                }

                secret_type secret;
            };

            // template<typename Group>
            // struct public_share_sss<weighted_shamir_sss<Group>> {
            //     typedef weighted_shamir_sss<Group> scheme_type;
            //     typedef typename scheme_type::indexed_weighted_public_element public_share_type;
            //
            //     public_share_sss() = default;
            //
            //     template<typename PublicShares>
            //     public_share_sss(const std::size_t i, const PublicShares &i_public_shares) :
            //         public_share_sss(i, std::cbegin(i_public_shares), std::cend(i_public_shares)) {
            //     }
            //
            //     template<typename PublicShareIt>
            //     public_share_sss(const std::size_t i, PublicShareIt first, PublicShareIt last) {
            //         public_share.first = i;
            //         std::copy(first, last, std::inserter(public_share.second, std::end(public_share.second)));
            //     }
            //
            //     inline typename public_share_type::first_type get_index() const {
            //         return public_share.first;
            //     }
            //
            //     inline typename public_share_type::second_type get_value() const {
            //         return public_share.second;
            //     }
            //
            // protected:
            //     public_share_type public_share;
            // };
            //
            // template<typename Group>
            // struct share_sss<weighted_shamir_sss<Group>> : public public_share_sss<weighted_shamir_sss<Group>> {
            //     typedef public_share_sss<weighted_shamir_sss<Group>> base_type;
            //     typedef weighted_shamir_sss<Group> scheme_type;
            //     typedef typename scheme_type::indexed_weighted_private_element share_type;
            //
            //     share_sss(const share_type &share) : share_sss(share.first, share.second) {
            //     }
            //
            //     template<typename Shares>
            //     share_sss(const std::size_t i, const Shares &i_shares) :
            //         share_sss(i, std::cbegin(i_shares), std::cend(i_shares)) {
            //     }
            //
            //     template<typename ShareIt>
            //     share_sss(const std::size_t i, ShareIt first, ShareIt last) :
            //         base_type(i, get_public_shares(first, last)) {
            //         share.first = i;
            //         std::copy(first, last, std::inserter(share.second, std::end(share.second)));
            //     }
            //
            //     inline typename share_type::first_type get_index() const {
            //         return share.first;
            //     }
            //
            //     inline typename share_type::second_type get_value() const {
            //         return share.second;
            //     }
            //
            //     inline share_type get_data() const {
            //         return share;
            //     }
            //
            //     bool operator==(const share_sss &other) const {
            //         return this->share == other.share;
            //     }
            //
            //     static inline void partial_eval_share(const typename scheme_type::coeff_type &coeff, std::size_t exp,
            //                                           share_type &share_value) {
            //         assert(scheme_type::check_participant_index(share_value.first));
            //         assert(scheme_type::check_exp(exp));
            //
            //         for (auto &j_share : share_value.second) {
            //             j_share.second = share_sss<shamir_sss<Group>>::partial_eval_share(coeff, exp,
            //             j_share).second;
            //         }
            //     }
            //
            // protected:
            //     template<typename ShareIt>
            //     static inline typename base_type::public_share_type::second_type get_public_shares(ShareIt first,
            //                                                                                        ShareIt last) {
            //         BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));
            //
            //         typename base_type::public_share_type::second_type public_shares;
            //         for (auto iter = first; iter != last; ++iter) {
            //             assert(public_shares.emplace(scheme_type::get_indexed_public_element(*iter)).second);
            //         }
            //         return public_shares;
            //     }
            //
            //     share_type share;
            // };
            //
            // template<typename Group>
            // struct secret_sss<weighted_shamir_sss<Group>> {
            //     typedef weighted_shamir_sss<Group> scheme_type;
            //     typedef typename scheme_type::private_element_type secret_type;
            //
            //     template<typename Shares>
            //     secret_sss(const Shares &shares) : secret_sss(std::cbegin(shares), std::cend(shares)) {
            //     }
            //
            //     template<typename ShareIt>
            //     secret_sss(ShareIt first, ShareIt last) : secret(reconstruct_secret(first, last)) {
            //     }
            //
            //     //
            //     // reconstruct participant secret
            //     //
            //     // template<typename Weights>
            //     // secret_sss(const share_sss<scheme_type> &share, const Weights &weights) :
            //     // secret(reconstruct_participant_secret(share, weights)) {
            //     // }
            //
            //     inline secret_type get_value() const {
            //         return secret;
            //     }
            //
            //     bool operator==(const secret_sss &other) const {
            //         return this->secret == other.secret;
            //     }
            //
            // protected:
            //     template<typename ShareIt,
            //              typename std::enable_if<
            //                  std::is_same<typename std::remove_cv<typename std::remove_reference<
            //                                   typename std::iterator_traits<ShareIt>::value_type>::type>::type,
            //                               share_sss<scheme_type>>::value,
            //                  bool>::type = true>
            //     static inline secret_type reconstruct_secret(ShareIt first, ShareIt last) {
            //         std::unordered_map<std::size_t, typename scheme_type::private_element_type> _shares;
            //         for (auto it = first; it != last; it++) {
            //             for (const auto &participant_share_j : it->get_value()) {
            //                 assert(_shares.emplace(participant_share_j).second);
            //             }
            //         }
            //         return reconstruct_secret(std::cbegin(_shares), std::cend(_shares),
            //                                   scheme_type::get_indexes(_shares));
            //     }
            //
            //     template<typename ShareIt>
            //     static inline secret_type reconstruct_secret(ShareIt first, ShareIt last,
            //                                                  const typename scheme_type::indexes_type &indexes) {
            //         BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));
            //
            //         secret_type secret = secret_type::zero();
            //         for (auto it = first; it != last; it++) {
            //             secret = secret + it->second * scheme_type::eval_basis_poly(indexes, it->first);
            //         }
            //
            //         return secret;
            //     }
            //
            //     secret_type secret;
            // };

            template<typename Group>
            struct deal_shares_op<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef shares_type internal_accumulator_type;

                template<typename Weights>
                static inline typename std::enable_if<std::is_unsigned<
                    typename std::iterator_traits<typename Weights::iterator>::value_type>::value>::type
                    init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t,
                                     const Weights &weights) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
                    assert(n == std::distance(std::cbegin(weights), std::cend(weights)));
                    assert(scheme_type::check_threshold_value(t, n));

                    std::size_t i = 1;
                    for (auto w_i : weights) {
                        acc.emplace_back(i++, w_i, t);
                    }
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    for (auto shares_iter = std::begin(acc); shares_iter != std::end(acc); ++shares_iter) {
                        shares_iter->update(coeff, exp);
                    }
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return acc;
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<weighted_shamir_sss<Group>> {
                typedef weighted_shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::vector<share_type> internal_accumulator_type;

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    acc.emplace_back(share);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return acc;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_WEIGHTED_SHAMIR_SSS_HPP
