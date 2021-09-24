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

#ifndef CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_SHAMIR_SSS_HPP

#include <vector>
#include <type_traits>
#include <unordered_map>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/pubkey/operations/deal_shares_op.hpp>
#include <nil/crypto3/pubkey/operations/reconstruct_secret_op.hpp>

#include <nil/crypto3/pubkey/secret_sharing/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct shamir_sss {
                typedef Group group_type;
                typedef sss_basic_policy<group_type> basic_policy;

                //===========================================================================
                // secret sharing scheme output types

                typedef std::vector<typename basic_policy::coeff_t> coeffs_type;
                typedef std::vector<typename basic_policy::public_coeff_t> public_coeffs_type;
                typedef std::unordered_map<std::size_t, typename basic_policy::private_element_t> shares_type;
                typedef std::unordered_map<std::size_t, typename basic_policy::public_element_t> public_shares_type;

                //===========================================================================
                // shares dealing functions

                template<typename Coeffs, typename basic_policy::template check_private_elements_t<Coeffs> = true>
                static inline shares_type deal_shares(const Coeffs &coeffs, std::size_t n) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                    return deal_shares(coeffs.begin(), coeffs.end(), n);
                }

                template<typename CoeffsIt,
                         typename basic_policy::template check_private_element_iterator_t<CoeffsIt> = true>
                static inline shares_type deal_shares(CoeffsIt first, CoeffsIt last, std::size_t n) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));

                    std::size_t t = std::distance(first, last);
                    assert(basic_policy::check_threshold_value(t, n));

                    shares_type shares;
                    for (std::size_t i = 1; i <= n; i++) {
                        assert(shares.emplace(deal_share(first, last, i)).second);
                    }
                    return shares;
                }

                template<typename Coeffs, typename basic_policy::template check_private_elements_t<Coeffs> = true>
                static inline typename basic_policy::share_t deal_share(const Coeffs &coeffs, std::size_t i) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                    return deal_share(coeffs.begin(), coeffs.end(), i);
                }

                template<typename CoeffsIt,
                         typename basic_policy::template check_private_element_iterator_t<CoeffsIt> = true>
                static inline typename basic_policy::share_t deal_share(CoeffsIt first, CoeffsIt last, std::size_t i) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));
                    assert(basic_policy::check_participant_index(i));
                    assert(check_minimal_size(std::distance(first, last)));

                    typename basic_policy::private_element_t e_i(i);
                    typename basic_policy::private_element_t temp = basic_policy::private_element_t::one();
                    typename basic_policy::private_element_t share = basic_policy::private_element_t::zero();

                    for (auto it = first; it != last; it++) {
                        share = share + *it * temp;
                        temp = temp * e_i;
                    }
                    return typename basic_policy::share_t(i, share);
                }

                //
                //  0 <= k < t
                //
                static inline typename basic_policy::share_t
                    partial_eval_share(const typename basic_policy::coeff_t &coeff, std::size_t exp,
                                       const typename basic_policy::share_t &init_share_value) {
                    assert(basic_policy::check_participant_index(init_share_value.first));
                    assert(basic_policy::check_exp(exp));

                    return typename basic_policy::share_t(
                        init_share_value.first,
                        init_share_value.second +
                            coeff * typename basic_policy::private_element_t(init_share_value.first).pow(exp));
                }

                //===========================================================================
                // secret recovering functions

                template<typename Shares,
                         typename basic_policy::template check_indexed_private_elements_t<Shares> = true>
                static inline typename basic_policy::secret_t reconstruct_secret(const Shares &shares,
                                                                                 std::size_t id_i = 0) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));

                    return reconstruct_secret(std::cbegin(shares), std::cend(shares), id_i);
                }

                template<typename SharesIt,
                         typename basic_policy::template check_indexed_private_element_iterator_t<SharesIt> = true>
                static inline typename basic_policy::secret_t reconstruct_secret(SharesIt first, SharesIt last,
                                                                                 std::size_t id_i = 0) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIt>));

                    typename basic_policy::secret_t secret = basic_policy::secret_t::zero();
                    typename basic_policy::indexes_t indexes = basic_policy::get_indexes(first, last);
                    for (auto it = first; it != last; it++) {
                        secret = secret + it->second * eval_basis_poly(indexes, id_i ? id_i : it->first);
                    }
                    return secret;
                }

                template<typename PublicShares,
                         typename basic_policy::template check_indexed_public_elements_t<PublicShares> = true>
                static inline typename basic_policy::public_element_t
                    reconstruct_public_element(const PublicShares &public_shares) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicShares>));

                    return reconstruct_public_element(public_shares.begin(), public_shares.end());
                }

                template<typename PublicSharesIt,
                         typename basic_policy::template check_indexed_public_element_iterator_t<PublicSharesIt> = true>
                static inline typename basic_policy::public_element_t reconstruct_public_element(PublicSharesIt first,
                                                                                                 PublicSharesIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicSharesIt>));

                    typename basic_policy::public_element_t result = basic_policy::public_element_t::zero();
                    typename basic_policy::indexes_t indexes = basic_policy::get_indexes(first, last);

                    for (auto it = first; it != last; it++) {
                        result = result + eval_basis_poly(indexes, it->first) * it->second;
                    }
                    return result;
                }

                static inline typename basic_policy::private_element_t
                    eval_basis_poly(const typename basic_policy::indexes_t &indexes, std::size_t i) {
                    assert(basic_policy::check_participant_index(i));

                    typename basic_policy::private_element_t e_i(i);
                    typename basic_policy::private_element_t result = basic_policy::private_element_t::one();

                    for (auto j : indexes) {
                        if (j != i) {
                            result = result * (typename basic_policy::private_element_t(j) /
                                               (typename basic_policy::private_element_t(j) - e_i));
                        }
                    }
                    return result;
                }

                template<typename PublicElements,
                         typename basic_policy::template check_public_elements_t<PublicElements> = true>
                static inline typename basic_policy::public_element_t
                    reduce_public_elements(const PublicElements &public_elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicElements>));

                    return reduce_public_elements(public_elements.begin(), public_elements.end());
                }

                template<typename PublicElementsIt,
                         typename basic_policy::template check_public_element_iterator_t<PublicElementsIt> = true>
                static inline typename basic_policy::public_element_t reduce_public_elements(PublicElementsIt first,
                                                                                             PublicElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicElementsIt>));
                    assert(check_minimal_size(std::distance(first, last)));

                    return std::accumulate(first, last, basic_policy::public_element_t::zero());
                }

                template<typename IndexedPublicElements,
                         typename basic_policy::template check_indexed_public_elements_t<IndexedPublicElements> = true>
                static inline typename basic_policy::public_element_t
                    reduce_public_elements(const IndexedPublicElements &indexed_public_elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedPublicElements>));

                    return reduce_public_elements(indexed_public_elements.begin(), indexed_public_elements.end());
                }

                template<typename IndexedPublicElementsIt,
                         typename basic_policy::template check_indexed_public_element_iterator_t<
                             IndexedPublicElementsIt> = true>
                static inline typename basic_policy::public_element_t
                    reduce_public_elements(IndexedPublicElementsIt first, IndexedPublicElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedPublicElementsIt>));
                    assert(check_minimal_size(std::distance(first, last)));

                    typename basic_policy::public_element_t result = basic_policy::public_element_t::zero();
                    for (auto it = first; it != last; it++) {
                        result = result + it->second;
                    }
                    return result;
                }

                //===========================================================================
                // polynomial generation functions

                static inline coeffs_type get_poly(std::size_t t, std::size_t n) {
                    assert(basic_policy::check_threshold_value(t, n));

                    return get_poly(t);
                }

                template<
                    typename Generator = random::algebraic_random_device<typename basic_policy::coeff_t::field_type>,
                    typename Distribution = void>
                static inline coeffs_type get_poly(std::size_t t) {
                    assert(basic_policy::check_minimal_size(t));

                    coeffs_type coeffs;
                    Generator gen;
                    for (std::size_t i = 0; i < t; i++) {
                        coeffs.emplace_back(gen());
                    }
                    return coeffs;
                }

                //===========================================================================
                // TODO: refactor
                // general purposes functions

                template<typename Coeffs>
                static inline public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                    return get_public_coeffs(std::cbegin(coeffs), std::cend(coeffs));
                }

                template<typename CoeffsIt>
                static inline public_coeffs_type get_public_coeffs(CoeffsIt first, CoeffsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));
                    assert(basic_policy::check_minimal_size(std::distance(first, last)));

                    public_coeffs_type public_coeffs;
                    for (auto it = first; it != last; it++) {
                        public_coeffs.emplace_back(basic_policy::get_public_element(*it));
                    }
                    return public_coeffs;
                }

                template<typename Shares, typename basic_policy::template check_indexed_elements_t<Shares> = true>
                static inline public_shares_type get_public_shares(const Shares &shares) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));

                    return get_public_shares(std::cbegin(shares), std::cend(shares));
                }

                template<typename SharesIt,
                         typename basic_policy::template check_indexed_element_iterator_t<SharesIt> = true>
                static inline public_shares_type get_public_shares(SharesIt first, SharesIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIt>));
                    assert(basic_policy::check_minimal_size(std::distance(first, last)));

                    public_shares_type public_shares;
                    for (auto it = first; it != last; it++) {
                        assert(public_shares.emplace(basic_policy::get_public_share(*it)).second);
                    }
                    return public_shares;
                }
            };

            template<typename Group>
            struct deal_shares_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::basic_policy basic_policy;

                typedef typename scheme_type::group_type group_type;
                typedef typename scheme_type::shares_type shares_type;

                typedef shares_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n) {
                    std::size_t i = 1;
                    std::generate_n(std::inserter(acc, std::end(acc)), n, [&i]() {
                        return typename basic_policy::share_t(i++, basic_policy::private_element_t::zero());
                    });
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename basic_policy::coeff_t &coeff) {
                    for (auto shares_iter = std::begin(acc); shares_iter != std::end(acc); ++shares_iter) {
                        shares_iter->second = scheme_type::partial_eval_share(coeff, exp, *shares_iter).second;
                    }
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return acc;
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::basic_policy basic_policy;
                typedef typename scheme_type::shares_type shares_type;

                typedef typename basic_policy::secret_t secret_type;

                typedef shares_type internal_accumulator_type;

                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const typename basic_policy::share_t &share) {
                    assert(acc.emplace(share).second);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return scheme_type::reconstruct_secret(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
