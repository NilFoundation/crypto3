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

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct shamir_sss {
                typedef Group group_type;
                typedef typename group_type::policy_type::scalar_field_type scalar_field_type;

                typedef typename group_type::value_type group_value_type;
                typedef typename scalar_field_type::value_type scalar_field_value_type;

                typedef scalar_field_value_type private_element_type;
                typedef group_value_type public_element_type;
                typedef std::pair<std::size_t, private_element_type> indexed_private_element_type;
                typedef std::pair<std::size_t, public_element_type> indexed_public_element_type;

                //===========================================================================
                // secret sharing scheme logical types

                typedef private_element_type coeff_type;
                typedef public_element_type public_coeff_type;
                typedef std::vector<coeff_type> coeffs_type;
                typedef std::vector<public_coeff_type> public_coeffs_type;
                typedef indexed_private_element_type share_type;
                typedef indexed_public_element_type public_share_type;
                typedef std::unordered_map<std::size_t, private_element_type> shares_type;
                typedef std::unordered_map<std::size_t, public_element_type> public_shares_type;
                typedef std::set<std::size_t> indexes_type;

                //===========================================================================
                // constraints checking meta-functions

                template<typename Index>
                using check_index_type = typename std::enable_if<std::is_unsigned<Number>::value, bool>::type;

                //
                // check elements
                //
                template<typename PrivateElement>
                using check_private_element_type = typename std::enable_if<
                    std::is_same<private_element_type, typename std::remove_cv<typename std::remove_reference<
                                                           PrivateElement>::type>::type>::value,
                    bool>::type;

                template<typename PublicElement>
                using check_public_element_type = typename std::enable_if<
                    std::is_same<public_element_type, typename std::remove_cv<typename std::remove_reference<
                                                          PublicElement>::type>::type>::value,
                    bool>::type;

                //
                // check indexed elements
                //
                template<typename IndexedPrivateElement,
                         check_index_type<typename IndexedPrivateElement::first_type> = true,
                         typename ResultT = check_private_element_type<typename IndexedPrivateElement::second_type>>
                using check_indexed_private_element_type = ResultT;

                template<typename IndexedPublicElement,
                         check_index_type<typename IndexedPublicElement::first_type> = true,
                         typename ResultT = check_public_element_type<typename IndexedPublicElement::second_type>>
                using check_indexed_public_element_type = ResultT;

                template<typename IndexedElement,
                         typename ResultT = check_index_type<typename IndexedElement::first_type>>
                using check_indexed_element_type = ResultT;

                //
                // check iterators
                //
                template<typename PublicElementIt,
                         typename ResultT =
                             check_public_element_type<typename std::iterator_traits<PublicElementIt>::value_type>>
                using check_public_element_iterator_type = ResultT;

                template<typename PrivateElementIt,
                         typename ResultT =
                             check_private_element_type<typename std::iterator_traits<PrivateElementIt>::value_type>>
                using check_private_element_iterator_type = ResultT;

                template<typename IndexedPrivateElementIt,
                         typename ResultT = check_indexed_private_element_type<
                             typename std::iterator_traits<IndexedPrivateElementIt>::value_type>>
                using check_indexed_private_element_iterator_type = ResultT;

                template<typename IndexedPublicElementIt,
                         typename ResultT = check_indexed_public_element_type<
                             typename std::iterator_traits<IndexedPublicElementIt>::value_type>>
                using check_indexed_public_element_iterator_type = ResultT;

                template<typename IndexedElementIt,
                         typename ResultT =
                             check_indexed_element_type<typename std::iterator_traits<IndexedElementIt>::value_type>>
                using check_indexed_element_iterator_type = ResultT;

                //
                // check ranges
                //
                template<typename PublicElements,
                         typename ResultT = check_public_element_iterator_type<typename PublicElements::iterator>>
                using check_public_elements_type = ResultT;

                template<typename PrivateElements,
                         typename ResultT = check_private_element_iterator_type<typename PrivateElements::iterator>>
                using check_private_elements_type = ResultT;

                template<typename IndexedPrivateElements,
                         typename ResultT =
                             check_indexed_private_element_iterator_type<typename IndexedPrivateElements::iterator>>
                using check_indexed_private_elements_type = ResultT;

                template<typename IndexedPublicElements,
                         typename ResultT =
                             check_indexed_public_element_iterator_type<typename IndexedPublicElements::iterator>>
                using check_indexed_public_elements_type = ResultT;

                template<typename IndexedElements,
                         typename ResultT = check_indexed_element_iterator_type<typename IndexedElements::iterator>>
                using check_indexed_elements_type = ResultT;

                //===========================================================================
                // shares dealing functions

                template<typename Coeffs, check_private_elements_type<Coeffs> = true>
                static inline shares_type deal_shares(const Coeffs &coeffs, std::size_t n) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                    
                    return deal_shares(coeffs.begin(), coeffs.end(), n);
                }

                template<typename CoeffsIt, check_private_element_iterator_type<CoeffsIt> = true>
                static inline shares_type deal_shares(CoeffsIt first, CoeffsIt last, std::size_t n) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));

                    std::size_t t = std::distance(first, last);
                    assert(check_t(t, n));

                    shares_type shares;
                    for (std::size_t i = 1; i <= n; i++) {
                        assert(shares.emplace(deal_share(first, last, i)).second);
                    }
                    return shares;
                }

                template<typename Coeffs, check_private_elements_type<Coeffs> = true>
                static inline share_type deal_share(const Coeffs &coeffs, std::size_t i) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));
                    
                    return deal_share(coeffs.begin(), coeffs.end(), i);
                }

                template<typename CoeffsIt, check_private_element_iterator_type<CoeffsIt> = true>
                static inline share_type deal_share(CoeffsIt first, CoeffsIt last, std::size i) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));
                    assert(check_participant_index(i));
                    assert(check_minimal_size(std::distance(first, last)));

                    private_element_type e_i(i);
                    private_element_type temp = private_element_type::one();
                    private_element_type share = private_element_type::zero();

                    for (auto it = first; it != last; it++) {
                        share = share + *it * temp;
                        temp = temp * e_i;
                    }
                    return share_type(i, share);
                }

                // TODO: move function
                //
                //  0 <= k < t
                //
                static inline share_type partial_eval_share(const coeff_type &coeff, std::size_t exp,
                                                            const share_type &init_share_value) {
                    assert(check_participant_index(init_share_value.first));
                    assert(check_exp(exp));
                    
                    return share_type(init_share_value.first,
                                      init_share_value.second +
                                          coeff * private_element_type(init_share_value.first).pow(exp));
                }

                //===========================================================================
                // secret recovering functions

                template<typename Shares, check_indexed_private_elements_type<Shares> = true>
                static inline private_element_type reconstruct_secret(const Shares &shares, std::size_t id_i = 0) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                    
                    return reconstruct_secret(shares.begin(), shares.end(), id_i);
                }

                template<typename SharesIt, check_indexed_private_element_iterator_type<SharesIt> = true>
                static inline private_element_type reconstruct_secret(SharesIt first, SharesIt last,
                                                                      std::size_t id_i = 0) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIt>));

                    private_element_type secret = private_element_type::zero();
                    indexes_type indexes = get_indexes(first, last);
                    for (auto it = first; it != last; it++) {
                        secret = secret + it->second * eval_basis_poly(indexes, id_i ? id_i : it->first);
                    }
                    return secret;
                }

                template<typename PublicShares, check_indexed_public_elements_type<PublicShares> = true>
                static inline public_element_type reconstruct_public_element(const PublicShares &public_shares) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicShares>));
                    
                    return reconstruct_public_element(public_shares.begin(), public_shares.end());
                }

                template<typename PublicSharesIt, check_indexed_public_element_iterator_type<PublicSharesIt> = true>
                static inline public_element_type reconstruct_public_element(PublicSharesIt first,
                                                                             PublicSharesIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicSharesIt>));

                    public_element_type result = public_element_type::zero();
                    indexes_type indexes = get_indexes(first, last);

                    for (auto it = first; it != last; it++) {
                        result = result + eval_basis_poly(indexes, it->first) * it->second;
                    }
                    return result;
                }

                static inline private_element_type eval_basis_poly(const indexes_type &indexes, std::size_t i) {
                    assert(check_participant_index(i));

                    private_element_type e_i(i);
                    private_element_type result = private_element_type::one();

                    for (auto j : indexes) {
                        if (j != i) {
                            result = result * (private_element_type(j) / (private_element_type(j) - e_i));
                        }
                    }
                    return result;
                }

                template<typename PublicElements, check_public_elements_type<PublicElements> = true>
                static inline public_element_type reduce_public_elements(const PublicElements &public_elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicElements>));
                    
                    return reduce_public_elements(public_elements.begin(), public_elements.end());
                }

                template<typename PublicElementsIt, check_public_element_iterator_type<PublicElementsIt> = true>
                static inline public_element_type reduce_public_elements(PublicElementsIt first,
                                                                         PublicElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicElementsIt>));
                    assert(check_minimal_size(std::distance(first, last)));
                    
                    return std::accumulate(first, last, public_element_type::zero());
                }

                template<typename IndexedPublicElements,
                         check_indexed_public_elements_type<IndexedPublicElements> = true>
                static inline public_element_type
                    reduce_public_elements(const IndexedPublicElements &indexed_public_elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedPublicElements>));
                    
                    return reduce_public_elements(indexed_public_elements.begin(), indexed_public_elements.end());
                }

                template<typename IndexedPublicElementsIt,
                         check_indexed_public_element_iterator_type<IndexedPublicElementsIt> = true>
                static inline public_element_type reduce_public_elements(IndexedPublicElementsIt first,
                                                                         IndexedPublicElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedPublicElementsIt>));
                    assert(check_minimal_size(std::distance(first, last)));

                    public_element_type result = public_element_type::zero();
                    for (auto it = first; it != last; it++) {
                        result = result + it->second;
                    }
                    return result;
                }

                //===========================================================================
                // polynomial generation functions

                static inline coeffs_type get_poly(std::size_t t, std::size_t n) {
                    assert(check_t(t, n));

                    return get_poly(t);
                }

                template<typename Generator = random::algebraic_random_device<coeff_type>, typename Distribution = void>
                static inline coeffs_type get_poly(std::size_t t) {
                    assert(check_minimal_size(t));

                    coeffs_type coeffs;
                    Generator gen;
                    for (std::size_t i = 0; i < t; i++) {
                        coeffs.emplace_back(gen());
                    }
                    return coeffs;
                }

                //===========================================================================
                // general purposes functions

                template<typename IndexedElements, check_indexed_elements_type<IndexedElements> = true>
                static inline indexes_type get_indexes(const IndexedElements &elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedElements>));
                    
                    return get_indexes(elements.begin(), elements.end());
                }

                template<typename IndexedElementsIt, check_indexed_element_iterator_type<IndexedElementsIt> = true>
                static inline indexes_type get_indexes(IndexedElementsIt first, IndexedElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedElementsIt>));

                    indexes_type indexes;
                    for (auto it = first; it != last; it++) {
                        assert(check_participant_index(it->first) && indexes.emplace(it->first).second);
                    }
                    return indexes;
                }

                template<typename Coeffs, check_private_elements_type<Coeffs> = true>
                static inline public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                    return get_public_coeffs(coeffs.begin(), coeffs.end());
                }

                template<typename CoeffsIt, check_private_element_iterator_type<CoeffsIt> = true>
                static inline public_coeffs_type get_public_coeffs(CoeffsIt first, CoeffsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));
                    assert(check_minimal_size(std::distance(first, last)));

                    public_coeffs_type public_coeffs;
                    for (auto it = first; it != last; it++) {
                        public_coeffs.emplace_back(get_public_element(*it));
                    }
                    return public_coeffs;
                }

                template<typename Shares, check_indexed_private_elements_type<Shares> = true>
                static inline public_shares_type get_public_shares(const Shares &shares) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                    assert(check_minimal_size(std::distance(shares.begin(), shares.end())));

                    public_shares_type public_shares;
                    for (const auto &s : shares) {
                        assert(public_shares.emplace(get_public_share(s)).second);
                    }
                    return public_shares;
                }

                template<typename SharesIt, check_indexed_private_element_iterator_type<SharesIt> = true>
                static inline public_shares_type get_public_shares(SharesIt first, SharesIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIt>));
                    assert(check_minimal_size(std::distance(first, last)));

                    public_shares_type public_shares;
                    for (auto it = first; it != last; it++) {
                        assert(public_shares.emplace(get_public_share(*it)).second);
                    }
                    return public_shares;
                }

                template<typename Share, check_indexed_private_element_type<Share> = true>
                static inline public_share_type get_public_share(const Share &s) {
                    assert(check_participant_index(s.first));

                    return public_share_type(s.first, get_public_element(s.second));
                }

                static inline public_element_type get_public_element(const private_element_type &s) {
                    return s * public_element_type::one();
                }

                static inline bool check_minimal_size(std::size_t size) {
                    return size >= 2;
                }

                static inline bool check_participant_index(std::size_t i) {
                    return i > 0;
                }

                static inline bool check_participant_index(std::size_t i, std::size_t n) {
                    return check_participant_index(i) && i <= n;
                }

                static inline std::size_t get_minimal_t(std::size_t n) {
                    assert(check_minimal_size(n));

                    return (n + 1) / 2;
                }

                static inline bool check_t(std::size_t t, std::size_t n) {
                    return check_minimal_size(t) && n >= t && t >= get_minimal_t(n);
                }

                static inline bool check_exp(std::size_t exp) {
                    return exp >= 0;
                }
            };

            template<typename Group>
            struct deal_shares_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;

                typedef typename scheme_type::
            };

            template<typename Group>
            struct reconstruct_secret_op<shamir_sss<Group>> { };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
