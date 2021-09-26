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

#ifndef CRYPTO3_PUBKEY_SSS_BASIC_TYPES_HPP
#define CRYPTO3_PUBKEY_SSS_BASIC_TYPES_HPP

#include <utility>
#include <set>
#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct sss_basic_policy {
            protected:
                //===========================================================================
                // internal secret sharing scheme types

                using private_element_type = typename Group::curve_type::scalar_field_type::value_type;
                using public_element_type = typename Group::value_type;
                using indexed_private_element_type = std::pair<std::size_t, private_element_type>;
                using indexed_public_element_type = std::pair<std::size_t, public_element_type>;

            public:
                //===========================================================================
                // public secret sharing scheme types

                using secret_type = private_element_type;
                using coeff_type = private_element_type;
                using public_coeff_type = public_element_type;
                using share_type = indexed_private_element_type;
                using public_share_type = indexed_public_element_type;
                using indexes_type = std::set<std::size_t>;

            protected:
                //===========================================================================
                // internal constraints checking meta-functions

                template<typename Index>
                using check_index_type = typename std::enable_if<std::is_unsigned<Index>::value, bool>::type;

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

            public:
                //===========================================================================
                // public constraints checking meta-functions

                //
                // check elements
                //
                template<typename Secret>
                using check_secret_type = check_private_element_type<Secret>;

                template<typename Coeff>
                using check_coeff_type = check_private_element_type<Coeff>;

                template<typename PublicCoeff>
                using check_public_coeff_type = check_public_element_type<PublicCoeff>;

                template<typename Share>
                using check_share_type = check_indexed_private_element_type<Share>;

                template<typename PublicShare>
                using check_public_share_type = check_indexed_public_element_type<PublicShare>;

                //
                // check iterators
                //
                template<typename SecretIt>
                using check_secret_iterator_type = check_private_element_iterator_type<SecretIt>;

                template<typename CoeffIt>
                using check_coeff_iterator_type = check_private_element_iterator_type<CoeffIt>;

                template<typename PublicCoeffIt>
                using check_public_coeff_iterator_type = check_public_element_iterator_type<PublicCoeffIt>;

                template<typename ShareIt>
                using check_share_iterator_type = check_indexed_private_element_iterator_type<ShareIt>;

                template<typename PublicShareIt>
                using check_public_share_iterator_type = check_indexed_public_element_iterator_type<PublicShareIt>;

                //
                // check ranges
                //
                template<typename Secrets>
                using check_secrets_type = check_private_elements_type<Secrets>;

                template<typename Coeffs>
                using check_coeffs_type = check_private_elements_type<Coeffs>;

                template<typename PublicCoeffs>
                using check_public_coeffs_type = check_public_elements_type<PublicCoeffs>;

                template<typename Shares>
                using check_shares_type = check_indexed_private_elements_type<Shares>;

                template<typename PublicShares>
                using check_public_shares_type = check_indexed_public_elements_type<PublicShares>;

                //===========================================================================
                // general purposes functions

                static inline bool check_minimal_size(std::size_t size) {
                    return size >= 2;
                }

                static inline std::size_t get_min_threshold_value(std::size_t n) {
                    assert(check_minimal_size(n));

                    return (n + 1) / 2;
                }

                static inline bool check_participant_index(std::size_t i) {
                    return i > 0;
                }

                static inline bool check_participant_index(std::size_t i, std::size_t n) {
                    return check_participant_index(i) && i <= n;
                }

                static inline bool check_threshold_value(std::size_t t, std::size_t n) {
                    return check_minimal_size(t) && n >= t && t >= get_min_threshold_value(n);
                }

                static inline bool check_exp(std::size_t exp) {
                    return exp >= 0;
                }

                // // TODO: DELETE
                // template<typename IndexedElements, check_indexed_elements_type<IndexedElements> = true>
                // static inline indexes_type get_indexes(const IndexedElements &elements) {
                //     BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedElements>));
                //
                //     return get_indexes(std::cbegin(elements), std::cend(elements));
                // }
                //
                // // TODO: DELETE
                // template<typename IndexedElementsIt, check_indexed_element_iterator_type<IndexedElementsIt> = true>
                // static inline indexes_type get_indexes(IndexedElementsIt first, IndexedElementsIt last) {
                //     BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedElementsIt>));
                //
                //     indexes_type indexes;
                //     for (auto it = first; it != last; it++) {
                //         assert(check_participant_index(it->first) && indexes.emplace(it->first).second);
                //     }
                //     return indexes;
                // }

                template<typename Share, check_share_type<Share> = true>
                static inline public_share_type get_public_share(const Share &s) {
                    assert(check_participant_index(s.first));

                    return public_share_type(s.first, get_public_element(s.second));
                }

                static inline public_element_type get_public_element(const private_element_type &e) {
                    return e * public_element_type::one();
                }

                static inline public_element_type get_public_element(const public_element_type &e) {
                    return e;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_BASIC_TYPES_HPP
