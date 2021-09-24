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
                using private_element_t = typename Group::curve_type::scalar_field_type::value_type;
                using public_element_t = typename Group::value_type;
                using indexed_private_element_t = std::pair<std::size_t, private_element_t>;
                using indexed_public_element_t = std::pair<std::size_t, public_element_t>;

                //===========================================================================
                // secret sharing scheme logical types

                using secret_t = private_element_t;
                using coeff_t = private_element_t;
                using public_coeff_t = public_element_t;
                using share_t = indexed_private_element_t;
                using public_share_t = indexed_public_element_t;
                using indexes_t = std::set<std::size_t>;

                //===========================================================================
                // constraints checking meta-functions

                template<typename Index>
                using check_index_t = typename std::enable_if<std::is_unsigned<Index>::value, bool>::type;

                //
                // check elements
                //
                template<typename PrivateElement>
                using check_private_element_t = typename std::enable_if<
                    std::is_same<private_element_t, typename std::remove_cv<typename std::remove_reference<
                                                        PrivateElement>::type>::type>::value,
                    bool>::type;

                template<typename PublicElement>
                using check_public_element_t = typename std::enable_if<
                    std::is_same<public_element_t, typename std::remove_cv<typename std::remove_reference<
                                                       PublicElement>::type>::type>::value,
                    bool>::type;

                //
                // check indexed elements
                //
                template<typename IndexedPrivateElement,
                         check_index_t<typename IndexedPrivateElement::first_type> = true,
                         typename ResultT = check_private_element_t<typename IndexedPrivateElement::second_type>>
                using check_indexed_private_element_t = ResultT;

                template<typename IndexedPublicElement, check_index_t<typename IndexedPublicElement::first_type> = true,
                         typename ResultT = check_public_element_t<typename IndexedPublicElement::second_type>>
                using check_indexed_public_element_t = ResultT;

                template<typename IndexedElement, typename ResultT = check_index_t<typename IndexedElement::first_type>>
                using check_indexed_element_t = ResultT;

                //
                // check iterators
                //
                template<typename PublicElementIt,
                         typename ResultT =
                             check_public_element_t<typename std::iterator_traits<PublicElementIt>::value_type>>
                using check_public_element_iterator_t = ResultT;

                template<typename PrivateElementIt,
                         typename ResultT =
                             check_private_element_t<typename std::iterator_traits<PrivateElementIt>::value_type>>
                using check_private_element_iterator_t = ResultT;

                template<typename IndexedPrivateElementIt,
                         typename ResultT = check_indexed_private_element_t<
                             typename std::iterator_traits<IndexedPrivateElementIt>::value_type>>
                using check_indexed_private_element_iterator_t = ResultT;

                template<typename IndexedPublicElementIt,
                         typename ResultT = check_indexed_public_element_t<
                             typename std::iterator_traits<IndexedPublicElementIt>::value_type>>
                using check_indexed_public_element_iterator_t = ResultT;

                template<typename IndexedElementIt,
                         typename ResultT =
                             check_indexed_element_t<typename std::iterator_traits<IndexedElementIt>::value_type>>
                using check_indexed_element_iterator_t = ResultT;

                //
                // check ranges
                //
                template<typename PublicElements,
                         typename ResultT = check_public_element_iterator_t<typename PublicElements::iterator>>
                using check_public_elements_t = ResultT;

                template<typename PrivateElements,
                         typename ResultT = check_private_element_iterator_t<typename PrivateElements::iterator>>
                using check_private_elements_t = ResultT;

                template<typename IndexedPrivateElements,
                         typename ResultT =
                             check_indexed_private_element_iterator_t<typename IndexedPrivateElements::iterator>>
                using check_indexed_private_elements_t = ResultT;

                template<typename IndexedPublicElements,
                         typename ResultT =
                             check_indexed_public_element_iterator_t<typename IndexedPublicElements::iterator>>
                using check_indexed_public_elements_t = ResultT;

                template<typename IndexedElements,
                         typename ResultT = check_indexed_element_iterator_t<typename IndexedElements::iterator>>
                using check_indexed_elements_t = ResultT;

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

                template<typename IndexedElements, check_indexed_elements_t<IndexedElements> = true>
                static inline indexes_t get_indexes(const IndexedElements &elements) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const IndexedElements>));

                    return get_indexes(std::cbegin(elements), std::cend(elements));
                }

                template<typename IndexedElementsIt, check_indexed_element_iterator_t<IndexedElementsIt> = true>
                static inline indexes_t get_indexes(IndexedElementsIt first, IndexedElementsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedElementsIt>));

                    indexes_t indexes;
                    for (auto it = first; it != last; it++) {
                        assert(check_participant_index(it->first) && indexes.emplace(it->first).second);
                    }
                    return indexes;
                }

                template<typename Share, check_indexed_element_t<Share> = true>
                static inline public_share_t get_public_share(const Share &s) {
                    assert(check_participant_index(s.first));

                    return public_share_t(s.first, get_public_element(s.second));
                }

                static inline public_element_t get_public_element(const private_element_t &e) {
                    return e * public_element_t::one();
                }

                static inline public_element_t get_public_element(const public_element_t &e) {
                    return e;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_BASIC_TYPES_HPP
