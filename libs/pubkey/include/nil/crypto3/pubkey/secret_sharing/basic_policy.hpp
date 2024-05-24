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
                //===========================================================================
                // internal secret sharing scheme types

                using private_element_type = typename Group::curve_type::scalar_field_type::value_type;
                using public_element_type = typename Group::value_type;
                using indexed_private_element_type = std::pair<std::size_t, private_element_type>;
                using indexed_public_element_type = std::pair<std::size_t, public_element_type>;

                //===========================================================================
                // public secret sharing scheme types

                using coeff_type = private_element_type;
                using public_coeff_type = public_element_type;
                using indexes_type = std::set<std::size_t>;

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

                //===========================================================================
                // TODO: refactor
                static inline public_element_type get_public_element(const private_element_type &e) {
                    return e * public_element_type::one();
                }

                template<typename IndexedElementIt>
                static inline indexes_type get_indexes(IndexedElementIt first, IndexedElementIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<IndexedElementIt>));

                    indexes_type indexes;
                    for (auto it = first; it != last; ++it) {
                        bool emplace_status = indexes.emplace(it->get_index()).second;
                        assert(check_participant_index(it->get_index()) && emplace_status);
                    }

                    return indexes;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_BASIC_TYPES_HPP
