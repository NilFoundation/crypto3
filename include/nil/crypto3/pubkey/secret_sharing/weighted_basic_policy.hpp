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

#ifndef CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
#define CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP

#include <unordered_map>

#include <nil/crypto3/pubkey/secret_sharing/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct sss_weighted_basic_policy : public sss_basic_policy<Group> {
            protected:
                typedef sss_basic_policy<Group> base_type;

            public:
                //===========================================================================
                // public weighted secret sharing scheme types

                using weights_type = std::vector<std::size_t>;
                using indexed_weighted_private_element =
                    std::pair<std::size_t, std::unordered_map<std::size_t, typename base_type::private_element_type>>;
                using indexed_weighted_public_element =
                    std::pair<std::size_t, std::unordered_map<std::size_t, typename base_type::public_element_type>>;

                static inline bool check_weight(const std::size_t &w) {
                    return 0 < w;
                }

                template<typename Weights>
                typename base_type::indexes_type get_weighted_indexes(std::size_t t, const Weights &weights) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));

                    return get_weighted_indexes(t, std::cbegin(weights), std::end(weights));
                }

                template<typename WeightIt>
                static inline typename std::enable_if<
                    std::is_unsigned<typename std::iterator_traits<WeightIt>::value_type>::value,
                    typename base_type::indexes_type>::type
                    get_weighted_indexes(std::size_t t, WeightIt first, WeightIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightIt>));

                    typename base_type::indexes_type indexes;
                    std::size_t i = 1;
                    for (auto iter = first; iter != last; ++iter) {
                        for (std::size_t j = 1; j <= *iter; ++j) {
                            assert(indexes.emplace(i * t + j).second);
                        }
                        ++i;
                    }
                    return indexes;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
