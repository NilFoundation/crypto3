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

                // TODO: make weights indexed
                using weights_type = std::vector<std::size_t>;

                template<typename Weight>
                static inline typename std::enable_if<std::is_unsigned<Weight>::value, bool>::type
                    check_weight(Weight w) {
                    return 0 < w;
                }

                using base_type::get_indexes;

                template<typename WeightIt>
                static inline typename base_type::indexes_type get_indexes(WeightIt first, WeightIt last,
                                                                           std::size_t t) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightIt>));
                    assert(base_type::check_threshold_value(t, std::distance(first, last)));

                    typename base_type::indexes_type result;
                    std::size_t i = 1;
                    for (auto it = first; it != last; it++) {
                        check_weight(*it);
                        for (std::size_t j = 1; j <= *it; ++j) {
                            bool emplace_status = result.emplace(i * t + j).second;
                            assert(emplace_status);
                        }
                        ++i;
                    }

                    return result;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
