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

                using weights_type = std::map<std::size_t, std::size_t>;

                template<typename Weight>
                static inline typename std::enable_if<std::is_unsigned<typename Weight::first_type>::value &&
                                                          std::is_unsigned<typename Weight::second_type>::value,
                                                      bool>::type
                    check_weight(const Weight &w) {
                    return check_weight(w.first, w.second);
                }

                static inline bool check_weight(std::size_t i, std::size_t w) {
                    return base_type::check_participant_index(i) && 0 < w;
                }

                using base_type::get_indexes;

                static inline typename base_type::indexes_type get_indexes(const weights_type &weights, std::size_t t) {
                    assert(std::size(weights));

                    typename base_type::indexes_type result;
                    for (const auto &weight : weights) {
                        check_weight(weight);
                        for (std::size_t j = 1; j <= weight.second; ++j) {
                            bool emplace_status = result.emplace(weight.first * t + j).second;
                            assert(emplace_status);
                        }
                    }

                    return result;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SSS_WEIGHTED_BASIC_TYPES_HPP
