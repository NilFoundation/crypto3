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

#ifndef CRYPTO3_HASH_H2C_HPP
#define CRYPTO3_HASH_H2C_HPP

#include <string>
#include <vector>

#include <nil/crypto3/hash/h2c_suites.hpp>
#include <nil/crypto3/hash/detail/h2c/h2c_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Group, UniformityCount _uniformity_count = UniformityCount::uniform_count,
                     ExpandMsgVariant _expand_msg_variant = ExpandMsgVariant::rfc_xmd>
            struct h2c_default_params {
                constexpr static UniformityCount uniformity_count = _uniformity_count;
                constexpr static ExpandMsgVariant expand_msg_variant = _expand_msg_variant;

                typedef h2c_suite<Group> suite_type;
                typedef std::vector<std::uint8_t> dst_type;
                static inline dst_type dst = []() {
                    std::string default_tag_str = "QUUX-V01-CS02-with-";
                    dst_type dst(default_tag_str.begin(), default_tag_str.end());
                    dst.insert(dst.end(), suite_type::suite_id.begin(), suite_type::suite_id.end());
                    return dst;
                }();
            };

            /*!
             * @brief Hashing to Elliptic Curves
             * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11
             *
             * @tparam Group
             * @tparam Params
             */
            template<typename Group, typename Params = h2c_default_params<Group>>
            struct h2c {
                typedef Group group_type;
                typedef Params params_type;

            protected:
                typedef detail::ep_map<Group, params_type, params_type::uniformity_count,
                                       params_type::expand_msg_variant>
                    policy_type;

            public:
                typedef typename h2c_suite<Group>::hash_type hash_type;
                typedef typename group_type::value_type group_value_type;
                typedef typename policy_type::internal_accumulator_type internal_accumulator_type;
                typedef group_value_type result_type;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                    policy_type::init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    policy_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    policy_type::update(acc, first, last);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return policy_type::process(acc);
                }
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_H2C_HPP
