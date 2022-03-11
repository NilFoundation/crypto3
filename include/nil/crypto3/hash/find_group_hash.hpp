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

#ifndef CRYPTO3_HASH_FIND_GROUP_HASH_HPP
#define CRYPTO3_HASH_FIND_GROUP_HASH_HPP

#include <string>
#include <array>
#include <vector>

#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <nil/crypto3/hash/detail/raw_stream_processor.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            struct find_group_hash_default_params {
                static constexpr std::size_t dst_bits = 8 * 8;
                using dst_type = std::vector<std::uint8_t>;
                static inline dst_type dst = []() {
                    std::string default_tag_str = "Zcash_PH";
                    dst_type dst(default_tag_str.begin(), default_tag_str.end());
                    assert(dst.size() == 8);
                    return dst;
                }();
            };

            /*!
             * @brief Hashing to elliptic curve Jubjub according to FindGroupHash Zcash algorithm
             * https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub
             *
             * @tparam Group
             * @tparam Params
             */
            // TODO: use blake2s by default
            template<typename Params = find_group_hash_default_params,
                     typename Hash = sha2<256>,
                     typename Group = algebra::curves::jubjub::template g1_type<
                         nil::crypto3::algebra::curves::coordinates::affine,
                         nil::crypto3::algebra::curves::forms::twisted_edwards>>
            struct find_group_hash {
                using params = Params;
                using hash_type = Hash;
                using group_type = Group;
                using curve_type = typename group_type::curve_type;

                // TODO: FIXME: use marshalling method to determine bit size of serialized group_value_type
                static constexpr std::size_t digest_bits = group_type::field_type::value_bits;
                using group_value_type = typename group_type::value_type;
                using internal_accumulator_type = accumulator_set<hash_type>;
                using result_type = group_value_type;
                using digest_type = result_type;

                struct construction {
                    struct params_type {
                        typedef nil::marshalling::option::little_endian digest_endian;
                    };
                    typedef void type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename construction::params_type::digest_endian digest_endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef raw_stream_processor<construction, StateAccumulator, params_type> type;
                };

                static inline std::vector<std::uint8_t> urs = {
                    0x30, 0x39, 0x36, 0x62, 0x33, 0x36, 0x61, 0x35, 0x38, 0x30, 0x34, 0x62, 0x66, 0x61, 0x63, 0x65,
                    0x66, 0x31, 0x36, 0x39, 0x31, 0x65, 0x31, 0x37, 0x33, 0x63, 0x33, 0x36, 0x36, 0x61, 0x34, 0x37,
                    0x66, 0x66, 0x35, 0x62, 0x61, 0x38, 0x34, 0x61, 0x34, 0x34, 0x66, 0x32, 0x36, 0x64, 0x64, 0x64,
                    0x37, 0x65, 0x38, 0x64, 0x39, 0x66, 0x37, 0x39, 0x64, 0x35, 0x62, 0x34, 0x32, 0x64, 0x66, 0x30};

                static inline void init_accumulator(internal_accumulator_type &acc) {
                    hash<hash_type>(params::dst, acc);
                    hash<hash_type>(urs, acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    hash<hash_type>(range, acc);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    hash<hash_type>(first, last, acc);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    nil::marshalling::status_type status;
                    group_value_type point;
                    std::uint8_t i = 0;

                    while (true) {
                        auto acc_copy = acc;
                        hash<hash_type>(
                            {
                                i++,
                            },
                            acc_copy);
                        typename hash_type::digest_type H =
                            nil::crypto3::accumulators::extract::hash<hash_type>(acc_copy);
                        // TODO: generalize pack interface to accept arbitrary containers
                        std::vector<std::uint8_t> H_vec(std::cbegin(H), std::cend(H));
                        point = nil::marshalling::pack<nil::marshalling::option::little_endian>(H_vec, status);
                        if (status == nil::marshalling::status_type::success) {
                            break;
                        }
                        // TODO: return status
                        assert(i < 256);
                    }
                    point = typename group_type::field_type::value_type(group_type::params_type::cofactor) * point;
                    // TODO: return status
                    assert(!point.is_zero());
                    assert(point.is_well_formed());

                    return point;
                }
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_FIND_GROUP_HASH_HPP
