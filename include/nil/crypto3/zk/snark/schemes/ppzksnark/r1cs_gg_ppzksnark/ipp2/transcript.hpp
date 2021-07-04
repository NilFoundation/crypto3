//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_AGGREGATE_IPP2_TRANSCRIPT_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_AGGREGATE_IPP2_TRANSCRIPT_HPP

#include <vector>
#include <type_traits>
#include <iterator>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/algebra/marshalling.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType = algebra::curves::bls12<381>, typename Hash = hashes::sha2<256>>
                struct transcript {
                    typedef CurveType curve_type;
                    typedef Hash hash_type;

                    typedef marshalling::curve_bincode<curve_type> bincode;

                    std::vector<std::uint8_t> buffer;
                    ::nil::crypto3::accumulator_set<Hash> hasher_acc;

                    template<
                        typename InputIterator,
                        typename std::enable_if<
                            std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value,
                            bool>::type = true>
                    transcript(InputIterator first, InputIterator last) {
                        buffer.insert(buffer.end(), first, last);
                        hash<hash_type>(buffer, hasher_acc);
                        buffer.clear();
                    }

                    template<
                        typename InputIterator,
                        typename std::enable_if<
                            std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value,
                            bool>::type = true>
                    inline void write_domain_separator(InputIterator first, InputIterator last) {
                        buffer.insert(buffer.end(), first, last);
                        hash<hash_type>(buffer, hasher_acc);
                        buffer.clear();
                    }

                    template<typename FieldType>
                    inline typename std::enable_if<
                        std::is_same<typename curve_type::base_field_type, FieldType>::value ||
                        std::is_same<typename curve_type::scalar_field_type, FieldType>::value ||
                        std::is_same<typename curve_type::gt_type, FieldType>::value>::type
                        write(const typename FieldType::value_type &x) {
                        buffer.resize(bincode::template get_element_size<FieldType>());
                        bincode::template field_element_to_bytes<FieldType>(x, buffer.begin(), buffer.end());
                        hash<hash_type>(buffer, hasher_acc);
                        buffer.clear();
                    }

                    template<typename GroupType>
                    inline typename std::enable_if<std::is_same<typename curve_type::g1_type, GroupType>::value ||
                                                   std::is_same<typename curve_type::g2_type, GroupType>::value>::type
                        write(const typename GroupType::value_type &x) {
                        buffer.resize(bincode::template get_element_size<GroupType>());
                        bincode::template point_to_bytes<GroupType>(x, buffer.begin(), buffer.end());
                        hash<hash_type>(buffer, hasher_acc);
                        buffer.clear();
                    }

                    template<typename InputIterator>
                    inline typename std::enable_if<
                        std::is_same<std::uint8_t,
                                     typename std::iterator_traits<InputIterator>::value_type>::value>::type
                        write(InputIterator first, InputIterator last) {
                        std::array<std::uint8_t, sizeof(std::uint64_t)> len_bytes;
                        nil::crypto3::detail::pack<stream_endian::little_byte_big_bit,
                                                   stream_endian::big_byte_big_bit,
                                                   sizeof(std::uint64_t) * 8,
                                                   8>(
                            std::vector<std::uint64_t> {
                                static_cast<std::uint64_t>(std::distance(first, last)),
                            },
                            len_bytes);
                        buffer.insert(buffer.end(), len_bytes.begin(), len_bytes.end());
                        buffer.insert(buffer.end(), first, last);
                        hash<hash_type>(buffer, hasher_acc);
                        buffer.clear();
                    }

                    inline typename curve_type::scalar_field_type::value_type read_challenge() {
                        auto hasher_state = hasher_acc;
                        std::size_t counter_nonce = 0;
                        std::array<std::uint8_t, sizeof(std::size_t)> counter_nonce_bytes;
                        while (true) {
                            ++counter_nonce;
                            nil::crypto3::detail::pack<stream_endian::big_byte_big_bit,
                                                       stream_endian::little_byte_big_bit,
                                                       sizeof(std::size_t) * 8,
                                                       8>(
                                std::vector<std::size_t> {
                                    counter_nonce,
                                },
                                counter_nonce_bytes);

                            hash<hash_type>(counter_nonce_bytes, hasher_state);
                            typename hash_type::digest_type hasher_res =
                                boost::accumulators::extract_result<typename boost::mpl::front<
                                    typename ::nil::crypto3::accumulator_set<Hash>::features_type>::type>(hasher_state);
                            std::pair<bool, typename curve_type::scalar_field_type::value_type> hasher_res_deser =
                                bincode::template field_element_from_bytes<typename curve_type::scalar_field_type>(
                                    hasher_res.begin(), hasher_res.end());

                            if (!hasher_res_deser.first ||
                                hasher_res_deser.second == curve_type::scalar_field_type::value_type::zero() ||
                                hasher_res_deser.second == curve_type::scalar_field_type::value_type::one()) {
                                continue;
                            }
                            return hasher_res_deser.second;
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_AGGREGATE_IPP2_TRANSCRIPT_HPP
