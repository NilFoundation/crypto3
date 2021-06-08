//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType = ::nil::crypto3::algebra::curves::bls12_381,
                         typename Hash = ::nil::crypto3::hashes::sha2<256>>
                struct transcript {
                    typedef CurveType curve_type;
                    typedef Hash hash_type;

                    typedef marshalling::ipp2_aggregation_bincode<curve_type> bincode;

                    std::vector<std::uint8_t> buffer;

                    template<
                        typename InputIterator,
                        typename std::enable_if<
                            std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value,
                            bool>::type = true>
                    transcript(InputIterator first, InputIterator last) {
                        buffer.insert(buffer.end(), first, last);
                    }

                    template<
                        typename InputIterator,
                        typename std::enable_if<
                            std::is_same<std::uint8_t, typename std::iterator_traits<InputIterator>::value_type>::value,
                            bool>::type = true>
                    inline void write_domain_separator(InputIterator first, InputIterator last) {
                        buffer.insert(buffer.end(), first, last);
                    }

                    template<typename FieldType>
                    inline typename std::enable_if<
                        std::is_same<typename curve_type::base_field_type, FieldType>::value ||
                        std::is_same<typename curve_type::scalar_field_type, FieldType>::value ||
                        std::is_same<typename curve_type::gt_type, FieldType>::value>::type
                        write(const typename FieldType::value_type &x) {
                        buffer.resize(buffer.size() + bincode::template get_element_size<FieldType>());
                        bincode::template field_element_to_bytes<FieldType>(
                            x, buffer.end() - bincode::template get_element_size<FieldType>(), buffer.end());
                    }

                    template<typename GroupType>
                    inline typename std::enable_if<std::is_same<typename curve_type::g1_type, GroupType>::value ||
                                                   std::is_same<typename curve_type::g2_type, GroupType>::value>::type
                        write(const typename GroupType::value_type &x) {
                        buffer.resize(buffer.size() + bincode::template get_element_size<GroupType>());
                        bincode::template point_to_bytes<GroupType>(
                            x, buffer.end() - bincode::template get_element_size<GroupType>(), buffer.end());
                    }

                    inline typename curve_type::scalar_field_type::value_type read_challenge() {
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

                            buffer.insert(buffer.end(), counter_nonce_bytes.begin(), counter_nonce_bytes.end());
                            typename hash_type::digest_type res = hash<hash_type>(buffer);
                            typename curve_type::scalar_field_type::value_type res_deser =
                                bincode::template field_element_from_bytes<typename curve_type::scalar_field_type>(
                                    res.begin(), res.end());

                            if (res_deser == curve_type::scalar_field_type::value_type::zero() ||
                                res_deser == curve_type::scalar_field_type::value_type::one()) {
                                continue;
                            }
                            return res_deser;
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_AGGREGATE_IPP2_TRANSCRIPT_HPP
