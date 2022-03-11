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

#ifndef CRYPTO3_HASH_H2F_HPP
#define CRYPTO3_HASH_H2F_HPP

#include <string>
#include <vector>

#include <nil/crypto3/hash/detail/raw_stream_processor.hpp>
#include <nil/crypto3/hash/detail/h2f/h2f_suites.hpp>
#include <nil/crypto3/hash/detail/h2f/h2f_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Field,
                     typename Hash,
                     std::size_t _k = 128,
                     UniformityCount _uniformity_count = UniformityCount::uniform_count,
                     ExpandMsgVariant _expand_msg_variant = ExpandMsgVariant::rfc_xmd>
            struct h2f_default_params {
                constexpr static UniformityCount uniformity_count = _uniformity_count;
                constexpr static ExpandMsgVariant expand_msg_variant = _expand_msg_variant;
                constexpr static std::size_t k = _k;

                typedef std::vector<std::uint8_t> dst_type;
                static inline dst_type dst = []() {
                    using suite_type = h2f_suite<Field, Hash, k>;
                    std::string default_tag_str = "QUUX-V01-CS02-with-";
                    dst_type dst(default_tag_str.begin(), default_tag_str.end());
                    dst.insert(dst.end(), suite_type::suite_id.begin(), suite_type::suite_id.end());
                    return dst;
                }();
            };

            /*!
             * @brief Hashing to Fields
             * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11
             *
             * @tparam Group
             * @tparam Params
             */
            template<typename Field, typename Hash = sha2<256>, typename Params = h2f_default_params<Field, Hash>>
            struct h2f {
                typedef h2f_suite<Field, Hash, Params::k> suite_type;
                static constexpr UniformityCount uniformity_count = Params::uniformity_count;
                static constexpr ExpandMsgVariant expand_msg_variant = Params::expand_msg_variant;

                typedef typename suite_type::field_type field_type;
                typedef typename suite_type::field_value_type field_value_type;
                typedef typename suite_type::modular_type modular_type;
                typedef typename suite_type::hash_type hash_type;

                constexpr static std::size_t digest_bits = hash_type::digest_bits;
                constexpr static std::size_t modulus_bits = field_type::modulus_bits;

                constexpr static std::size_t m = suite_type::m;
                constexpr static std::size_t L = suite_type::L;
                constexpr static std::size_t k = suite_type::k;
                constexpr static std::size_t count = static_cast<std::size_t>(uniformity_count);

                static_assert(count == 1 || count == 2, "unavailable count value");

                constexpr static std::size_t len_in_bytes = count * m * L;

                typedef typename std::conditional<(ExpandMsgVariant::rfc_xmd == expand_msg_variant),
                                                  detail::expand_message_xmd<k, len_in_bytes, hash_type, Params>,
                                                  void>::type expand_message_type;
                static_assert(!std::is_void<expand_message_type>::value, "Undefined expand_message_type.");

                typedef std::array<field_value_type, count> result_type;
                typedef result_type digest_type;
                typedef typename expand_message_type::internal_accumulator_type internal_accumulator_type;

                struct construction {
                    struct params_type {
                        typedef nil::marshalling::option::big_endian digest_endian;
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

                static inline void init_accumulator(internal_accumulator_type &acc) {
                    expand_message_type::init_accumulator(acc);
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    expand_message_type::update(acc, range);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    expand_message_type::update(acc, first, last);
                }

                // TODO: use type deducing to element_fp instead of arity, make FieldParams public for this
                template<std::size_t arity = m, typename std::enable_if<1 == arity, bool>::type = true>
                static inline result_type process(internal_accumulator_type &acc) {

                    typename expand_message_type::result_type uniform_bytes =
                        expand_message_type::process(acc, Params::dst);
                    std::array<modular_type, m> coordinates;
                    std::array<field_value_type, count> result;
                    for (std::size_t i = 0; i < count; i++) {
                        for (std::size_t j = 0; j < m; j++) {
                            auto elm_offset = L * (j + i * m);
                            // TODO: creating copy of range is a bottleneck:
                            //  extend marshalling interface by function supporting initialization from
                            //  container which length is less than modulus_octets
                            std::vector<std::uint8_t> imported_octets;
                            std::copy(std::cbegin(uniform_bytes) + elm_offset,
                                      std::cbegin(uniform_bytes) + elm_offset + L,
                                      std::back_inserter(imported_octets));
                            nil::marshalling::status_type status;
                            multiprecision::cpp_int tmp =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(imported_octets, status);
                            coordinates[j] = modular_type(tmp, field_type::modulus);
                        }
                        result[i] = coordinates[0];
                    }
                    return result;
                }

                // TODO: use type deducing to element_fp2 instead of arity, make FieldParams public for this
                template<std::size_t arity = m, typename std::enable_if<2 == arity, bool>::type = true>
                static inline result_type process(internal_accumulator_type &acc) {

                    typename expand_message_type::result_type uniform_bytes =
                        expand_message_type::process(acc, Params::dst);
                    std::array<modular_type, m> coordinates;
                    std::array<field_value_type, count> result;
                    for (std::size_t i = 0; i < count; i++) {
                        for (std::size_t j = 0; j < m; j++) {
                            auto elm_offset = L * (j + i * m);
                            // TODO: creating copy of range is a bottleneck:
                            //  extend marshalling interface by function supporting initialization from
                            //  container which length is less than modulus_octets
                            std::vector<std::uint8_t> imported_octets;
                            std::copy(std::cbegin(uniform_bytes) + elm_offset,
                                      std::cbegin(uniform_bytes) + elm_offset + L,
                                      std::back_inserter(imported_octets));
                            nil::marshalling::status_type status;
                            multiprecision::cpp_int tmp =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(imported_octets, status);
                            coordinates[j] = modular_type(tmp, field_type::modulus);
                        }
                        result[i] = field_value_type(coordinates[0], coordinates[1]);
                    }
                    return result;
                }
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_H2F_HPP
