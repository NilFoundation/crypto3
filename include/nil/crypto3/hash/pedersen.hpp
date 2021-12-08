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

#ifndef CRYPTO3_HASH_PEDERSEN_HPP
#define CRYPTO3_HASH_PEDERSEN_HPP

#include <tuple>

#include <nil/crypto3/detail/static_pow.hpp>

#include <nil/crypto3/hash/algorithm/to_curve.hpp>
#include <nil/crypto3/hash/to_curve_state.hpp>
#include <nil/crypto3/hash/find_group_hash.hpp>

#include <nil/crypto3/hash/detail/raw_stream_processor.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                /// See definition of \p c in https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash
                template<typename Field>
                constexpr std::size_t get_chunks_per_base_point(std::size_t chunk_bits) {
                    typename Field::extended_integral_type two(2);
                    std::size_t c = 1;
                    std::size_t prev_c = 0;
                    /// (Fr - 1) / 2
                    typename Field::extended_integral_type upper_bound = (Field::modulus - 1) / 2;
                    // TODO: first multiplier should be verified
                    /// (chunk_bits + 1) * ((2^(c * (chunk_bits + 1)) - 1) / (2^(chunk_bits + 1) - 1))
                    auto get_test_value = [&](auto i) {
                        return (chunk_bits + 1) * ((::nil::crypto3::detail::pow(two, i * (chunk_bits + 1)) - 1) /
                                                   (::nil::crypto3::detail::pow(two, chunk_bits + 1) - 1));
                    };
                    auto test_value = get_test_value(c);

                    while (test_value <= upper_bound) {
                        prev_c = c++;
                        test_value = get_test_value(c);
                    }

                    return prev_c;
                }
            }    // namespace detail

            /*!
             * @brief Pedersen hash
             *
             * @tparam Group
             * @tparam Params
             */
            // TODO: use blake2s by default
            template<typename Params = find_group_hash_default_params,
                     typename BasePointGeneratorHash = sha2<256>,
                     typename Group = algebra::curves::jubjub::template g1_type<
                         nil::crypto3::algebra::curves::coordinates::affine,
                         nil::crypto3::algebra::curves::forms::twisted_edwards>>
            struct pedersen_to_point {
                using params = Params;
                using group_type = Group;

                using base_point_generator_hash = BasePointGeneratorHash;
                using base_point_generator = find_group_hash<params, base_point_generator_hash, group_type>;

                using curve_type = typename group_type::curve_type;
                using group_value_type = typename group_type::value_type;

                using digest_type = group_value_type;
                using result_type = digest_type;

                // TODO: sync definition of the chunk_bits with circuit
                static constexpr std::size_t chunk_bits = 3;
                /// See definition of \p c in https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash
                static constexpr std::size_t chunks_per_base_point =
                    detail::get_chunks_per_base_point<typename curve_type::scalar_field_type>(chunk_bits);

                // TODO: simplify, refactor
                class internal_accumulator_type {
                    std::size_t bits_supplied = 0;
                    std::size_t chunks_supplied = 0;
                    std::uint32_t segment_n = 0;
                    std::vector<bool> cached_bits;
                    typename curve_type::scalar_field_type::integral_type pow_two;
                    typename curve_type::scalar_field_type::value_type encoded_segment;
                    group_value_type current_base_point = to_curve<base_point_generator>({
                        segment_n,
                    });

                public:
                    group_value_type result = group_value_type::zero();

                private:
                    void encode_chunk() {
                        assert(cached_bits.size() == chunk_bits);
                        if ((chunks_supplied - 1) % chunks_per_base_point ==
                            0) {    ///< we moved to a new segment, pow_two and encoded_segment should be reset
                            pow_two = 1;
                            encoded_segment = curve_type::scalar_field_type::value_type::zero();
                        }
                        // TODO: generalize calculation of the lookup table value for chunk_bits != 3
                        typename curve_type::scalar_field_type::value_type encoded_chunk =
                            static_cast<typename curve_type::scalar_field_type::value_type>(
                                (1 - 2 * cached_bits[2]) * (1 + cached_bits[0] + 2 * cached_bits[1])) *
                            pow_two;
                        encoded_segment = encoded_segment + encoded_chunk;
                        pow_two = pow_two << (chunk_bits + 1);
                        cached_bits.clear();    ///< current chunk was processed, we could clear cache and be ready to
                                                ///< accepts bits of the next chunk
                    }

                    void update_base_point() {
                        chunks_supplied = bits_supplied / chunk_bits;
                        std::uint32_t new_segment_n = (chunks_supplied - 1) / chunks_per_base_point;
                        if (new_segment_n ==
                            segment_n + 1) {    ///< current base point already used chunks_per_base_point times, it's
                                                ///< time to update base point
                            result =
                                result + encoded_segment * current_base_point;    ///< encoded_segment is ready, it's
                                                                                  ///< time to add it to the result
                            segment_n = new_segment_n;
                            current_base_point = to_curve<base_point_generator>({
                                segment_n,
                            });
                        }
                    }

                public:
                    void update(bool b) {
                        cached_bits.template emplace_back(b);
                        ++bits_supplied;
                        if (cached_bits.size() == chunk_bits) {    ///< we could proceed if whole chunk was supplied
                            update_base_point();
                            encode_chunk();
                        }
                    }

                    void pad_update() {
                        while (!cached_bits
                                    .empty() ||     ///< length of the input bit string is not a multiple of chunk_bits
                               !bits_supplied) {    ///< empty bit string is being hashed, then hash only padding
                            update(false);
                        }
                        if ((chunks_supplied - 1) % chunks_per_base_point !=
                                0 ||    ///< last encoded_segment wasn't added to the result in encode_chunk() yet
                            chunks_supplied % chunks_per_base_point != 0 ||
                            chunks_supplied == 1) {    ///< only one chunk was supplied, so it was not added neither in
                                                       ///< encode_chunk() nor in previous previous condition
                            result = result + encoded_segment * current_base_point;
                        }
                    }
                };

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<
                    typename InputRange,
                    typename std::enable_if<
                        std::is_same<bool,
                                     typename std::iterator_traits<typename InputRange::iterator>::value_type>::value,
                        bool>::type = true>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    for (auto b : range) {
                        acc.update(b);
                    }
                }

                template<typename InputIterator,
                         typename std::enable_if<
                             std::is_same<bool, typename std::iterator_traits<InputIterator>::value_type>::value,
                             bool>::type = true>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    for (auto it = first; it != last; ++it) {
                        acc.update(*it);
                    }
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    acc.pad_update();
                    return acc.result;
                }
            };

            // TODO: use blake2s by default
            template<typename Params = find_group_hash_default_params,
                     typename BasePointGeneratorHash = sha2<256>,
                     typename Group = algebra::curves::jubjub::template g1_type<
                         nil::crypto3::algebra::curves::coordinates::affine,
                         nil::crypto3::algebra::curves::forms::twisted_edwards>>
            struct pedersen {
                using params = Params;
                using group_type = Group;
                using base_point_generator_hash = BasePointGeneratorHash;

                using base_hash_type = pedersen_to_point<params, base_point_generator_hash, group_type>;

                using curve_type = typename base_hash_type::curve_type;
                using group_value_type = typename base_hash_type::group_value_type;

                // TODO: use marshalling method to determine bit size of serialized group_value_type
                static constexpr std::size_t digest_bits = group_type::field_type::value_bits;
                // TODO: define digest_type using marshalling
                using digest_type = std::vector<bool>;
                using result_type = digest_type;

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

                using internal_accumulator_type = hashing_to_curve_accumulator_set<base_hash_type>;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    to_curve<base_hash_type>(range, acc);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    to_curve<base_hash_type>(first, last, acc);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    auto result_point = nil::crypto3::hashes::accumulators::extract::to_curve<base_hash_type>(acc);
                    nil::marshalling::status_type status;
                    // TODO: check status
                    result_type result =
                        nil::marshalling::unpack<typename construction::params_type::digest_endian, bool>(result_point,
                                                                                                          status);
                    return result;
                }
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_PEDERSEN_HPP
