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

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/hash_state.hpp>
#include <nil/crypto3/hash/find_group_hash.hpp>

#include <nil/crypto3/hash/detail/raw_stream_processor.hpp>
#include <nil/crypto3/hash/detail/pedersen/basic_functions.hpp>
#include <nil/crypto3/hash/detail/pedersen/lookup.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
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

                static constexpr std::size_t digest_bits = group_type::field_type::value_bits;
                using digest_type = group_value_type;
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

                // TODO: sync definition of the chunk_bits with circuit
                static constexpr std::size_t chunk_bits = 3;
                /// See definition of \p c in https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash
                static constexpr std::size_t chunks_per_base_point =
                    detail::chunks_per_base_point<typename curve_type::scalar_field_type>(chunk_bits);

                class internal_accumulator_type {
                    std::size_t bits_supplied = 0;
                    std::vector<bool> cached_bits;
                    typename curve_type::scalar_field_type::integral_type pow_two = 1;
                    typename curve_type::scalar_field_type::value_type encoded_segment =
                        curve_type::scalar_field_type::value_type::zero();
                    group_value_type current_base_point = hash<base_point_generator>({
                        static_cast<std::uint32_t>(0),
                    });

                public:
                    group_value_type result = group_value_type::zero();

                private:
                    inline std::size_t supplied_chunks() const {
                        assert(bits_supplied % chunk_bits == 0);
                        return bits_supplied / chunk_bits;
                    }

                    inline bool is_time_to_go_to_new_segment() const {
                        return supplied_chunks() > 1 &&    ///< first base point is initialized by default, there is no
                                                           ///< need to update when processing first segment
                               supplied_chunks() % chunks_per_base_point ==
                                   1;    ///< it's time to update base point if we moved to a new segment
                    }

                    inline void update_result() {
                        result = result + encoded_segment * current_base_point;
                    }

                    inline void update_new_segment() {
                        assert(bits_supplied > 0);
                        assert(is_time_to_go_to_new_segment());
                        current_base_point = hash<base_point_generator>({
                            static_cast<std::uint32_t>(supplied_chunks() / chunks_per_base_point),
                        });
                        pow_two = 1;
                        encoded_segment = curve_type::scalar_field_type::value_type::zero();
                    }

                    inline void update_current_segment() {
                        assert(cached_bits.size() == chunk_bits);
                        typename curve_type::scalar_field_type::value_type encoded_chunk =
                            detail::lookup<typename curve_type::scalar_field_type::value_type, chunk_bits>::process(
                                cached_bits) *
                            pow_two;
                        encoded_segment = encoded_segment + encoded_chunk;
                        pow_two = pow_two << (chunk_bits + 1);
                        cached_bits.clear();    ///< current chunk was processed, we could clear cache and be ready to
                                                ///< accepts bits of the next chunk
                    }

                public:
                    inline void update(bool b) {
                        cached_bits.template emplace_back(b);
                        ++bits_supplied;
                        if (cached_bits.size() == chunk_bits) {    ///< we could proceed if whole chunk was supplied
                            if (is_time_to_go_to_new_segment()) {
                                update_result();
                                update_new_segment();
                            }
                            update_current_segment();
                        }
                    }

                    inline void pad_update() {
                        while (!cached_bits
                                    .empty() ||     ///< length of the input bit string is not a multiple of chunk_bits
                               !bits_supplied) {    ///< empty bit string is being hashed, then hash only padding
                            update(false);
                        }
                        update_result();
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

                using internal_accumulator_type = nil::crypto3::accumulator_set<base_hash_type>;

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputRange>
                static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                    hash<base_hash_type>(range, acc);
                }

                template<typename InputIterator>
                static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                    hash<base_hash_type>(first, last, acc);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    auto result_point = nil::crypto3::accumulators::extract::hash<base_hash_type>(acc);
                    nil::marshalling::status_type status;
                    // TODO: check status
                    result_type result =
                        nil::marshalling::pack<typename construction::params_type::digest_endian>(result_point, status);
                    return result;
                }
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_PEDERSEN_HPP
