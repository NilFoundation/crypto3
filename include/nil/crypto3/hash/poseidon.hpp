//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

// #ifndef CRYPTO3_HASH_POSEIDON_HPP
// #define CRYPTO3_HASH_POSEIDON_HPP

// #include <nil/crypto3/hash/detail/poseidon/poseidon_functions.hpp>
// #include <nil/crypto3/hash/detail/sponge_construction.hpp>
// #include <nil/crypto3/hash/detail/block_stream_processor.hpp>

// namespace nil {
//     namespace crypto3 {
//         namespace hashes {
//             template<typename FieldT, typename element_type, std::size_t t, bool strength>
//             class poseidon_compressor {
//             protected:
//                 typedef detail::poseidon_functions<FieldT, element_type, t, strength> policy_type;

//             public:
//                 constexpr static const std::size_t word_bits = policy_type::word_bits;
//                 typedef typename policy_type::word_type word_type;

//                 constexpr static const std::size_t state_bits = policy_type::state_bits;
//                 constexpr static const std::size_t state_words = policy_type::state_words;
//                 typedef typename policy_type::state_type state_type;

//                 constexpr static const std::size_t block_bits = policy_type::block_bits;
//                 constexpr static const std::size_t block_words = policy_type::block_words;
//                 typedef typename policy_type::block_type block_type;

//                 static void process_block(state_type &state, const block_type &block) {
//                     for (std::size_t i = state_words - block_words; i != state_words; ++i)
//                         state[i] ^= block[i];
                    
//                     // for (std::size_t i = 0; i != state_words; ++i)
//                     //     boost::endian::endian_reverse_inplace(state[i]);

//                     policy_type::permute(state);

//                     // for (std::size_t i = 0; i != state_words; ++i)
//                     //     boost::endian::endian_reverse_inplace(state[i]);
//                 }
//             };

//             template<typename FieldT, typename element_type, std::size_t t, bool strength>
//             struct poseidon {
//             protected:
//                 typedef detail::poseidon_policy<FieldT, element_type, t, strength> policy_type;

//             public:
//                 constexpr static const std::size_t word_bits = policy_type::word_bits;
//                 typedef typename policy_type::word_type word_type;

//                 constexpr static const std::size_t block_bits = policy_type::block_bits;
//                 constexpr static const std::size_t block_words = policy_type::block_words;
//                 typedef typename policy_type::block_type block_type;

//                 constexpr static const std::size_t digest_bits = policy_type::digest_bits;
//                 typedef typename policy_type::digest_type digest_type;

//                 struct construction {
//                     struct params_type {
//                         typedef typename policy_type::digest_endian digest_endian;

//                         //constexpr static const std::size_t length_bits = policy_type::length_bits;
//                         constexpr static const std::size_t digest_bits = policy_type::digest_bits;
//                     };

//                     typedef sponge_construction<
//                         params_type, typename policy_type::iv_generator, poseidon_compressor<FieldT, element_type, t, strength>,
//                         // TODO: padding and finalizer
//                         detail::poseidon_padding<policy_type>, detail::poseidon_finalizer<policy_type>>
//                         type;
//                 };

//                 template<typename StateAccumulator, std::size_t ValueBits>
//                 struct stream_processor {
//                     struct params_type {
//                         typedef typename policy_type::digest_endian digest_endian;

//                         constexpr static const std::size_t value_bits = ValueBits;
//                     };

//                     typedef block_stream_processor<construction, StateAccumulator, params_type> type;
//                 };
//             };
//         }    // namespace hashes
//     }        // namespace crypto3
// }    // namespace nil

// #endif
