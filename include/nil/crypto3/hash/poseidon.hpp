//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_HPP
#define CRYPTO3_HASH_POSEIDON_HPP

#ifdef __ZKLLVM__
#include <nil/crypto3/algebra/curves/pallas.hpp>
#else
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/block_stream_processor.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace hashes {

#ifdef __ZKLLVM__
            class poseidon {
            public:
                typedef typename algebra::curves::pallas::base_field_type::value_type block_type;

                struct process{
                    block_type operator()(block_type first_input_block, block_type second_input_block){
                        return __builtin_assigner_poseidon_pallas_base({0, first_input_block, second_input_block})[2];
                    }
                };
            };
#else
            template<typename policy_type>
            class poseidon_compressor {
            protected:
                typedef detail::poseidon_permutation<policy_type> poseidon_permutation;

            public:
                typedef typename policy_type::word_type word_type;
                typedef typename policy_type::block_type block_type;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                constexpr static const std::size_t length_bits = policy_type::length_bits;

                static void process_block(state_type &state, const block_type &block) {

                    for (std::size_t i = 0; i < state_words; ++i)
                        state[i] ^= block[i];

                    // for (std::size_t i = 0; i != state_words; ++i)
                    //     boost::endian::endian_reverse_inplace(state[i]);

                    poseidon_permutation::permute(state);

                    // for (std::size_t i = 0; i != state_words; ++i)
                    //     boost::endian::endian_reverse_inplace(state[i]);
                }
            };

            template<typename PolicyType>
            struct poseidon {
            public:
                typedef PolicyType policy_type;
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;
                typedef digest_type value_type;

                // This is required by 'is_hash' concept.
                struct construction {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                    };

                    typedef detail::poseidon_sponge_construction<policy_type> type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef block_stream_processor<construction, StateAccumulator, params_type> type;
                };
            };
#endif
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif
