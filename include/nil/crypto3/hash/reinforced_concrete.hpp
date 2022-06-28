#ifndef CRYPTO3_HASH_REINFORCED_COCNRETE_HPP
#define CRYPTO3_HASH_REINFORCED_COCNRETE_HPP

#include "detail/reinforced_concrete/reinforced_concrete_policy.hpp"
#include "detail/reinforced_concrete/reinforced_concrete_functions.hpp"
namespace nil{
    namespace crypto3{
        namespace hashes{
            template <typename FieldType>
            struct reinforced_concrete_compressor{
                typedef detail::reinforced_concrete_functions<FieldType> policy_type;
                typedef typename policy_type::element_type element_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t block_words = policy_type::block_words;
                constexpr static const std::size_t block_bits = policy_type::block_bits;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t state_words = policy_type::state_words;
                constexpr static const std::size_t state_bits = policy_type::state_bits;
                typedef typename policy_type::state_type state_type;

                static inline void process_block(state_type& state, block_type& block){
                    for(int i = 0; i < block_words; ++i){
                        state[i] ^= block[i];
                    }

                    policy_type::permute(state);
                }
            };
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_HASH_REINFORCED_COCNRETE_HPP