//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_POLICY_HPP
#define CRYPTO3_HASH_POSEIDON_POLICY_HPP

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // at this moment only for bls12-381 - filecoin oriented im

                /*!
                 * @brief Poseidon internal parameters
                 * @tparam FieldType type of field
                 * @tparam ElementType type of field element
                 * @tparam t arity of Poseidon permutation in field elements
                 */
                template<typename FieldType, std::size_t Arity>
                struct base_poseidon_policy {
                    typedef typename FieldType::value_type ElementType;

                    constexpr static const std::size_t word_bits = FieldType::modulus_bits;
                    typedef ElementType word_type;

                    constexpr static const std::size_t digest_bits = FieldType::modulus_bits;
                    typedef ElementType digest_type;

                    constexpr static const std::size_t state_bits = Arity * FieldType::modulus_bits;
                    constexpr static const std::size_t state_words = Arity;
                    typedef std::array<ElementType, Arity> state_type;

                    constexpr static const std::size_t block_bits = (Arity - 1) * FieldType::modulus_bits;
                    constexpr static const std::size_t block_words = Arity - 1;
                    typedef std::array<ElementType, Arity - 1> block_type;

                    struct iv_generator {
                        // TODO: return-value seems not to be const in reality
                        // TODO: maybe it would be done in constexpr way
                        const state_type &operator()() const {
                            static const state_type H0 = [](){
                                state_type H;
                                H.fill(ElementType(0));
                                return H;
                            }();
                            return H0;
                        }
                    };
                };


                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_policy;


                template<typename FieldType, bool strength>
                struct poseidon_policy<FieldType, 2, strength> :
                    base_poseidon_policy<FieldType, 2>
                {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = strength ? 69 : 55;
                };


                template<typename FieldType, bool strength>
                struct poseidon_policy<FieldType, 3, strength> :
                    base_poseidon_policy<FieldType, 3>
                {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = strength ? 69 : 55;
                };


                template<typename FieldType, bool strength>
                struct poseidon_policy<FieldType, 4, strength> :
                    base_poseidon_policy< FieldType, 4>
                {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = strength ? 70 : 56;
                };

                template<typename FieldType, bool strength>
                struct poseidon_policy<FieldType, 5, strength> :
                    base_poseidon_policy< FieldType, 5>
                {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = strength ? 70 : 56;
                };

                template<typename FieldType, bool strength>
                struct poseidon_policy<FieldType, 9, strength> :
                    base_poseidon_policy< FieldType, 9>
                {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = strength ? 72 : 57;
                };

                // continue define partial specialized temlate classes for each arity separately...

            }         // namespace detail
        }             // namespace hashes
    }                 // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
