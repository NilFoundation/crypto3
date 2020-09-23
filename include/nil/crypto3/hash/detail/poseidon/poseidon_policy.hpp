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
                 * @tparam Arity arity of input block for Poseidon permutation in field elements
                 * @tparam Strength mode of Poseidon permutatuion
                 */
                template<typename FieldType, std::size_t Arity, bool Strength>
                struct base_poseidon_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;

                    constexpr static const std::size_t word_bits = field_type::modulus_bits;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = field_type::modulus_bits;
                    typedef element_type digest_type;

                    constexpr static const std::size_t state_bits = (Arity + 1) * field_type::modulus_bits;
                    constexpr static const std::size_t state_words = (Arity + 1);
                    typedef std::array<element_type, Arity + 1> state_type;

                    constexpr static const std::size_t block_bits = Arity * field_type::modulus_bits;
                    constexpr static const std::size_t block_words = Arity;
                    typedef std::array<element_type, Arity> block_type;

                    constexpr static const bool strength = Strength;

                    struct iv_generator {
                        // TODO: maybe it would be done in constexpr way
                        const state_type &operator()() const {
                            static const state_type H0 = []() {
                                state_type H;
                                H.fill(element_type(0));
                                return H;
                            }();
                            return H0;
                        }
                    };
                };

                template<typename FieldType, std::size_t Arity, bool Strength>
                struct poseidon_policy;

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 1, Strength> : base_poseidon_policy<FieldType, 1, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 69 : 55;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 2, Strength> : base_poseidon_policy<FieldType, 2, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 69 : 55;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 3, Strength> : base_poseidon_policy<FieldType, 3, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 70 : 56;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 4, Strength> : base_poseidon_policy<FieldType, 4, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 70 : 56;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 5, Strength> : base_poseidon_policy<FieldType, 5, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 70 : 56;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 6, Strength> : base_poseidon_policy<FieldType, 6, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 70 : 56;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 7, Strength> : base_poseidon_policy<FieldType, 7, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 8, Strength> : base_poseidon_policy<FieldType, 8, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 9, Strength> : base_poseidon_policy<FieldType, 9, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 10, Strength> : base_poseidon_policy<FieldType, 10, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 11, Strength> : base_poseidon_policy<FieldType, 11, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 12, Strength> : base_poseidon_policy<FieldType, 12, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 13, Strength> : base_poseidon_policy<FieldType, 13, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 14, Strength> : base_poseidon_policy<FieldType, 14, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 72 : 57;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 15, Strength> : base_poseidon_policy<FieldType, 15, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 74 : 59;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 16, Strength> : base_poseidon_policy<FieldType, 16, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 74 : 59;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 24, Strength> : base_poseidon_policy<FieldType, 24, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 74 : 59;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 36, Strength> : base_poseidon_policy<FieldType, 36, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 75 : 60;
                };

                template<typename FieldType, bool Strength>
                struct poseidon_policy<FieldType, 64, Strength> : base_poseidon_policy<FieldType, 64, Strength> {
                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;
                    constexpr static const std::size_t part_rounds = Strength ? 77 : 61;
                };

                // continue define partial specialized template classes for each arity separately...

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
