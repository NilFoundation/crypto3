//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_POLICY_HPP
#define CRYPTO3_HASH_POSEIDON_POLICY_HPP

#include <array>
#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // at this moment only for bls12-381 - filecoin oriented implementation

                /*!
                 * @brief Poseidon internal parameters
                 * @tparam FieldType type of field
                 * @tparam Arity arity of input block for Poseidon permutation in field elements
                 * @tparam Strength mode of Poseidon permutation
                 */
                template<typename FieldType, std::size_t Arity>
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

                    constexpr static const std::size_t full_rounds = 8;
                    constexpr static const std::size_t half_full_rounds = 4;

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

                template<typename FieldType, std::size_t Arity, std::size_t PartRounds, typename Enable = void>
                struct poseidon_policy;

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 1, PartRounds,
                                       std::enable_if_t<PartRounds == 69 || PartRounds == 55>> :
                    base_poseidon_policy<FieldType, 1> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 69 : 55;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 2, PartRounds,
                                       std::enable_if_t<PartRounds == 69 || PartRounds == 55>> :
                    base_poseidon_policy<FieldType, 2> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 69 : 55;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 3, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 3> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 70 : 56;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 4, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 4> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 70 : 56;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 5, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 5> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 70 : 56;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 6, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 6> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 70 : 56;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 7, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 7> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 8> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 9, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 9> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 10, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 10> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 11, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 11> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 12, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 12> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 13, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 13> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 14, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 14> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 72 : 57;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 15, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 15> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 74 : 59;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 16, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 16> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 74 : 59;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 24, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 24> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 74 : 59;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 36, PartRounds,
                                       std::enable_if_t<PartRounds == 75 || PartRounds == 60>> :
                    base_poseidon_policy<FieldType, 36> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 75 : 60;
                };

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 64, PartRounds,
                                       std::enable_if_t<PartRounds == 77 || PartRounds == 61>> :
                    base_poseidon_policy<FieldType, 64> {
                    constexpr static const std::size_t part_rounds = PartRounds;// Strength ? 77 : 61;
                };

                // continue define partial specialized template classes for each arity separately...

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
