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
                 * @tparam Rate Rate of input block for Poseidon permutation in field elements
                 * @tparam Capacity Capacity or inner part of Poseidon permutation in field elements
                 * @tparam Strength mode of Poseidon permutation
                 */
                template<typename FieldType, std::size_t Rate, std::size_t Capacity, std::size_t SBoxPower, std::size_t FullRounds, std::size_t PartRounds>
                struct base_poseidon_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;

                    constexpr static const std::size_t word_bits = field_type::modulus_bits;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = field_type::modulus_bits;
                    typedef element_type digest_type;

                    constexpr static const std::size_t state_bits = (Rate + Capacity) * field_type::modulus_bits;
                    constexpr static const std::size_t state_words = (Rate + Capacity);
                    typedef std::array<element_type, Rate + Capacity> state_type;

                    constexpr static const std::size_t block_bits = Rate * field_type::modulus_bits;
                    constexpr static const std::size_t block_words = Rate;
                    typedef std::array<element_type, Rate> block_type;

                    constexpr static const std::size_t full_rounds = FullRounds;
                    constexpr static const std::size_t half_full_rounds = FullRounds >> 1;
                    constexpr static const std::size_t part_rounds = PartRounds;

                    constexpr static const std::size_t rate = Rate;
                    constexpr static const std::size_t capacity = Capacity;
                    constexpr static const std::size_t sbox_power = SBoxPower;

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

                template<typename FieldType, std::size_t Rate, std::size_t Capacity, std::size_t SBoxPower, std::size_t FullRounds, std::size_t PartRounds, typename Enable = void>
                struct poseidon_policy;

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 1, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 69 || PartRounds == 55>> :
                    base_poseidon_policy<FieldType, 1, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 2, 1,  5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 69 || PartRounds == 55>> :
                    base_poseidon_policy<FieldType, 2, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 3, 1,  5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 3, 1,  5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 4, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 4, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 5, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 5, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 6, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 70 || PartRounds == 56>> :
                    base_poseidon_policy<FieldType, 6, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 7, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 7, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 8, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 8, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 9, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 9, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 10, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 10, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 11, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 11, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 12, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 12, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 13, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 13, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 14, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 72 || PartRounds == 57>> :
                    base_poseidon_policy<FieldType, 14, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 15, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 15, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 16, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 16, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 24, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 74 || PartRounds == 59>> :
                    base_poseidon_policy<FieldType, 24, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 36, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 75 || PartRounds == 60>> :
                    base_poseidon_policy<FieldType, 36, 1, 5, 8, PartRounds> {};

                template<typename FieldType, std::size_t PartRounds>
                struct poseidon_policy<FieldType, 64, 1, 5, 8, PartRounds,
                                       std::enable_if_t<PartRounds == 77 || PartRounds == 61>> :
                    base_poseidon_policy<FieldType, 64, 1, 5, 8, PartRounds> {};

                // continue define partial specialized template classes for each Rate separately...

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
