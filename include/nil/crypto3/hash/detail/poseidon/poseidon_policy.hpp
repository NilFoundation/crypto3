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

#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                /*!
                 * @brief Poseidon internal parameters
                 * @tparam FieldType type of field
                 * @tparam Rate Rate of input block for Poseidon permutation in field elements
                 * @tparam Capacity Capacity or inner part of Poseidon permutation in field elements
                 * @tparam Security mode of Poseidon permutation
                 */
                template<typename FieldType, std::size_t Security, std::size_t Rate, std::size_t Capacity, std::size_t SBoxPower, std::size_t FullRounds, std::size_t PartRounds, bool MinaVersion>
                struct base_poseidon_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;

                    constexpr static const std::size_t word_bits = field_type::modulus_bits;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = field_type::modulus_bits;
                    typedef element_type digest_type;

                    // TODO: Not sure what is best to use here.
                    typedef typename stream_endian::big_octet_big_bit digest_endian;

                    constexpr static const std::size_t state_bits = (Rate + Capacity) * field_type::modulus_bits;
                    constexpr static const std::size_t state_words = (Rate + Capacity);
                    typedef std::array<element_type, Rate + Capacity> state_type;

                    constexpr static const std::size_t block_bits = Rate * field_type::modulus_bits;

                    // TODO: Check if this value is correct.
                    constexpr static const std::size_t length_bits = word_bits;

                    constexpr static const std::size_t block_words = Rate;
                    typedef std::array<element_type, Rate> block_type;

                    constexpr static const std::size_t full_rounds = FullRounds;
                    constexpr static const std::size_t half_full_rounds = FullRounds >> 1;
                    constexpr static const std::size_t part_rounds = PartRounds;

                    constexpr static const std::size_t security = Security;
                    constexpr static const std::size_t rate = Rate;
                    constexpr static const std::size_t capacity = Capacity;
                    constexpr static const std::size_t sbox_power = SBoxPower;

                    constexpr static const bool mina_version = MinaVersion; 

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

                /*!
                 * @brief Policy class for the original implementation.
                 * @tparam FieldType Type of the field.
                 * @tparam Security The bit strength of hash, one of [80, 128, 256].
                 * @tparam Rate Rate of input block for Poseidon permutation in field elements. Values of 2 or 4 are used with Merkle Trees. 
                 * @tparam Capacity Capacity or inner part of Poseidon permutation in field elements.
                 */
                template<typename FieldType, std::size_t Security, std::size_t Rate, typename Enable = void>
                struct poseidon_policy;

                template<typename FieldType, std::size_t Rate>
                struct poseidon_policy<FieldType, 80, Rate,
                        std::enable_if_t<Rate == 1 || Rate == 2 >> :
                    base_poseidon_policy<FieldType, 80, Rate, 1, 5, 8, 33, false> {};

                template<typename FieldType>
                struct poseidon_policy<FieldType, 80, 4> :
                    base_poseidon_policy<FieldType, 80, 4, 1, 5, 8, 35, false> {};

                template<typename FieldType, std::size_t Rate>
                struct poseidon_policy<FieldType, 128, Rate,
                        std::enable_if_t<Rate == 1 || Rate == 2 >> :
                    base_poseidon_policy<FieldType, 128, Rate, 1, 5, 8, 57, false> {};

                template<typename FieldType>
                struct poseidon_policy<FieldType, 128, 4> :
                    base_poseidon_policy<FieldType, 128, 4, 1, 5, 8, 60, false> {};

                template<typename FieldType>
                struct poseidon_policy<FieldType, 128, 8> :
                    base_poseidon_policy<FieldType, 128, 4, 1, 5, 8, 63, false> {};

                template<typename FieldType, std::size_t Rate>
                struct poseidon_policy<FieldType, 256, Rate,
                        std::enable_if_t<Rate <= 4 >> :
                    base_poseidon_policy<FieldType, 256, Rate, 1, 5, 8, 120, false> {};

                /*!
                 * @brief Policy class for Mina implementation.
                 * Mina uses X^7 S-boxes,
                 *      changes the order of arc, s-box and mds operations and
                 *      they don't use partial rounds.
                 * Only 1 options is supported, with Rate=2, Capacity=1, 55 full rounds and security of 128 bits.
                 * @tparam FieldType Type of the field.
                 */
                template<typename FieldType>
                struct mina_poseidon_policy : base_poseidon_policy<FieldType, 128, 2, 1, 7, 55, 0, true> {};

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
