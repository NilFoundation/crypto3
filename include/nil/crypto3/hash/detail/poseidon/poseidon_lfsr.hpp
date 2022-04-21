//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_LFSR_HPP
#define CRYPTO3_HASH_POSEIDON_LFSR_HPP

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>

#include <nil/crypto3/hash/detail/poseidon/kimchi_constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                using namespace nil::crypto3::multiprecision;

                template<typename poseidon_policy_type>
                struct poseidon_lfsr {
                    typedef poseidon_policy_type policy_type;
                    typedef typename policy_type::field_type field_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    typedef typename field_type::value_type element_type;
                    typedef typename field_type::integral_type integral_type;
                    constexpr static const integral_type modulus = field_type::modulus;

                    constexpr static const std::size_t lfsr_state_bits = 80;
                    typedef number<backends::cpp_int_backend<
                        lfsr_state_bits, lfsr_state_bits, cpp_integer_type::unsigned_magnitude,
                        cpp_int_check_type::unchecked, void>>
                        lfsr_state_type;

                    constexpr static const std::size_t constants_number = (full_rounds + part_rounds) * state_words;
                    typedef algebra::vector<element_type, constants_number> round_constants_type;

                    constexpr void generate_round_constants() {
                        if (policy_type::full_rounds == 55) { //TODO: kimchi constants
                            for (std::size_t i = 0; i < (full_rounds + part_rounds) * state_words; i++) {
                                std::size_t idx1 = i / state_words;
                                std::size_t idx2 = i % state_words;
                                round_constants[i] = poseidon_constants_kimchi_vesta::round_constant[idx1][idx2];
                            }

                            return;
                        }
                        integral_type constant = 0;
                        lfsr_state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t i = 0; i < (full_rounds + part_rounds) * state_words; i++) {
                            while (true) {
                                constant = 0;
                                for (std::size_t j = 0; j < word_bits; j++) {
                                    lfsr_state = update_lfsr_state(lfsr_state);
                                    constant = set_new_bit<integral_type>(
                                        constant, get_lfsr_state_bit(lfsr_state, lfsr_state_bits - 1));
                                }
                                if (constant < modulus) {
                                    round_constants[i] = element_type(constant);
                                    break;
                                }
                            }
                        }
                    }

                    constexpr lfsr_state_type get_lfsr_init_state() {
                        lfsr_state_type state = 0;
                        int i = 0;
                        for (i = 1; i >= 0; i--)
                            state = set_new_bit(state, (1U >> i) & 1U);    // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            state = set_new_bit(state, (1U >> i) & 1U);    // s-box - as in filecoin
                        for (i = 11; i >= 0; i--)
                            state = set_new_bit(state, (word_bits >> i) & 1U);
                        for (i = 11; i >= 0; i--)
                            state = set_new_bit(state, (state_words >> i) & 1U);
                        for (i = 9; i >= 0; i--)
                            state = set_new_bit(state, (full_rounds >> i) & 1U);
                        for (i = 9; i >= 0; i--)
                            state = set_new_bit(state, (part_rounds >> i) & 1U);
                        for (i = 29; i >= 0; i--)
                            state = set_new_bit(state, 1);
                        // idling
                        for (i = 0; i < 160; i++)
                            state = update_lfsr_state_raw(state);
                        return state;
                    }

                    constexpr lfsr_state_type update_lfsr_state(lfsr_state_type state) {
                        while (true) {
                            state = update_lfsr_state_raw(state);
                            if (get_lfsr_state_bit(state, lfsr_state_bits - 1))
                                break;
                            else
                                state = update_lfsr_state_raw(state);
                        }
                        return update_lfsr_state_raw(state);
                    }

                    constexpr inline lfsr_state_type update_lfsr_state_raw(lfsr_state_type state) {
                        bool new_bit = get_lfsr_state_bit(state, 0) != get_lfsr_state_bit(state, 13) !=
                                       get_lfsr_state_bit(state, 23) != get_lfsr_state_bit(state, 38) !=
                                       get_lfsr_state_bit(state, 51) != get_lfsr_state_bit(state, 62);
                        return set_new_bit(state, new_bit);
                    }

                    constexpr inline bool get_lfsr_state_bit(lfsr_state_type state, std::size_t pos) {
                        return bit_test(state, lfsr_state_bits - 1 - pos);
                    }

                    template<typename T>
                    constexpr inline T set_new_bit(T var, bool new_bit) {
                        return (var << 1) | (new_bit ? 1 : 0);
                    }

                    constexpr poseidon_lfsr() : round_constants() {
                        generate_round_constants();
                    }

                    round_constants_type round_constants;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_LFSR_HPP
