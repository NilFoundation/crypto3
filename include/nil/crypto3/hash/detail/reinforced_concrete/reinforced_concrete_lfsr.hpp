//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_HASH_REINFORCED_CONCRETE_LFSR_HPP
#define CRYPTO3_HASH_REINFORCED_CONCRETE_LFSR_HPP

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/hash/detail/reinforced_concrete/reinforced_concrete_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                using namespace nil::crypto3::multiprecision;

                // round constants generating is taken from poseidon_lsfr
                template<typename FieldType>
                struct reinforced_concrete_lfsr {
                    typedef reinforced_concrete_policy<FieldType> policy_type;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;
                    constexpr static const std::size_t full_rounds = 2 * (part_rounds + 1);

                    typedef typename FieldType::value_type element_type;
                    typedef typename FieldType::integral_type integral_type;
                    constexpr static const integral_type modulus = FieldType::modulus;

                    constexpr static const std::size_t lfsr_state_bits = 80;
                    typedef number<backends::cpp_int_backend<lfsr_state_bits, lfsr_state_bits,
                                                             cpp_integer_type::unsigned_magnitude,
                                                             cpp_int_check_type::unchecked, void>>
                        lfsr_state_type;

                    constexpr static const std::size_t constants_number = full_rounds * state_words;
                    typedef algebra::vector<element_type, constants_number> round_constants_type;

                    constexpr void generate_round_constants() {
                        integral_type constant = 0;
                        lfsr_state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t i = 0; i < constants_number; i++) {
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

                    constexpr reinforced_concrete_lfsr() : round_constants() {
                        generate_round_constants();
                    }

                    round_constants_type round_constants;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_REINFORCED_CONCRETE_LFSR_HPP
