//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_LFSR_HPP
#define CRYPTO3_HASH_POSEIDON_LFSR_HPP

#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision::literals;

#define POSEIDON_LFSR_GENERATOR_LEN 80

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(POSEIDON_LFSR_GENERATOR_LEN);

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_lfsr {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef typename FieldType::value_type element_type;
                    typedef typename FieldType::modulus_type modulus_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t lfsr_state_len = 80;
                    typedef std::bitset<lfsr_state_len> lfsr_state_type;

                    // TODO: maybe make without storing state in class instance
                    // TODO: then make const all methods of this class
                    inline poseidon_lfsr() {
                        int i;
                        std::size_t offset = 0;
                        for (i = 1; i >= 0; i--)
                            lfsr_state[offset++] = (1 >> i) & 1;    // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            lfsr_state[offset++] = (1 >> i) & 1;    // s-box - as in filecoin
                        for (i = 11; i >= 0; i--)
                            lfsr_state[offset++] = (word_bits >> i) & 1;
                        for (i = 11; i >= 0; i--)
                            lfsr_state[offset++] = (Arity >> i) & 1;
                        for (i = 9; i >= 0; i--)
                            lfsr_state[offset++] = (full_rounds >> i) & 1;
                        for (i = 9; i >= 0; i--)
                            lfsr_state[offset++] = (part_rounds >> i) & 1;
                        for (i = 29; i >= 0; i--)
                            lfsr_state[offset++] = 1;
                        // idling
                        for (i = 0; i < 160; i++)
                            get_next_raw_bit();
                    }

                    // get next element
                    inline element_type get_next_element() {
                        modulus_type round_const;
                        while (true) {
                            round_const = 0;
                            round_const |= get_next_bit();
                            for (std::size_t i = 1; i < word_bits; i++) {
                                round_const <<= 1;
                                round_const |= get_next_bit() ? 1 : 0;
                            }
                            if (round_const <
                                FieldType::modulus)    // filecoin oriented - remake when integrate in the project
                                break;
                        }
                        return element_type(round_const);
                    }

                    inline bool get_next_bit() {
                        while (true) {
                            if (get_next_raw_bit())
                                break;
                            else
                                get_next_raw_bit();
                        }
                        return get_next_raw_bit();
                    }

                    inline bool get_next_raw_bit() {
                        bool next_v = lfsr_state[0] ^ lfsr_state[13] ^ lfsr_state[23] ^ lfsr_state[38] ^
                                      lfsr_state[51] ^ lfsr_state[62];
                        lfsr_state >>= 1;
                        lfsr_state[lfsr_state_len - 1] = next_v;
                        return next_v;
                    }

                private:
                    lfsr_state_type lfsr_state;
                };


                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_lfsr_constexpr {
                    typedef typename FieldType::value_type ElementType;
                    typedef typename FieldType::modulus_type modulus_type;
                    constexpr static const modulus_type modulus = FieldType::modulus;

                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t state_bits = POSEIDON_LFSR_GENERATOR_LEN;
                    typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                        state_bits, state_bits, boost::multiprecision::cpp_integer_type::unsigned_magnitude,
                        boost::multiprecision::cpp_int_check_type::unchecked, void>>
                        state_type;

                    constexpr static const std::size_t constants_number = (full_rounds + part_rounds) * state_words;
                    typedef cotila::vector<ElementType, constants_number> round_constants_type;
                    typedef cotila::vector<ElementType, state_words> round_constants_arity_slice_type;


                    constexpr void generate_round_constants() {
                        modulus_type constant = 0;
                        state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t i = 0; i < (full_rounds + part_rounds) * Arity; i++) {
                            while (true) {
                                constant = 0;
                                for (std::size_t i = 0; i < word_bits; i++) {
                                    lfsr_state = update_state(lfsr_state);
                                    constant =
                                        set_new_bit<modulus_type>(constant, get_state_bit(lfsr_state, state_bits - 1));
                                }
                                if (constant < modulus) {
                                    round_constants[i] = ElementType(constant);
                                    break;
                                }
                            }
                        }
                    }

                    constexpr static state_type get_lfsr_init_state() {
                        state_type state = 0;
                        int i = 0;
                        for (i = 1; i >= 0; i--)
                            state = set_new_bit(state, (1 >> i) & 1);    // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            state = set_new_bit(state, (1 >> i) & 1);    // s-box - as in filecoin
                        for (i = 11; i >= 0; i--)
                            state = set_new_bit(state, (word_bits >> i) & 1);
                        for (i = 11; i >= 0; i--)
                            state = set_new_bit(state, (Arity >> i) & 1);
                        for (i = 9; i >= 0; i--)
                            state = set_new_bit(state, (full_rounds >> i) & 1);
                        for (i = 9; i >= 0; i--)
                            state = set_new_bit(state, (part_rounds >> i) & 1);
                        for (i = 29; i >= 0; i--)
                            state = set_new_bit(state, 1);
                        // idling
                        for (i = 0; i < 160; i++)
                            state = update_state_raw(state);
                        return state;
                    }

                    constexpr static state_type update_state(state_type state) {
                        while (true) {
                            state = update_state_raw(state);
                            if (get_state_bit(state, state_bits - 1))
                                break;
                            else
                                state = update_state_raw(state);
                        }
                        return update_state_raw(state);
                    }

                    constexpr static state_type update_state_raw(state_type state) {
                        bool new_bit = get_state_bit(state, 0) != get_state_bit(state, 13) !=
                                       get_state_bit(state, 23) != get_state_bit(state, 38) !=
                                       get_state_bit(state, 51) != get_state_bit(state, 62);
                        return set_new_bit(state, new_bit);
                    }

                    constexpr static bool get_state_bit(state_type state, std::size_t pos) {
                        state_type bit_getter = 1;
                        bit_getter <<= (state_bits - 1 - pos);
                        return (state & bit_getter) ? true : false;
                    }

                    template<typename T>
                    constexpr static T set_new_bit(T var, bool new_bit) {
                        return (var << 1) | (new_bit ? 1 : 0);
                    }

                    constexpr poseidon_lfsr_constexpr() : round_constants() {
                        generate_round_constants();
                    }

                    round_constants_type round_constants;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_LFSR_HPP

