//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
#define CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_mds_matrix.hpp>

#include <boost/assert.hpp>

#include <bitset>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(GRAIN_LFSR_STATE_LEN);

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_lfsr {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef typename FieldType::value_type ElementType;

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
                            lfsr_state[offset++] = (1 >> i) & 1; // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            lfsr_state[offset++] = (1 >> i) & 1; // s-box - as in filecoin
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
                    inline ElementType get_next_element() {
                        typename ElementType::number_type round_const;
                        while (true) {
                            round_const = 0;
                            round_const |= get_next_bit();
                            for (std::size_t i = 1; i < word_bits; i++) {
                                round_const <<= 1;
                                round_const |= get_next_bit();
                            }
                            if (round_const < ElementType::modulus) // filecoin oriented - remake when integrate in the project
                                break;
                        }
                        return ElementType(round_const);
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
                        bool next_v = lfsr_state[0] ^ lfsr_state[13] ^ lfsr_state[23] ^ lfsr_state[38] ^ lfsr_state[51] ^ lfsr_state[62];
                        lfsr_state >>= 1;
                        lfsr_state[lfsr_state_len - 1] = next_v;
                        return next_v;
                    }

                private:
                    lfsr_state_type lfsr_state;
                };


                template<typename modulus_type, std::size_t Arity, std::size_t modulus_bits, std::size_t full_rounds, std::size_t part_rounds>
                struct poseidon_lfsr_constexpr_bls12_381 {
                    // constexpr static const modulus_type modulus = FieldType::modulus;
                    constexpr static const modulus_type modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui255;

                    constexpr static const std::size_t state_bits = 80;
                    typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<state_bits, state_bits,
                        boost::multiprecision::cpp_integer_type::unsigned_magnitude, boost::multiprecision::cpp_int_check_type::unchecked, void>>
                        state_type;

                    constexpr void generate_round_constants() {
                        modulus_type constant = 0;
                        state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t i = 0; i < (full_rounds + part_rounds) * Arity; i++) {
                            while (true) {
                                constant = 0;
                                for (std::size_t i = 0; i < modulus_bits; i++) {
                                    lfsr_state = update_state(lfsr_state);
                                    constant = set_new_bit<modulus_type>(constant, get_state_bit(lfsr_state, state_bits - 1));
                                }
                                if (constant < modulus) {
                                    constants[i] = constant;
                                    break;
                                }
                            }
                        }
                    }

                    constexpr void generate_round_constants_unfolded() {
                        modulus_type constant = 0;
                        bool new_bit = false;
                        state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t i = 0; i < (full_rounds + part_rounds) * Arity; i++) {
                            while (true) {
                                constant = 0;
                                for (std::size_t i = 0; i < modulus_bits; i++) {
                                    while (true) {
                                        new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                                                ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                                                ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                                                ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                                                ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                                                ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                                        lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                                        if (new_bit)
                                            break;
                                        else {
                                            new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                                                    ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                                                    ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                                                    ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                                                    ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                                                    ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                                            lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                                        }
                                    }
                                    new_bit = ((lfsr_state & (0x1_cppui80 << (state_bits - 1))) != 0) !=
                                            ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 13))) != 0) !=
                                            ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 23))) != 0) !=
                                            ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 38))) != 0) !=
                                            ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 51))) != 0) !=
                                            ((lfsr_state & (0x1_cppui80 << (state_bits - 1 - 62))) != 0);
                                    lfsr_state = (lfsr_state << 1) | (new_bit ? 1 : 0);
                                    constant = (constant << 1) | (lfsr_state & 1);
                                }
                                if (constant < modulus) {
                                    constants[i] = constant;
                                    break;
                                }
                            }
                        }
                    }

                    constexpr static state_type get_lfsr_init_state() {
                        state_type state = 0;
                        int i = 0;
                        for (i = 1; i >= 0; i--)
                            state = set_new_bit(state, (1 >> i) & 1); // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            state = set_new_bit(state, (1 >> i) & 1); // s-box - as in filecoin
                        for (i = 11; i >= 0; i--)
                            state = set_new_bit(state, (modulus_bits >> i) & 1);
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
                        bool new_bit = get_state_bit(state, 0) != get_state_bit(state, 13) != get_state_bit(state, 23) !=
                                    get_state_bit(state, 38) != get_state_bit(state, 51) != get_state_bit(state, 62);
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

                    constexpr poseidon_lfsr_constexpr() : constants() {
                        // generate_round_constants();
                        generate_round_constants_unfolded();
                    }

                    modulus_type constants[(full_rounds + part_rounds) * Arity];
                };


                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_constants {

                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef poseidon_mds_matrix<FieldType, Arity, strength> mds_matrix_type;
                    typedef poseidon_lfsr<FieldType, Arity, strength> constants_generator_type;
                    typedef poseidon_lfsr_constexpr_bls12_381<typename FieldType::modulus_type, Arity, FieldType::modulus_bits, policy_type::full_rounds, policy_type::part_rounds> constants_generator_constexpr_type;
                    typedef typename FieldType::value_type ElementType;
                    typedef typename mds_matrix_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t round_constants_size = (full_rounds + part_rounds) * state_words;
                    constexpr static const std::size_t equivalent_round_constants_size = (full_rounds + 1) * state_words + part_rounds - 1;
                    typedef boost::numeric::ublas::vector<ElementType> round_constants_type;

                    // constexpr static const constants_generator_constexpr_type constants_generator_constexpr();

                    /*
                    * =============================================================================================================
                    * Optimized
                    * =============================================================================================================
                    */

                    static inline void arc_sbox_mds_full_round_optimized_first(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds, "wrong using: arc_sbox_mds_full_round_optimized_first");
                        std::size_t constant_number_base = round_number * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        mds_matrix_type::product_with_mds_matrix(A);
                    }

                    static inline void arc_sbox_mds_full_round_optimized_last(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds + part_rounds, "wrong using: arc_sbox_mds_full_round_optimized_last");
                        std::size_t constant_number_base = (half_full_rounds + 1) * state_words + (part_rounds - 1)
                            + (round_number - half_full_rounds - part_rounds) * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        mds_matrix_type::product_with_mds_matrix(A);
                    }

                    static inline void arc_mds_part_round_optimized_init(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds, "wrong using: arc_mds_part_round_optimized_init");
                        std::size_t constant_number_base = half_full_rounds * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                        }
                        mds_matrix_type::product_with_equivalent_mds_matrix_init(A, round_number);
                    }

                    static inline void sbox_arc_mds_part_round_optimized(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds
                            && round_number < half_full_rounds + part_rounds - 1, "wrong using: sbox_arc_mds_part_round_optimized");
                        std::size_t constant_number_base = (half_full_rounds + 1) * state_words + (round_number - half_full_rounds - 1) + 1;
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        A[0] += get_equivalent_round_constant(constant_number_base);
                        mds_matrix_type::product_with_equivalent_mds_matrix(A, round_number);
                    }

                    static inline void sbox_mds_part_round_optimized_last(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds + part_rounds - 1, "wrong using: sbox_mds_part_round_optimized_last");
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        mds_matrix_type::product_with_equivalent_mds_matrix(A, round_number);
                    }

                    /*
                    * =============================================================================================================
                    * Default
                    * =============================================================================================================
                    */

                    static inline void arc_sbox_mds_full_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds
                            || round_number >= half_full_rounds + part_rounds, "wrong using: arc_sbox_mds_full_round");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_round_constant(round_number * state_words + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        mds_matrix_type::product_with_mds_matrix(A);
                    }

                    static inline void arc_sbox_mds_part_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds
                            && round_number < half_full_rounds + part_rounds, "wrong using: arc_sbox_mds_part_round");
                        for (std::size_t i = 0; i < state_words; i++)
                            A[i] += get_round_constant(round_number * state_words + i);
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        mds_matrix_type::product_with_mds_matrix(A);
                    }

                // private:
                    static inline const ElementType &get_equivalent_round_constant(std::size_t constant_number) {
                        return generate_equivalent_round_constants()[constant_number];
                    }

                    // See https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/d9382dbd933cc559bd12ee3fa7d32ea934ace43d/code/poseidonperm_x3_64_24_optimized.sage#L40
                    static inline const round_constants_type &generate_equivalent_round_constants() {
                        static const round_constants_type equivalent_round_constants = [](){
                            round_constants_type equivalent_round_constants(equivalent_round_constants_size);
                            mds_matrix_type mds_matrix;
                            round_constants_type round_constants = generate_round_constants();
                            state_vector_type inv_cip1(state_words);
                            state_vector_type agregated_round_constants;
                            std::size_t equivalent_constant_number_base = (half_full_rounds + 1) * state_words - half_full_rounds;

                            for (std::size_t i = 0; i < half_full_rounds * state_words; i++) {
                                equivalent_round_constants[i] = round_constants[i];
                                equivalent_round_constants[equivalent_round_constants_size - i - 1] = round_constants[round_constants_size - i - 1];
                            }

                            for (std::size_t i = half_full_rounds * state_words; i < half_full_rounds * state_words + state_words; i++) {
                                equivalent_round_constants[i] = round_constants[i];
                            }

                            for (std::size_t r = half_full_rounds + part_rounds - 2; r >= half_full_rounds; r--) {
                                agregated_round_constants = boost::numeric::ublas::subrange(
                                    round_constants,
                                    (r + 1) * state_words,
                                    (r + 1) * state_words + state_words
                                ) + inv_cip1;
                                mds_matrix_type::product_with_inverse_mds_matrix_noalias(agregated_round_constants, inv_cip1);
                                equivalent_round_constants[equivalent_constant_number_base + r] = inv_cip1[0];
                                inv_cip1[0] = 0;
                            }

                            mds_matrix_type::product_with_inverse_mds_matrix_noalias(agregated_round_constants, inv_cip1);
                            inv_cip1[0] = 0;
                            boost::numeric::ublas::subrange(
                                equivalent_round_constants,
                                half_full_rounds * state_words,
                                half_full_rounds * state_words + state_words
                            ) += inv_cip1;

                            return equivalent_round_constants;
                        }();
                        return equivalent_round_constants;
                    }

                    static inline const ElementType &get_round_constant(std::size_t constant_number) {
                        return generate_round_constants()[constant_number];
                    }

                    static inline const round_constants_type &generate_round_constants() {
                        static const round_constants_type round_constants = [](){
                            round_constants_type round_constants(round_constants_size);
                            constants_generator_type constants_generator;
                            // constexpr constants_generator_constexpr_type constants_generator_constexpr;
                            for (std::size_t i = 0; i < round_constants_size; i++) {
                                round_constants[i] = constants_generator.get_next_element();
                                // round_constants[i] = constants_generator_constexpr.constants[i];
                            }
                            return round_constants;
                        }();
                        return round_constants;
                    }
                };

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
