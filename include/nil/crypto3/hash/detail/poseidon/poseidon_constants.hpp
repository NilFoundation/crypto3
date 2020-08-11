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


namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename field_type, typename element_type, std::size_t t, bool strength>
                struct poseidon_constants {

                    typedef poseidon_policy<field_type, element_type, t, strength> policy_type;
                    typedef poseidon_mds_matrix<field_type, element_type, t, strength> mds_matrix_type;
                    typedef typename mds_matrix_type::state_vector_type state_vector_type;

                    // constexpr static std::size_t const block_words = policy_type::block_words;

                    constexpr static std::size_t const state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static std::size_t const full_rounds = policy_type::full_rounds;
                    constexpr static std::size_t const half_full_rounds = policy_type::half_full_rounds;
                    constexpr static std::size_t const part_rounds = policy_type::part_rounds;

                    constexpr static std::size_t const round_constants_size = (full_rounds + part_rounds) * state_words;
                    typedef state_vector_type round_constants_type;

                    constexpr static std::size_t const equivalent_round_constants_size = (full_rounds + 1) * state_words + part_rounds - 1;
                    typedef state_vector_type equivalent_round_constants_type;

                    constexpr static std::size_t const word_bits = policy_type::word_bits;

                    inline void arc_sbox_full_round_optimized_first(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds, "error: arc_sbox_full_round_optimized_first");
                        std::size_t constant_number_base = round_number * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                    }

                    inline void arc_sbox_full_round_optimized_last(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds + part_rounds, "error: arc_sbox_full_round_optimized_last");
                        std::size_t constant_number_base = (half_full_rounds + 1) * state_words + (part_rounds - 1)
                                                        + (round_number - half_full_rounds - part_rounds) * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                    }

                    inline void arc_sbox_part_round_optimized_init(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds, "error: arc_sbox_part_round_optimized_init");
                        std::size_t constant_number_base = half_full_rounds * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                        }
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                    }

                    inline void arc_part_round_optimized_init(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds, "error: arc_part_round_optimized_init");
                        std::size_t constant_number_base = half_full_rounds * state_words + state_words;
                        A[0] += get_equivalent_round_constant(constant_number_base);
                    }

                    inline void sbox_arc_part_round_optimized(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number > half_full_rounds
                                        && round_number < half_full_rounds + part_rounds - 1, "error: arc_sbox_part_round_optimized");
                        std::size_t constant_number_base = (half_full_rounds + 1) * state_words + (round_number - half_full_rounds - 1) + 1;
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        A[0] += get_equivalent_round_constant(constant_number_base);
                    }

                    inline void sbox_part_round_optimized_last(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds + part_rounds - 1, "error: sbox_part_round_optimized_last");
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                    }

                    inline void arc_sbox_full_round(state_vector_type &A, std::size_t round_number) {
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_round_constant(round_number * state_words + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                    }

                    inline void arc_sbox_part_round(state_vector_type &A, std::size_t round_number) {
                        for (std::size_t i = 0; i < state_words; i++)
                            A[i] += get_round_constant(round_number * state_words + i);
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                    }

                // private:
                    constexpr static std::size_t const lfsr_state_len = 80;
                    typedef std::bitset<lfsr_state_len> lfsr_state_type;
                    lfsr_state_type lfsr_state;

                    inline element_type const &get_equivalent_round_constant(std::size_t constant_number) {
                        return generate_equivalent_round_constants()[constant_number];
                    }

                    // See https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/d9382dbd933cc559bd12ee3fa7d32ea934ace43d/code/poseidonperm_x3_64_24_optimized.sage#L40
                    inline equivalent_round_constants_type const &generate_equivalent_round_constants() {
                        static equivalent_round_constants_type const equivalent_round_constants = [this](){
                            // cout << "generate_equivalent_round_constants" << '\n';
                            equivalent_round_constants_type equivalent_round_constants(equivalent_round_constants_size);
                            mds_matrix_type mds_matrix;
                            round_constants_type round_constants = generate_round_constants();
                            state_vector_type inv_cip1(state_words);
                            state_vector_type agregated_round_constants;
                            std::size_t equivalent_constant_number_base = (half_full_rounds + 1) * state_words - half_full_rounds;

                            for (std::size_t i = 0; i < half_full_rounds * state_words; i++) {
                                equivalent_round_constants[i] = get_round_constant(i);
                                equivalent_round_constants[equivalent_round_constants_size - i - 1] = get_round_constant(round_constants_size - i - 1);
                            }
                            for (std::size_t i = half_full_rounds * state_words; i < half_full_rounds * state_words + state_words; i++)
                                equivalent_round_constants[i] = get_round_constant(i);

                            for (std::size_t r = half_full_rounds + part_rounds - 2; r >= half_full_rounds; r--) {
                                agregated_round_constants = boost::numeric::ublas::subrange(
                                    round_constants,
                                    (r + 1) * state_words,
                                    (r + 1) * state_words + state_words
                                ) + inv_cip1;
                                mds_matrix.product_with_inverse_mds_matrix(agregated_round_constants, inv_cip1);
                                equivalent_round_constants[equivalent_constant_number_base + r] = inv_cip1[0];
                                inv_cip1[0] = 0;
                            }

                            mds_matrix.product_with_inverse_mds_matrix(agregated_round_constants, inv_cip1);
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

                    inline element_type const &get_round_constant(std::size_t constant_number) {
                        return generate_round_constants()[constant_number];
                    }

                    inline round_constants_type const &generate_round_constants() {
                        static round_constants_type const round_constants = [this](){
                            // cout << "generate_round_constants" << '\n';
                            round_constants_type round_constants(round_constants_size);
                            lfsr_state_init();
                            for (std::size_t i = 0; i < round_constants_size; i++)
                                round_constants[i] = get_next_element();
                            return round_constants;
                        }();
                        return round_constants;
                    }

                    // TODO: maybe make without storing state in class instance
                    // TODO: then make const all methods of this class
                    inline void lfsr_state_init() {
                        int i;
                        std::size_t offset = 0;
                        for (i = 1; i >= 0; i--)
                            lfsr_state[offset++] = (1 >> i) & 1; // field - as in filecoin
                        for (i = 3; i >= 0; i--)
                            lfsr_state[offset++] = (1 >> i) & 1; // s-box - as in filecoin
                        for (i = 11; i >= 0; i--)
                            lfsr_state[offset++] = (word_bits >> i) & 1;
                        for (i = 11; i >= 0; i--)
                            lfsr_state[offset++] = (t >> i) & 1;
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
                        typename element_type::type round_const;
                        while (true) {
                            round_const = 0;
                            round_const |= get_next_bit();
                            for (std::size_t i = 1; i < word_bits; i++) {
                                round_const <<= 1;
                                round_const |= get_next_bit();
                            }
                            if (round_const < typename element_type::type("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")) // filecoin oriented - remake when integrate in the project
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
                        bool next_v = lfsr_state[0] ^ lfsr_state[13] ^ lfsr_state[23] ^ lfsr_state[38] ^ lfsr_state[51] ^ lfsr_state[62];
                        lfsr_state >>= 1;
                        lfsr_state[lfsr_state_len - 1] = next_v;
                        return next_v;
                    }
                };

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
