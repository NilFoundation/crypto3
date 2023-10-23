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

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_constants.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                using namespace nil::crypto3::multiprecision;

                // Uses Grain-LFSR stream cipher for constants generation.
                template<typename poseidon_policy_type>
                class poseidon_constants_generator {
                public:

                    BOOST_STATIC_ASSERT_MSG(
                        !poseidon_policy_type::mina_version,
                        "Constants generation can only be used with the original version, not Mina version.");

                    typedef poseidon_policy_type policy_type;
                    typedef typename policy_type::field_type field_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    typedef typename field_type::value_type element_type;
                    typedef typename field_type::integral_type integral_type;
                    constexpr static const integral_type modulus = field_type::modulus;

                    typedef poseidon_constants<poseidon_policy_type> poseidon_constants_type;
                    typedef typename poseidon_constants_type::mds_matrix_type mds_matrix_type;
                    typedef typename poseidon_constants_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t lfsr_state_bits = 80;
                    typedef number<backends::cpp_int_backend<
                        lfsr_state_bits, lfsr_state_bits, cpp_integer_type::unsigned_magnitude,
                        cpp_int_check_type::unchecked, void>>
                        lfsr_state_type;
    
                    typedef typename poseidon_constants_type::round_constants_type round_constants_type;

                    /*! 
                     * @brief Randomly generates all the constants required, using the correct generation rules.
                     * If called multiple times, will return DIFFERENT constants.
                     */

#ifdef CRYPTO3_HASH_POSEIDON_COMPILE_TIME
                    constexpr
#endif
                    static std::pair<mds_matrix_type, round_constants_type> generate_constants() {
                        return {generate_mds_matrix(), generate_round_constants()};
                    }
                    
                private:
                    
#ifdef CRYPTO3_HASH_POSEIDON_COMPILE_TIME
                    constexpr
#endif
                    static inline mds_matrix_type generate_mds_matrix() {
                        mds_matrix_type new_mds_matrix;

                        state_vector_type x;
                        state_vector_type y;
                        bool secure_MDS_found = false;
                        while (!secure_MDS_found) {
                            secure_MDS_found = true;
                            for (std::size_t i = 0; i < state_words; i++) {
                                x[i] = algebra::random_element<field_type>(); 
                                y[i] = algebra::random_element<field_type>(); 
                            }

                            for (std::size_t i = 0; i < state_words; i++) {
                                for (std::size_t j = 0; j < state_words; j++) {
                                    if ((i != j && x[i] == x[j]) || 
                                            (i != j && y[i] == y[j]) || 
                                            (x[i] == y[j])) {
                                        secure_MDS_found = false; 
                                        break;
                                    }
                                    // We use minus in the next line, as is done in Mina implementation.
                                    // Original implementation uses + instead, but it doesn't matter,
                                    // since X and Y are random elements.
                                    new_mds_matrix[i][j] = (x[i] - y[i]).inversed();
                                }
                                if (!secure_MDS_found)
                                    break;
                            }
                            // Determinant of the matrix must not be 0.
                            if (new_mds_matrix.det() == 0)
                                secure_MDS_found = false;

                            // TODO(martun): check that mds has NO eignevalues. 
                            // if len(new_mds_matrix.characteristic_polynomial().roots()) == 0:
                                // return new_mds_matrix
                            // The original matrix security check is here: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_params_poseidon.sage
                        }
                        return new_mds_matrix;
                    }

#ifdef CRYPTO3_HASH_POSEIDON_COMPILE_TIME
                   constexpr
#endif
                   static const round_constants_type generate_round_constants() {
                        round_constants_type round_constants;

                        integral_type constant = 0;
                        lfsr_state_type lfsr_state = get_lfsr_init_state();

                        for (std::size_t r = 0; r < full_rounds + part_rounds; r++) {
                            for (std::size_t i = 0; i < state_words; i++) {
                                while (true) {
                                    constant = 0;
                                    for (std::size_t j = 0; j < word_bits; j++) {
                                        lfsr_state = update_lfsr_state(lfsr_state);
                                        constant = set_new_bit<integral_type>(
                                            constant, get_lfsr_state_bit(lfsr_state, lfsr_state_bits - 1));
                                    }
                                    if (constant < modulus) {
                                        round_constants[r][i] = element_type(constant);
                                        break;
                                    }
                                }
                            }
                        }
                        return round_constants;
                    }

                    static constexpr lfsr_state_type get_lfsr_init_state() {
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

                    static constexpr lfsr_state_type update_lfsr_state(lfsr_state_type state) {
                        while (true) {
                            state = update_lfsr_state_raw(state);
                            if (get_lfsr_state_bit(state, lfsr_state_bits - 1))
                                break;
                            else
                                state = update_lfsr_state_raw(state);
                        }
                        return update_lfsr_state_raw(state);
                    }

                    static constexpr inline lfsr_state_type update_lfsr_state_raw(lfsr_state_type state) {
                        bool new_bit = get_lfsr_state_bit(state, 0) != get_lfsr_state_bit(state, 13) !=
                                       get_lfsr_state_bit(state, 23) != get_lfsr_state_bit(state, 38) !=
                                       get_lfsr_state_bit(state, 51) != get_lfsr_state_bit(state, 62);
                        return set_new_bit(state, new_bit);
                    }

                    static constexpr inline bool get_lfsr_state_bit(lfsr_state_type state, std::size_t pos) {
                        return bit_test(state, lfsr_state_bits - 1 - pos);
                    }

                    template<typename T>
                    static constexpr inline T set_new_bit(T var, bool new_bit) {
                        return (var << 1) | (new_bit ? 1 : 0);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_LFSR_HPP
