//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
#define CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/fp.hpp>
#include <nil/algebra/fields/operations.hpp>
// #include <nil/algebra/fields/detail/operations/fp.hpp>

#include <bitset>

#include <boost/numeric/ublas/vector.hpp>
#include <boost/numeric/ublas/matrix.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                // filecoin oriented implementation
                template<typename FieldT, typename element_type, std::size_t t, bool strength>
                struct poseidon_functions
                {
                    typedef poseidon_policy<FieldT, element_type, t, strength> policy_type;

                    constexpr static std::size_t const state_bits = policy_type::state_bits;
                    constexpr static std::size_t const state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static std::size_t const block_bits = policy_type::block_bits;
                    constexpr static std::size_t const block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static std::size_t const full_rounds = policy_type::full_rounds;
                    constexpr static std::size_t const half_full_rounds = policy_type::half_full_rounds;
                    constexpr static std::size_t const part_rounds = policy_type::part_rounds;

                    constexpr static std::size_t const word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static std::size_t const grain_lfsr_state_len = 80;


                    // TODO: add checks
                    // TODO: remake in constexpr way
                    struct round_constants_generator {

                        // BOOST_STATIC_ASSERT_MSG(round_const_num > 0 && round_const_num <= t * (r_f + r_p), "round is not in range");

                        inline round_constants_generator() {
                            int i;
                            std::size_t offset = 0;
                            for (i = 1; i >= 0; i--) {
                                state[offset++] = (1 >> i) & 1; // prime field - as in filecoin
                            }
                            for (i = 3; i >= 0; i--) {
                                state[offset++] = (1 >> i) & 1; // s-box x^5 - as in filecoin
                            }
                            for (i = 11; i >= 0; i--) {
                                state[offset++] = (word_bits >> i) & 1;
                            }
                            for (i = 11; i >= 0; i--) {
                                state[offset++] = (t >> i) & 1;
                            }
                            for (i = 9; i >= 0; i--) {
                                state[offset++] = (full_rounds >> i) & 1;
                            }
                            for (i = 9; i >= 0; i--) {
                                state[offset++] = (part_rounds >> i) & 1;
                            }
                            for (i = 29; i >= 0; i--) {
                                state[offset++] = 1;
                            }
                            // idling
                            for (i = 0; i < 160; i++)
                                get_next_raw_bit();
                        }

                        // TODO: check - interaction with element_type there should be like with cpp_int
                        // get next element
                        inline element_type operator()() {
                            typename element_type::value_type round_const;

                            while (true) {
                                round_const = 0;

                                round_const |= get_next_bit();
                                for (std::size_t i = 1; i < word_bits; i++) {
                                    round_const <<= 1;
                                    round_const |= get_next_bit();
                                }

                                // TODO: there should be check on excess of field modulus according to Poseidon spec.
                                // if (round_const < cpp_int("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")) // filecoin oriented - remake when integrate in the project
                                //     break;
                            }
                            
                            // TODO: check correctness of convertion to element_type
                            return {round_const};
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
                            bool next_v = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
                            state >>= 1;
                            state[grain_lfsr_state_len - 1] = next_v;
                            return next_v;
                        }

                        std::bitset<grain_lfsr_state_len> state;
                    };


                    // TODO: check - interaction with element_type there should be like with cpp_int
                    struct MDS_matrix {
                        inline boost::numeric::ublas::matrix<element_type> const get_mds_matrix() const {
                            static boost::numeric::ublas::matrix<element_type> const mds_matrix = [](){
                                static boost::numeric::ublas::matrix<element_type> mds_matrix(t, t);
                                for (std::size_t i = 0; i < t; i++) {
                                    for (std::size_t j = 0; j < t; j++) {
                                        mds_matrix.insert_element(i, j,
                                            algebra::invert<FieldT>({element_type::value_type(i + (j + t))})
                                        );
                                    }
                                }
                                return mds_matrix;
                            }();
                            return mds_matrix;
                        }
                        // TODO: make more efficient
                        inline void product(state_type &A) const {
                            boost::numeric::ublas::vector<element_type> A_vector(state_words);
                            for (std::size_t i = 0; i < state_words; i++)
                                A_vector[i] = A[i];
                            // TODO: this seems to be incorrect because operators * and + for element_type are not overloaded
                            A_vector = boost::numeric::ublas::prod(A_vector, this->get_mds_matrix());
                            for (std::size_t i = 0; i < state_words; i++)
                                A[i] = A_vector[i];
                        }
                    };

                    static inline void do_full_round(state_type &A, round_constants_generator &const_gen, MDS_matrix &mds_matrix) {
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] = algebra::add<FieldT>(A[i], const_gen());
                            A[i] = algebra::pow<FieldT>(A[i], 5);
                        }
                        mds_matrix.product(A);
                    }

                    static inline void do_part_round(state_type &A, round_constants_generator &const_gen, MDS_matrix &mds_matrix) {
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] = algebra::add<FieldT>(A[i], const_gen());
                        }
                        A[0] = algebra::pow<FieldT>(A[0], 5);
                        mds_matrix.product(A);
                    }

                    static inline void permute(state_type &A) {
                        round_constants_generator const_gen;
                        MDS_matrix mds_matrix;
                        
                        // first half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++)
                            do_full_round(A, const_gen, mds_matrix);

                        // partial rounds
                        for(std::size_t i = 0; i < part_rounds; i++)
                            do_part_round(A, const_gen, mds_matrix);

                        // second half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++)
                            do_full_round(A, const_gen, mds_matrix);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
