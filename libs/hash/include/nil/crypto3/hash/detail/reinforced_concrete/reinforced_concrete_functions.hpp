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

#ifndef REINFORCED_CONCRETE_FUNCTIONS_HPP
#define REINFORCED_CONCRETE_FUNCTIONS_HPP

#include "reinforced_concrete_policy.hpp"
#include "reinforced_concrete_operators.hpp"
#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template <typename FieldType>
                struct reinforced_concrete_functions{
                    typedef reinforced_concrete_policy<FieldType> policy_type;
                    typedef typename policy_type::element_type element_type;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    constexpr static const std::size_t block_words = policy_type::block_words;
                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t rounds = policy_type::part_rounds;

                    typedef reinforced_concrete_operators<FieldType> reinforced_concrete_operators_type;
                    typedef typename reinforced_concrete_operators_type::state_vector_type state_vector_type;

                    static reinforced_concrete_operators_type get_rc_operators_type(){
                        return reinforced_concrete_operators_type();
                    }

                    static inline const reinforced_concrete_operators_type rc_operators = get_rc_operators_type();
                    
                    static inline void permute(state_type &A){
                        state_vector_type A_vector;
                        std::copy(A.begin(), A.end(), A_vector.begin());

                        rc_operators.concrete(A_vector, 0);
                        for(int i = 1; i <= rounds; ++i){
                            rc_operators.bricks(A_vector);
                            rc_operators.concrete(A_vector, i);
                        }

                        rc_operators.Bars(A_vector);
                        rc_operators.concrete(A_vector, rounds + 1);
                        for(int i = rounds + 2; i < rounds + rounds + 2; ++i){
                            rc_operators.bricks(A_vector);
                            rc_operators.concrete(A_vector, i);
                        }

                        std::copy(A_vector.begin(), A_vector.end(), A.begin());
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil


#endif // REINFORCED_CONCRETE_FUNCTIONS_HPP