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

#ifndef REINFORCED_CONCRETE_OPERATORS_HPP
#define REINFORCED_CONCRETE_OPERATORS_HPP

#include "reinforced_concrete_policy.hpp"
#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/matrix/math.hpp>
#include <nil/crypto3/algebra/matrix/operators.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>
#include <nil/crypto3/algebra/vector/operators.hpp>

#include <nil/crypto3/hash/detail/reinforced_concrete/reinforced_concrete_lfsr.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType>
                struct reinforced_concrete_operators {
                    typedef reinforced_concrete_policy<FieldType> policy_type;

                    typedef typename policy_type::element_type element_type;
                    typedef typename element_type::integral_type integral_type;

                    typedef typename policy_type::bucket_type bucket_type;
                    constexpr static const std::size_t bucket_size = policy_type::bucket_size;
                    constexpr static const bucket_type bucket = policy_type::bucket;
                    constexpr static const element_type p_min = policy_type::p_min;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef algebra::vector<element_type, state_words> state_vector_type;
                    typedef algebra::matrix<element_type, state_words, state_words> mds_matrix_type;

                    typedef reinforced_concrete_lfsr<FieldType> lsfr_policy;
                    typedef typename lsfr_policy::round_constants_type round_constants_type;

                    mds_matrix_type mds_matrix;
                    lsfr_policy lsfr;

                    reinforced_concrete_operators() : mds_matrix(generate_mds_matrix()), lsfr(lsfr_policy()) {
                    }

                    static inline mds_matrix_type generate_mds_matrix() {
                        state_vector_type circulant = {element_type(integral_type(2)), element_type(integral_type(1)),
                                                       element_type(integral_type(1))};
                        mds_matrix_type new_matrix;

                        for (int i = 0; i < state_words; ++i) {
                            for (int j = 0; j < state_words; ++j) {
                                new_matrix[i][j] = circulant[(j + i) % state_words];
                            }
                        }
                        return new_matrix;
                    }

                    inline void concrete(state_vector_type &A, std::size_t round) const {
                        A = algebra::matvectmul(mds_matrix, A);

                        for (int i = 0; i < state_words; ++i) {
                            A[i] += lsfr.round_constants[round * state_words + i];
                        }
                    }

                    static inline void bricks(state_vector_type &A) {
                        element_type A_0 = A[0];
                        element_type A_1 = A[1];
                        A[0] = A[0].pow(policy_type::d);
                        A[1] = A[1] * (A_0 * A_0 + policy_type::alphas[0] * A_0 + policy_type::betas[0]);
                        A[2] = A[2] * (A_1 * A_1 + policy_type::alphas[1] * A_1 + policy_type::betas[1]);
                    }

                    static inline bucket_type decompose(element_type &element) {
                        bucket_type x_bucket;
                        element_type product = element_type(integral_type(1));
                        element_type sum = element_type(integral_type(0));

                        for (int i = bucket_size - 1; i >= 0; --i) {

                            x_bucket[i] = element_type(((element - sum) * product.inversed()).data % bucket[i].data);
                            sum += x_bucket[i] * product;
                            product *= bucket[i];
                        }
                        return x_bucket;
                    }

                    static inline element_type compose(bucket_type &y_bucket) {
                        element_type comp(integral_type(0));
                        element_type product(integral_type(1));

                        for (int i = bucket_size - 1; i >= 0; --i) {
                            comp += y_bucket[i] * product;
                            product *= bucket[i];
                        }
                        return comp;
                    }

                    static inline element_type SBox_inverse(element_type &element) {
                        return element.inversed();
                    }

                    static inline element_type SBox_MiMC(element_type &element) {
                        return element.pow(3);
                    }

                    static inline element_type f(element_type &element) {
                        return element == 0 ? element_type(integral_type(0)) : SBox_inverse(element);
                    }

                    static inline element_type S(element_type &element) {
                        return element < p_min ? f(element) : element;
                    }

                    static inline void Bars(state_vector_type &A) {
                        for (int i = 0; i < state_words; ++i) {

                            bucket_type temp_bucket = decompose(A[i]);
                            for (auto &a : temp_bucket) {
                                a = S(a);
                            }
                            A[i] = compose(temp_bucket);
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // REINFORCED_CONCRETE_OPERATORS_HPP