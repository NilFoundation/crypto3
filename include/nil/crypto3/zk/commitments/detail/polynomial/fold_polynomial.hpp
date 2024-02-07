//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_DETAIL_FOLD_POLYNOMIAL_HPP
#define CRYPTO3_ZK_COMMITMENTS_DETAIL_FOLD_POLYNOMIAL_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {

                    template<typename FieldType>
                    math::polynomial<typename FieldType::value_type>
                    fold_polynomial(math::polynomial<typename FieldType::value_type> &f,
                                    typename FieldType::value_type alpha) {

                        std::size_t d = f.degree();
                        if (d % 2 == 0) {
                            f.push_back(0);
                            d++;
                        }
                        math::polynomial<typename FieldType::value_type> f_folded(d / 2 + 1);

                        for (std::size_t index = 0; index <= f_folded.degree(); index++) {
                            f_folded[index] = f[2 * index] + alpha * f[2 * index + 1];
                        }

                        return f_folded;
                    }

                    template<typename FieldType>
                    math::polynomial_dfs<typename FieldType::value_type>
                    fold_polynomial(math::polynomial_dfs<typename FieldType::value_type> &f,
                                    const typename FieldType::value_type &alpha,
                                    std::shared_ptr<math::evaluation_domain<FieldType>>
                                    domain) {

                        // codeword = [two.inverse() * ( (one + alpha / (offset * (omega^i)) ) * codeword[i]
                        //  + (one - alpha / (offset * (omega^i)) ) * codeword[len(codeword)//2 + i] ) for i in
                        //  range(len(codeword)//2)]
                        math::polynomial_dfs<typename FieldType::value_type> f_folded(
                                domain->size() / 2 - 1, domain->size() / 2, FieldType::value_type::zero());

                        typename FieldType::value_type two_inversed = 2;
                        two_inversed = two_inversed.inversed();
                        typename FieldType::value_type omega_inversed = domain->get_domain_element(domain->size() - 1);

                        typename FieldType::value_type acc = alpha;

                        for (std::size_t i = 0; i <= f_folded.degree(); i++) {
                            f_folded[i] = two_inversed * ((1 + acc) * f[i] + (1 - acc) * f[domain->size() / 2 + i]);
                            acc *= omega_inversed;
                        }

                        return f_folded;
                    }
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_DETAIL_FOLD_POLYNOMIAL_HPP
