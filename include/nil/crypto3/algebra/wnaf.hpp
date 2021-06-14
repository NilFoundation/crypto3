//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_WNAF_HPP
#define CRYPTO3_ALGEBRA_WNAF_HPP

#include <nil/crypto3/multiprecision/wnaf.hpp>

#include <nil/crypto3/algebra/curves/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            template<typename BaseValueType, typename Backend,
                     multiprecision::expression_template_option ExpressionTemplates>
            BaseValueType fixed_window_wnaf_exp(const std::size_t window_size, const BaseValueType &base,
                                                const multiprecision::number<Backend, ExpressionTemplates> &scalar) {
                std::vector<long> naf = multiprecision::find_wnaf(window_size, scalar);
                std::vector<BaseValueType> table(1ul << (window_size - 1));
                BaseValueType tmp = base;
                BaseValueType dbl = base.doubled();
                for (size_t i = 0; i < 1ul << (window_size - 1); ++i) {
                    table[i] = tmp;
                    tmp = tmp + dbl;
                }

                BaseValueType res = BaseValueType::zero();
                bool found_nonzero = false;
                for (long i = naf.size() - 1; i >= 0; --i) {
                    if (found_nonzero) {
                        res = res.doubled();
                    }

                    if (naf[i] != 0) {
                        found_nonzero = true;
                        if (naf[i] > 0) {
                            res = res + table[naf[i] / 2];
                        } else {
                            res = res - table[(-naf[i]) / 2];
                        }
                    }
                }

                return res;
            }

            // TODO: check, that CurveGroupValueType is a curve group element. Otherwise it has no wnaf_window_table
            template<typename CurveGroupValueType, typename Backend,
                     multiprecision::expression_template_option ExpressionTemplates>
            CurveGroupValueType opt_window_wnaf_exp(const CurveGroupValueType &base,
                                                    const multiprecision::number<Backend, ExpressionTemplates> &scalar,
                                                    const std::size_t scalar_bits) {
                std::size_t best = 0;
                for (long i =
                         curves::wnaf_params<typename CurveGroupValueType::group_type>::wnaf_window_table.size() - 1;
                     i >= 0;
                     --i) {
                    if (scalar_bits >=
                        curves::wnaf_params<typename CurveGroupValueType::group_type>::wnaf_window_table[i]) {
                        best = i + 1;
                        break;
                    }
                }

                if (best > 0) {
                    return fixed_window_wnaf_exp(best, base, scalar);
                } else {
                    return scalar * base;
                }
            }
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
