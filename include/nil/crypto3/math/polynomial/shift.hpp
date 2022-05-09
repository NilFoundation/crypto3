//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_POLYNOMIAL_SHIFT_HPP
#define CRYPTO3_MATH_POLYNOMIAL_SHIFT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            template<typename FieldType>
            static inline polynomial<typename FieldType::value_type>
                polynomial_shift(const polynomial<typename FieldType::value_type> &f,
                                 const typename FieldType::value_type &x) {
                polynomial<typename FieldType::value_type> f_shifted(f);
                typename FieldType::value_type x_power = x;
                for (int i = 1; i < f.size(); i++) {
                    f_shifted[i] = f_shifted[i] * x_power;
                    x_power *= x;
                }

                return f_shifted;
            }

            template<typename FieldType>
            static inline polynomial_dfs<typename FieldType::value_type>
                polynomial_shift(const polynomial_dfs<typename FieldType::value_type> &f,
                                 const std::size_t shift,
                                 std::size_t domain_size = 0) {
                if ((domain_size == 0) && (f.size() > 0)) {
                    domain_size = f.size() - 1;
                }

                assert(domain_size + 1 <= f.size());

                polynomial_dfs<typename FieldType::value_type> f_shifted(domain_size + 1);

                for (std::size_t index = 0; index < f.size(); index++){
                    f_shifted[index] = f[index*(shift + 1) % domain_size];
                }

                return f_shifted;
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_POLYNOMIAL_SHIFT_HPP