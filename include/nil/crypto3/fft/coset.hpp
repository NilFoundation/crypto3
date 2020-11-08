//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FFT_COSET_HPP
#define CRYPTO3_ALGEBRA_FFT_COSET_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace fft {
            /**
             * Translate the vector a to a coset defined by g.
             */
            template<typename FieldValueType>
            void multiply_by_coset(std::vector<FieldValueType> &a, const FieldValueType &g) {
                FieldValueType u = g;
                for (std::size_t i = 1; i < a.size(); ++i) {
                    a[i] *= u;
                    u *= g;
                }
            }
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_COSET_HPP
