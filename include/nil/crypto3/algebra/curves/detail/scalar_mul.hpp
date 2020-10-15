//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef ALGEBRA_CURVES_SCALAR_MUL_HPP
#define ALGEBRA_CURVES_SCALAR_MUL_HPP

#include <boost/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    using namespace boost::multiprecision;

                    template<typename GroupType, typename Backend, expression_template_option ExpressionTemplates>
                    GroupType scalar_mul(const GroupType &base, const number<Backend, ExpressionTemplates> &scalar) {
                        GroupType result;

                        bool found_one = false;
                        for (std::size_t i = static_cast<std::size_t>(msb(scalar)); i >= 0; --i) {
                            if (found_one) {
                                result = result.doubled();
                            }

                            if (bit_test(scalar, i)) {
                                found_one = true;
                                result = result + base;
                            }
                        }

                        return result;
                    }
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_CURVES_SCALAR_MUL_HPP
