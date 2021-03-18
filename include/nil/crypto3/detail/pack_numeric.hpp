//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PACK_NUMERIC_HPP
#define CRYPTO3_PACK_NUMERIC_HPP

#include <boost/assert.hpp>
#include <boost/static_assert.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            using namespace nil::crypto3::multiprecision;

            template<typename Endianness, int InValueBits, int OutValueBits, typename InputIterator, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(InputIterator first, InputIterator last, number<Backend, ExpressionTemplates> &out) {
                import_bits(out, first, last);
                BOOST_ASSERT(msb(out) == OutValueBits);
            }

            template<typename Endianness, int OutValueBits, typename InputType, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(const InputType &in, number<Backend, ExpressionTemplates> &out) {
                import_bits(out, in.begin(), in.end());
                BOOST_ASSERT(msb(out) == OutValueBits);
            }

            template<typename Endianness, int OutValueBits, typename OutputType, typename Backend,
                     expression_template_option ExpressionTemplates>
            inline void pack(const number<Backend, ExpressionTemplates> &in, OutputType &out) {
                export_bits(in, out);
                BOOST_ASSERT(msb(out) == OutValueBits);
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_PACK_HPP
