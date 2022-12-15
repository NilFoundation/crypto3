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

#ifndef CRYPTO3_VDF_COMPUTE_HPP
#define CRYPTO3_VDF_COMPUTE_HPP

#ifdef CRYPTO3_VDF_BOOST
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/detail/number_base.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace vdf {
#ifndef CRYPTO3_VDF_BOOST

            template<typename Vdf, typename NumberType, typename Integer>
            void compute(const NumberType &challenge, Integer difficulty,
                         typename Vdf::template state_type<NumberType> &out) {
                Vdf::compute(out, challenge, difficulty);
            }

#else

            using namespace nil::crypto3::multiprecision;

            template<typename Vdf,
                     typename SinglePassRange,
                     typename Backend,
                     expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>>
                raw_input(const SinglePassRange &v) {
            }

            template<typename Vdf,
                     typename InputIterator,
                     typename Backend,
                     expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>> raw_input(InputIterator first,
                                                                                              InputIterator last) {
            }

            template<typename Vdf, typename Backend, expression_template_option ExpressionTemplates>
            typename Vdf::template state_type<number<Backend, ExpressionTemplates>>
                discriminant_input(const number<Backend, ExpressionTemplates> &v) {
                return Vdf::state_from_discriminant(v);
            }

            template<typename Vdf, typename Backend, expression_template_option ExpressionTemplates, typename Integer>
            void compute(typename Vdf::template state_type<number<Backend, ExpressionTemplates>> &state,
                         Integer difficulty) {
            }

            template<typename Vdf, typename Backend, expression_template_option ExpressionTemplates1, typename Integer>
            void compute(const number<Backend, ExpressionTemplates1> &challenge, Integer difficulty) {
                Vdf::compute(challenge, difficulty);
            }
#endif

            template<typename Vdf, typename NumberType>
            typename Vdf::template state_type<NumberType> discriminant_input(const NumberType &v) {
                return Vdf::state_from_discriminant(v);
            }

            template<typename Vdf, typename InputIterator, typename Integer, typename OutputIterator>
            OutputIterator compute(InputIterator first, InputIterator last, Integer difficulty, OutputIterator out) {
            }

            template<typename Vdf, typename SinglePassRange, typename Integer, typename OutputIterator>
            OutputIterator compute(const SinglePassRange &r, Integer difficulty, OutputIterator out) {
            }
        }    // namespace vdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_VDF_COMPUTE_HPP
