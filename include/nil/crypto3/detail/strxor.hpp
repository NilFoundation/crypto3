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

#ifndef CRYPTO3_STRXOR_HPP
#define CRYPTO3_STRXOR_HPP

#include <boost/concept/assert.hpp>
#include <boost/assert.hpp>

#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename InputType, typename OutputType>
            constexpr inline void strxor(const InputType &in1, const InputType &in2, OutputType &out) {
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputType>));
                BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<OutputType>));
                BOOST_CONCEPT_ASSERT((boost::WriteableRangeConcept<OutputType>));

                BOOST_ASSERT(std::distance(in1.begin(), in1.end()) == std::distance(in2.begin(), in2.end()) &&
                             std::distance(in1.begin(), in1.end()) == std::distance(out.begin(), out.end()));

                auto in1_iter = in1.begin();
                auto in2_iter = in2.begin();
                auto out_iter = out.begin();

                while (in1_iter != in1.end() && in2_iter != in2.end() && out_iter != out.end()) {
                    *out_iter++ = *in1_iter++ ^ *in2_iter++;
                }
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil


#endif    // CRYPTO3_STRXOR_HPP
