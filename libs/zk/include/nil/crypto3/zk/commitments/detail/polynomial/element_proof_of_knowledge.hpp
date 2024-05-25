//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_ELEMENT_HPP
#define CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_ELEMENT_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename CurveType>
                    struct element_pok {
                        typedef CurveType curve_type;
                        using g1_value_type = typename CurveType::template g1_type<>::value_type;
                        using g2_value_type = typename CurveType::template g2_type<>::value_type;

                        g1_value_type g1_s;
                        g1_value_type g1_s_x;
                        g2_value_type g2_s_x;

                        element_pok(const g1_value_type &g1_s,
                                    const g1_value_type &g1_s_x,
                                    const g2_value_type &g2_s_x) :
                                g1_s(g1_s), g1_s_x(g1_s_x), g2_s_x(g2_s_x) {
                        }
                    };
                } // detail
            }   // commitments
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_ZK_PROOF_OF_KNOWLEDGE_ELEMENT_HPP
