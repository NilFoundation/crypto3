//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_KNOWLEDGE_COMMITMENT_HPP
#define CRYPTO3_ZK_KNOWLEDGE_COMMITMENT_HPP

#include <nil/crypto3/zk/snark/commitments/detail/element_knowledge_commitment.hpp>

#include <nil/crypto3/zk/snark/sparse_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /********************** Knowledge commitment *********************************/

                /**
                 * A knowledge commitment element is a pair (g,h) where g is in Type1 and h in Type2,
                 * and Type1 and Type2 are groups (written additively).
                 *
                 * Such pairs form a group by defining:
                 * - "zero" = (0,0)
                 * - "one" = (1,1)
                 * - a * (g,h) + b * (g',h') := ( a * g + b * g', a * h + b * h').
                 */
                template<typename Type1, typename Type2>
                struct knowledge_commitment {

                    typedef detail::element_kc<Type1, Type2> value_type;

                    constexpr static const std::size_t value_bits = Type1::value_bits + Type2::value_bits;
                };

                /******************** Knowledge commitment vector ****************************/

                /**
                 * A knowledge commitment vector is a sparse vector of knowledge commitments.
                 */
                template<typename Type1, typename Type2>
                using knowledge_commitment_vector = sparse_vector<knowledge_commitment<Type1, Type2>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // KNOWLEDGE_COMMITMENT_HPP
