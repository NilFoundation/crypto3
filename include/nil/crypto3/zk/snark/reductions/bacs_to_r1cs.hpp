//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for a BACS-to-R1CS reduction, that is, constructing
// a R1CS ("Rank-1 Constraint System") from a BACS ("Bilinear Arithmetic Circuit Satisfiability").
//
// The reduction is straightforward: each bilinear gate gives rises to a
// corresponding R1CS constraint that enforces correct computation of the gate;
// also, each output gives rise to a corresponding R1CS constraint that enforces
// that the output is zero.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BACS_TO_R1CS_HPP
#define CRYPTO3_ZK_BACS_TO_R1CS_HPP

#include <nil/crypto3/zk/snark/reductions/detail/bacs_to_r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class bacs_to_r1cs : private detail::bacs_to_r1cs_basic_policy<FieldType> {
                    using policy_type = typename detail::bacs_to_r1cs_basic_policy<FieldType>;

                public:
                    using policy_type::instance_map;
                    using policy_type::witness_map;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_TO_R1CS_HPP
