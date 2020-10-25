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
// @file Declaration of interfaces for a TBCS-to-USCS reduction, that is, constructing
// a USCS ("Unitary-Square Constraint System") from a TBCS ("Two-input Boolean Circuit Satisfiability").
//
// The reduction is straightforward: each non-output wire is mapped to a
// corresponding USCS constraint that enforces the wire to carry a boolean value;
// each 2-input boolean gate is mapped to a corresponding USCS constraint that
// enforces correct computation of the gate; each output wire is mapped to a
// corresponding USCS constraint that enforces that the output is zero.
//
// The mapping of a gate to a USCS constraint is due to \[GOS12].
//
// References:
//
// \[GOS12]:
// "New techniques for noninteractive zero-knowledge",
// Jens Groth, Rafail Ostrovsky, Amit Sahai
// JACM 2012,
// <http://www0.cs.ucl.ac.uk/staff/J.Groth/NIZKJournal.pdf>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_TO_USCS_HPP
#define CRYPTO3_ZK_TBCS_TO_USCS_HPP

#include <nil/crypto3/zk/snark/reductions/detail/tbcs_to_uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class tbcs_to_uscs : private detail::tbcs_to_uscs_basic_policy<FieldType> {
                    using policy_type = typename detail::tbcs_to_uscs_basic_policy<FieldType>;

                public:
                    using policy_type::instance_map;
                    using policy_type::witness_map;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_TO_USCS_HPP
