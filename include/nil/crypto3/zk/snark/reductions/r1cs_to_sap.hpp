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
// @file Declaration of interfaces for a R1CS-to-SAP reduction, that is, constructing
// a SAP ("Square Arithmetic Program") from a R1CS ("Rank-1 Constraint System").
//
// SAPs are defined and constructed from R1CS in \[GM17].
//
// The implementation of the reduction follows, extends, and optimizes
// the efficient approach described in Appendix E of \[BCGTV13].
//
// References:
//
// \[BCGTV13]
// "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge",
// Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
// CRYPTO 2013,
// <http://eprint.iacr.org/2013/507>
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_TO_SAP_HPP
#define CRYPTO3_ZK_R1CS_TO_SAP_HPP

#include <nil/crypto3/zk/snark/reductions/detail/r1cs_to_sap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class r1cs_to_sap : private detail::r1cs_to_sap_basic_policy<FieldType> {
                    using policy_type = typename detail::r1cs_to_sap_basic_policy<FieldType>;

                public:
                    using policy_type::get_domain;

                    using policy_type::instance_map;
                    using policy_type::instance_map_with_evaluation;
                    using policy_type::witness_map;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_TO_SAP_HPP
