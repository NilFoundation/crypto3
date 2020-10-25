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
// @file Declaration of interfaces for a USCS-to-SSP reduction, that is, constructing
// a SSP ("Square Span Program") from a USCS ("boolean circuit with 2-input gates").
//
// SSPs are defined in \[DFGK14], and constructed for USCS also in \[DFGK14].
//
// The implementation of the reduction adapts to \[DFGK14], extends, and optimizes
// the efficient QAP-based approach described in Appendix E of \[BCGTV13].
//
// References:
//
// \[BCGTV13]
// "SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge",
// Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
// CRYPTO 2013,
// <http://eprint.iacr.org/2013/507>
//
// \[DFGK14]:
// "Square Span Programs with Applications to Succinct NIZK Arguments"
// George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
// ASIACRYPT 2014,
// <http://eprint.iacr.org/2014/718>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_USCS_TO_SSP_HPP
#define CRYPTO3_ZK_USCS_TO_SSP_HPP

#include <nil/crypto3/zk/snark/reductions/detail/uscs_to_ssp.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class uscs_to_ssp : private detail::uscs_to_ssp_basic_policy<FieldType> {
                    using policy_type = typename detail::uscs_to_ssp_basic_policy<FieldType>;

                public:
                    using policy_type::instance_map;
                    using policy_type::instance_map_with_evaluation;
                    using policy_type::witness_map;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_TO_SSP_HPP
