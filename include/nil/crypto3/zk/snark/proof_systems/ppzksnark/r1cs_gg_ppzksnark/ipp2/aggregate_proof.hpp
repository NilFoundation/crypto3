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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_AGGREGATE_PROOF_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_AGGREGATE_PROOF_HPP

#include <memory>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/commit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// AggregateProof contains all elements to verify n aggregated Groth16 proofs
                /// using inner pairing product arguments. This proof can be created by any
                /// party in possession of valid Groth16 proofs.
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_aggregate_proof {
                    /// commitment to A and B using the pair commitment scheme needed to verify
                    /// TIPP relation.
                    r1cs_gg_ppzksnark_commitment_output<CurveType> com_ab;
                    /// commit to C separate since we use it only in MIPP
                    r1cs_gg_ppzksnark_commitment_output<CurveType> com_c;
                    /// $A^r * B = Z$ is the left value on the aggregated Groth16 equation
                    algebra::Fqk<CurveType> ip_ab;
                    /// $C^r$ is used on the right side of the aggregated Groth16 equation
                    pub agg_c : E::G1, pub tmipp : TippMippProof<E>,
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
