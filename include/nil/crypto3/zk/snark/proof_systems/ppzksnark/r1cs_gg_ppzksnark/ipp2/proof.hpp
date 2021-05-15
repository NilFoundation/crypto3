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
#include <vector>
#include <tuple>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/ipp2/commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /// KZGOpening represents the KZG opening of a commitment key (which is a tuple
                /// given commitment keys are a tuple).
                template<typename GroupType>
                using kzg_opening = std::pair<typename GroupType::value_type, typename GroupType::value_type>;

                /// It contains all elements derived in the GIPA loop for both TIPP and MIPP at
                /// the same time.
                template<typename CurveType>
                struct gipa_proof {
                    typedef CurveType curve_type;

                    std::uint32_t nproofs;
                    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                          r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>>>
                        comms_ab;
                    std::vector<std::pair<r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>,
                                          r1cs_gg_ppzksnark_ipp2_commitment_output<CurveType>>>
                        comms_c;
                    std::vector<std::pair<typename CurveType::pairing::fqk_type::value_type, typename CurveType::pairing::fqk_type::value_type>>
                        z_ab;
                    std::vector<
                        std::pair<typename CurveType::g1_type::value_type, typename CurveType::g1_type::value_type>>
                        z_c;
                    typename CurveType::g1_type::value_type final_a;
                    typename CurveType::g2_type::value_type final_b;
                    typename CurveType::g1_type::value_type final_c;
                    typename CurveType::scalar_field_type::value_type final_r;

                    /// final commitment keys $v$ and $w$ - there is only one element at the
                    /// end for v1 and v2 hence it's a tuple.
                    r1cs_gg_ppzksnark_ipp2_vkey<CurveType> final_vkey;
                    r1cs_gg_ppzksnark_ipp2_wkey<CurveType> final_wkey;
                };

                template<typename CurveType>
                struct tipp_mipp_proof {
                    typedef CurveType curve_type;

                    gipa_proof<CurveType> gipa;
                    kzg_opening<typename CurveType::g2_type> vkey_opening;
                    kzg_opening<typename CurveType::g1_type> wkey_opening;
                };
                /// AggregateProof contains all elements to verify n aggregated Groth16 proofs
                /// using inner pairing product arguments. This proof can be created by any
                /// party in possession of valid Groth16 proofs.
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_aggregate_proof {
                    typedef CurveType curve_type;
                    /// commitment to A and B using the pair commitment scheme needed to verify
                    /// TIPP relation.
                    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_ab;
                    /// commit to C separate since we use it only in MIPP
                    r1cs_gg_ppzksnark_ipp2_commitment_output<curve_type> com_c;
                    /// $A^r * B = Z$ is the left value on the aggregated Groth16 equation
                    typename curve_type::pairing::fqk_type::value_type ip_ab;
                    /// $C^r$ is used on the right side of the aggregated Groth16 equation
                    typename curve_type::g1_type::value_type agg_c;
                    tipp_mipp_proof<curve_type> tmipp;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
