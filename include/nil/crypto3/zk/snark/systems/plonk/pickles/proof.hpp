//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_PICKLES_PROOF_HPP
#define CRYPTO3_ZK_PICKLES_PROOF_HPP

#include <array>
#include <tuple>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct LookupCommitments {
                    std::vector<PolyComm<CurveType>> sorted;
                    PolyComm<CurveType> aggreg;
                };

                template<typename CurveType>
                struct ProverCommitments {
                    // polynomial commitments
                    std::array<PolyComm<CurveType>, COLUMNS> w_comm;
                    PolyComm<CurveType> z_comm;
                    PolyComm<CurveType> t_comm;
                    LookupCommitments<CurveType> lookup;
                }

                template<typename CurveType>
                struct ProverProof {
                    typedef typename CurveType::scalar_group_type scalar_group_type;
                    // polynomial commitments
                    ProverCommitments<CurveType> commitments;

                    // batched commitment opening proof
                    OpeningProof<CurveType> proof;

                    // polynomial evaluations
                    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
                    std::array<ProofEvaluations<std::vector<typename scalar_group_type::value_type>>, 2> evals;

                    typename scalar_group_type::value_type ft_eval1;

                    // public part of the witness
                    std::vector<typename scalar_group_type::value_type> pub;

                    // The challenges underlying the optional polynomials folded into the proof
                    std::vector<std::tuple<std::vector<typename scalar_group_type::value_type>, PolyComm<CurveType>>>
                        prev_challenges;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP
