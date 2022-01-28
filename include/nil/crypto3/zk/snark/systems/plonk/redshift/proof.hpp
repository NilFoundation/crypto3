//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PROOF_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PROOF_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CommitmentSchemeType>
                struct redshift_proof {
                    typedef CommitmentSchemeType commitment_scheme_type;

                    redshift_proof() {
                    }

                    std::vector<typename CommitmentSchemeType::commitment_type> f_commitments;

                    typename CommitmentSchemeType::commitment_type P_commitment;
                    typename CommitmentSchemeType::commitment_type Q_commitment;

                    std::vector<typename CommitmentSchemeType::commitment_type> T_commitments;

                    std::vector<typename CommitmentSchemeType::proof_type> f_lpc_proofs;

                    typename CommitmentSchemeType::proof_type P_lpc_proof;
                    typename CommitmentSchemeType::proof_type Q_lpc_proof;

                    std::vector<typename CommitmentSchemeType::proof_type> T_lpc_proofs;

                    bool operator==(const redshift_proof &rhs) const {
                        return f_commitments == rhs.f_commitments && P_commitment == rhs.P_commitment &&
                               Q_commitment == rhs.Q_commitment && T_commitments == rhs.T_commitments &&
                               f_lpc_proofs == rhs.f_lpc_proofs && P_lpc_proof == rhs.P_lpc_proof &&
                               Q_lpc_proof == rhs.Q_lpc_proof && T_lpc_proofs == rhs.T_lpc_proofs;
                    }
                    bool operator!=(const redshift_proof &rhs) const {
                        return !(rhs == *this);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROOF_HPP
