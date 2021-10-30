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

#ifndef CRYPTO3_ZK_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_COMMITMENT_SCHEME_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * @brief Based on the Ploynomial Commitment description from \[Kate].
                 * 
                 * References:
                 * \[Kate]:
                 * "Constant-Size Commitments to Polynomials and Their Applications",
                 * Aniket Kate, Gregory M. Zaverucha, and Ian Goldberg,
                 * ASIACRYPT 2010,
                 * <https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf>
                 */

                template <typename TCommitment, typename TDecommitmentInfo, typename TSRS, typename TData>
                struct commitment_scheme {

                    virtual std::pair<TCommitment, TDecommitmentInfo> commit (TSRS PK, TData phi) = 0;

                    virtual ... open(TSRS PK, TCommitment C, TData phi, TDecommitmentInfo d) = 0;

                    virtual bool verify(TSRS PK, TCommitment C, TData phi, TDecommitmentInfo d) = 0;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENT_SCHEME_HPP
