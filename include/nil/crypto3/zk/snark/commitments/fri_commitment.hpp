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

#ifndef CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/zk/snark/commitments/commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * @brief Based on the FRI Commitment description from \[ResShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[RedShift].
                 * 
                 * References:
                 * \[RedShift]:
                 * "REDSHIFT: Transparent SNARKs from List 
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template <std::size_t d, std::size_t Rounds>
                class fri_commitment_scheme: commitment_scheme<...> {
                    typedef std::array<math::polynomial<...>, Rounds> TCommitment;
                    typedef std::array<std::size_t, d+1> TDecommitmentInfo;
                    typedef ... TSRS;
                    typedef std::tuple<math::polynomial<...>, std::array<std::size_t, Rounds>> TData; //f_0 and x_0...x_{r-1}
                public:

                    virtual std::pair<TCommitment, TDecommitmentInfo> commit (TSRS PK, TData data){
                        TCommitment f;
                        f[0] = std::get<0>(data);

                        for (std::size_t i = 0; i < Rounds - 1; i++){

                            math::polynomial<...> p_yi = math::make_interpolant(f[i], S_y(x));
                            f[i + 1] = p_yi(std::get<1>(data)[i]);
                        }

                        math::polynomial<...> p_yr = math::make_interpolant(f[r-1], S_y(x));

                        math::polynomial<...> f_r = p_yr(std::get<1>(data)[r]);
                        std::array<std::size_t, d+1> a = math::get_polynom_coefs(f_r);

                        return std::make_pair(f, a);
                    }

                    virtual ... open(TSRS PK, TCommitment C, TData phi, TDecommitmentInfo d){

                    }

                    virtual bool verify(TSRS PK, TCommitment f, ... a, TDecommitmentInfo d){
                        a = get<1>(C);
                        math::polynomial f_r(a);

                        std::array<..., r + 1> s;
                        s[0] = random<...>(...);

                        for (std::size_t i = 0; i < r; i++){
                            s[i + 1] = q(s[i]);
                        }

                        ...
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
