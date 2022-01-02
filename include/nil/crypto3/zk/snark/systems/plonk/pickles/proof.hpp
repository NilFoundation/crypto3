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

#ifndef CRYPTO3_ZK_PICKLES_PROOF_HPP
#define CRYPTO3_ZK_PICKLES_PROOF_HPP

#include <array>
#include <tuple>
#include <vector>

#include <nil/crypto3/zk/snark/commitments/pickles.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType, std::size_t WiresAmount, std::size_t LRRounds>
                class ProverProof {
                    typedef pickles_commitment_scheme<CurveType> commitment_scheme;

                public:
                    // Commitments:
                    std::array<typename commitment_scheme::commitment_type, WiresAmount + 1> w_comm;

                    typename commitment_scheme::commitment_type z_comm;

                    // N_perm
                    std::vector<typename commitment_scheme::commitment_type> t_comm;

                    // Evaluations:
                    std::array<typename commitment_scheme::evaluation_type, WiresAmount + 1> w_zeta;
                    std::array<typename commitment_scheme::evaluation_type, WiresAmount + 1> w_zeta_omega;

                    typename commitment_scheme::evaluation_type z_zeta;
                    typename commitment_scheme::evaluation_type z_zeta_omega;

                    // N_perm + 1
                    std::vector<typename commitment_scheme::commitment_type> S_sigma_zeta;
                    // N_perm + 1
                    std::vector<typename commitment_scheme::commitment_type> S_sigma_zeta_omega;

                    typename commitment_scheme::evaluation_type L_zeta_omega;

                    // Opening proof
                    std::array<typename CurveType::value_type, LRRounds> L;
                    std::array<typename CurveType::value_type, LRRounds> R;

                    typename CurveType::value_type sigma;
                    typename CurveType::value_type G;

                    typename CurveType::scalar_field_type::value_type z1, z2;

                    // Previous challenges
                    std::vector<std::tuple<std::vector<typename scalar_group_type::value_type>,
                                           typename commitment_scheme::commitment_type>>
                        prev_challenges;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP
