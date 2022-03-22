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

#include <nil/crypto3/zk/snark/commitments/polynmomial/pedersen.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType, std::size_t WiresAmount>
                class pickles_proof {
                    typedef pedersen_commitment_scheme<CurveType> commitment_scheme;

                public:
                    // Commitments:
                    std::array<typename commitment_scheme::commitment_type, WiresAmount + 1> w_comm;

                    typename commitment_scheme::commitment_type z_comm;

                    typename commitment_scheme::commitment_type t_comm;

                    // TODO: Lookup comm?

                    // Evaluations:
                    std::array<typename commitment_scheme::evaluation_type, WiresAmount + 1> w_zeta;    // evals[0]
                    std::array<typename commitment_scheme::evaluation_type, WiresAmount + 1>
                        w_zeta_omega;    // evals[1]

                    typename commitment_scheme::evaluation_type z_zeta;          // evals[0]
                    typename commitment_scheme::evaluation_type z_zeta_omega;    // evals[1]

                    // N_perm + 1
                    std::vector<typename commitment_scheme::commitment_type> S_sigma_zeta;    // evals[0]
                    // N_perm + 1
                    std::vector<typename commitment_scheme::commitment_type> S_sigma_zeta_omega;    // evals[1]

                    //typename commitment_scheme::evaluation_type L_zeta_omega; // TODO: what is it?

                    // Opening proof
                    std::vector<typename CurveType::template g1_type<>::value_type> L;
                    std::vector<typename CurveType::template g1_type<>::value_type> R;    // L + R using as lr in kimchi

                    typename CurveType::template g1_type<>::value_type sigma;    // using as sg in kimchi
                    typename CurveType::template g1_type<>::value_type delta;

                    typename CurveType::scalar_field_type::value_type z1, z2;

                    // ft_eval1
                    typename CurveType::scalar_field_type::value_type ft_eval1;

                    // public
                    std::vector<typename CurveType::scalar_field_type::value_type> public_p;

                    // Previous challenges
                    std::vector<
                        std::tuple<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_scheme>>
                        prev_challenges;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROOF_HPP
