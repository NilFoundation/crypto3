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

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CommitmentType>
                struct lookup_st {
                    std::vector<CommitmentType> sorted;
                    CommitmentType aggreg;
                };

                template<typename CurveType, std::size_t ColumnsAmount = 15, std::size_t PermutsAmount = 7>
                class pickles_proof {
                    typedef commitments::kimchi_pedersen<CurveType> commitment_scheme;
                    typedef typename commitments::kimchi_pedersen<CurveType>::commitment_type commitment_type;
                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::base_field_type base_field_type;

                public:
                    // Commitments:
                    struct commitments_t {
                        std::array<commitment_type, ColumnsAmount> w_comm;

                        commitment_type z_comm;

                        commitment_type t_comm;

                        lookup_st<commitment_type> lookup;
                    } commitments;

                    typename commitments::kimchi_pedersen<CurveType>::proof_type proof;

                    struct evals_t {
                        std::array<typename scalar_field_type::value_type, ColumnsAmount> w;

                        typename scalar_field_type::value_type z;

                        std::array<typename scalar_field_type::value_type, PermutsAmount - 1> s;

                        lookup_st<commitment_type> lookup;

                        typename scalar_field_type::value_type generic_selector;

                        typename scalar_field_type::value_type poseidon_selector;
                    };

                    std::array<evals_t, 2> evals;

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
