//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_INNER_CONSTANTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_INNER_CONSTANTS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename KimchiParamsType>
                struct kimchi_inner_constants {

                public:
                    using commitment_params_type = typename KimchiParamsType::commitment_params_type;

                    constexpr static std::size_t ft_generic_size = 2 * 5;
                    constexpr static std::size_t permutation_constraints = 3;

                    constexpr static std::size_t evaluations_in_batch_size =
                        KimchiParamsType::prev_challenges_size    // recursion
                        + 1                                       // p_comm
                        + 1                                       // ft_comm
                        + 1                                       // z_comm
                        + 1                                       // generic_comm
                        + 1                                       // psm_comm
                        + KimchiParamsType::witness_columns       // w_comm
                        + KimchiParamsType::permut_size - 1 + KimchiParamsType::lookup_comm_size;

                    constexpr static std::size_t srs_padding_size() {
                        std::size_t srs_two_power = 1 << (boost::static_log2<commitment_params_type::srs_len>::value);
                        std::size_t padding_size = srs_two_power == commitment_params_type::srs_len ?
                                                       0 :
                                                       srs_two_power * 2 - commitment_params_type::srs_len;
                        return padding_size;
                    }

                    constexpr static std::size_t final_msm_size(const std::size_t batch_size) {
                        return 1                                    // H
                               + commitment_params_type::srs_len    // G
                               + srs_padding_size() +
                               (1      // opening.G
                                + 1    // U
                                + 2 * commitment_params_type::eval_rounds +
                                evaluations_in_batch_size * commitment_params_type::shifted_commitment_split + 1    // U
                                + 1)    // opening.delta
                                   * batch_size;
                    }

                    constexpr static std::size_t f_comm_msm_size =
                        1 + ft_generic_size + KimchiParamsType::circuit_params::index_terms_list::size;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_INNER_CONSTANTS_HPP