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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PARAMS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PARAMS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename CurveType, typename CommitmentParamsType, typename CircuitDescriptionType,
                         std::size_t PublicInputSize, std::size_t PrevChalSize>
                struct kimchi_params_type {
                    using commitment_params_type = CommitmentParamsType;
                    using curve_type = CurveType;
                    using circuit_params = CircuitDescriptionType;

                    constexpr static std::size_t alpha_powers_n = CircuitDescriptionType::alpha_powers_n;
                    constexpr static std::size_t public_input_size = PublicInputSize;
                    constexpr static std::size_t witness_columns = CircuitDescriptionType::witness_columns;
                    constexpr static std::size_t permut_size = CircuitDescriptionType::permut_size;

                    constexpr static bool use_lookup = CircuitDescriptionType::use_lookup;

                    constexpr static std::size_t eval_points_amount = 2;
                    constexpr static std::size_t scalar_challenge_size = 128;

                    constexpr static std::size_t prev_challenges_size = PrevChalSize;

                    constexpr static std::size_t lookup_comm_size = 0;    // TODO:
                    constexpr static std::size_t index_term_size() {
                        return circuit_params::index_terms_list::size;
                    }

                    constexpr static std::size_t witness_commitment_size = 1;
                    constexpr static std::size_t z_commitment_size = 1;
                    constexpr static std::size_t t_commitment_size = 1;
                    constexpr static std::size_t lookup_runtime_commitment_size = 1;
                    constexpr static std::size_t lookup_sorted_commitment_size = 1;
                    constexpr static std::size_t lookup_aggregated_commitment_size = 1;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PARAMS_HPP