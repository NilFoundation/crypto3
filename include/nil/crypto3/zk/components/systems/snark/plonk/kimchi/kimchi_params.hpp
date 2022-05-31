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
                template<std::size_t WitnessColumns, std::size_t PermutSize,
                    bool UseLookup, std::size_t LookupTableSize,
                    std::size_t AlphaPowersN, std::size_t PublicInputSize>
                struct kimchi_params_type {
                    constexpr static std::size_t alpha_powers_n = AlphaPowersN;
                    constexpr static std::size_t public_input_size = PublicInputSize;
                    constexpr static std::size_t witness_columns = WitnessColumns;
                    constexpr static std::size_t permut_size = PermutSize;
                    constexpr static std::size_t lookup_table_size = LookupTableSize;
                    constexpr static bool use_lookup = UseLookup;

                    constexpr static std::size_t permutation_constraints = 3;
                    constexpr static std::size_t generic_constraints = 2;

                    constexpr static std::size_t eval_points_amount = 2;
                };

                template <std::size_t EvalRounds,
                    std::size_t MaxPolySize, std::size_t SrsLen>
                struct kimchi_commitment_params_type {
                    constexpr static std::size_t max_poly_size = MaxPolySize;
                    constexpr static std::size_t eval_rounds = EvalRounds;
                    constexpr static std::size_t res_size = max_poly_size == (1 << eval_rounds) ? 1 : 2;
                    constexpr static std::size_t srs_len = SrsLen;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PARAMS_HPP