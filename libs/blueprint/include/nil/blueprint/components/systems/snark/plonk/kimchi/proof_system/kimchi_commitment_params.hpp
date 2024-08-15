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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_PROOF_SYSTEM_KIMCHI_COMMITMENT_PARAMS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_PROOF_SYSTEM_KIMCHI_COMMITMENT_PARAMS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {
                template<std::size_t EvalRounds, std::size_t MaxPolySize, std::size_t SrsLen>
                struct kimchi_commitment_params_type {
                    constexpr static std::size_t max_poly_size = MaxPolySize;
                    constexpr static std::size_t eval_rounds = EvalRounds;
                    constexpr static std::size_t split_poly_eval_size = max_poly_size == (1 << eval_rounds) ? 1 : 2;
                    constexpr static std::size_t srs_len = SrsLen;

                    // TODO we can set commitments size values from template but for now it looks like we can just fix
                    // it
                    constexpr static std::size_t shifted_commitment_split = 1;
                    constexpr static std::size_t max_comm_size = 1;
                    constexpr static std::size_t w_comm_size = 1;
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_PROOF_SYSTEM_KIMCHI_COMMITMENT_PARAMS_HPP