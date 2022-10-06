//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PROOF_SYSTEM_CIRCUIT_DESCRIPTION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PROOF_SYSTEM_CIRCUIT_DESCRIPTION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename IndexTermsList, std::size_t WitnessColumns, std::size_t PermutSize>
                struct kimchi_circuit_description {
                    using index_terms_list = IndexTermsList;

                    static const std::size_t witness_columns = WitnessColumns;
                    static const std::size_t permut_size = PermutSize;

                    static const std::size_t alpha_powers_n = index_terms_list::alpha_powers_n;

                    static const bool poseidon_gate = index_terms_list::poseidon_gate;
                    static const bool ec_arithmetic_gates = index_terms_list::ec_arithmetic_gates;
                    static const bool chacha_gate = index_terms_list::chacha_gate;
                    static const bool generic_gate = index_terms_list::generic_gate;

                    static const std::size_t poseidon_gates_count = index_terms_list::poseidon_gates_count;
                    static const std::size_t ec_arithmetic_gates_count = index_terms_list::ec_arithmetic_gates_count;

                    static const bool use_lookup = index_terms_list::lookup_columns > 0;
                    static const bool joint_lookup = index_terms_list::joint_lookup;
                    static const std::size_t lookup_columns = index_terms_list::lookup_columns;
                    static const bool lookup_runtime = index_terms_list::lookup_runtime;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PROOF_SYSTEM_CIRCUIT_DESCRIPTION_HPP