//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PARAMS_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PARAMS_HPP

#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<
                    typename FieldType, 
                    typename ArithmetizationParams
                >
                struct placeholder_circuit_params {
                    constexpr static const std::size_t witness_columns = ArithmetizationParams::witness_columns;
                    constexpr static const std::size_t public_input_columns = ArithmetizationParams::public_input_columns;
                    constexpr static const std::size_t constant_columns = ArithmetizationParams::constant_columns;
                    constexpr static const std::size_t selector_columns = ArithmetizationParams::selector_columns;

                    using arithmetization_params = ArithmetizationParams;
                    using field_type = FieldType;
                    using public_input_type = std::array<std::vector<typename field_type::value_type>, arithmetization_params::public_input_columns>;
                    using constraint_system_type = plonk_constraint_system<field_type, arithmetization_params>;
                    using assignment_table_type = plonk_table<field_type, arithmetization_params, plonk_column<field_type>>;
                };

                template<typename CircuitParams, typename CommitmentScheme>
                struct placeholder_params {
                    constexpr static const std::size_t witness_columns = CircuitParams::witness_columns;
                    constexpr static const std::size_t public_input_columns = CircuitParams::public_input_columns;
                    constexpr static const std::size_t constant_columns = CircuitParams::constant_columns;
                    constexpr static const std::size_t selector_columns = CircuitParams::selector_columns;
                    constexpr static const std::size_t total_columns = witness_columns + public_input_columns + constant_columns + selector_columns;

                    using field_type = typename CircuitParams::field_type;

                    using arithmetization_params = typename CircuitParams::arithmetization_params;
                    using constraint_system_type = typename CircuitParams::constraint_system_type;
                    using assignment_table_type = typename CircuitParams::assignment_table_type;

                    using commitment_scheme_type = CommitmentScheme;
                    using commitment_scheme_params_type = typename CommitmentScheme::params_type;
                    using public_input_type = typename CircuitParams::public_input_type;

                    using transcript_hash_type = typename CommitmentScheme::transcript_hash_type;
                    using circuit_params_type = CircuitParams;

                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PARAMS_HPP
