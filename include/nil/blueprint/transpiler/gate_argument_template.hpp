#ifndef __GATE_ARGUMENT_TEMPLATE_HPP__
#define __GATE_ARGUMENT_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {

std::string command_line_arguments = R"(There are two commands:
    gen_test_proof    -- prepares gate argument, placeholder params and sample proof for testing
    gen_gate_argument -- prepares gate argument and some placeholder params
)";

std::string command_line_arguments_gen_test_proof = R"(Command-line parameters for proof generation
    1-st parameter is "gen_gate_argument" or "gen_test_proof" command
    2-nd parameter is input folder path
    3-rd parameter is output folder path
It'll be better to create an empty folder for output files.
Copy output folder to evm-placeholder-verification directory and run verifier
)";

std::string command_line_arguments_gen_gate_argument = R"(Command-line parameters for gate argument generation
    1-st parameter is "gen_gate_argument" or "gen_test_proof" command
    2-nd parameter is input folder path
    3-rd parameter is output folder path
It'll be better to create an empty folder for output files.
Copy output folder to evm-placeholder-verification.
)";

std::string main_sol_file_template = R"(
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova  <alalmoskvin@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.8.4;

import "../contracts/types.sol";
import "../contracts/profiling.sol";
import "../contracts/basic_marshalling.sol";
import "../contracts/commitments/batched_lpc_verifier.sol";
import "../contracts/gate_argument_interface.sol";

$GATES_IMPORTS$

// TODO: name component
contract gate_argument_split_gen  is IGateArgument{
    // TODO: specify constants
    uint256 constant GATES_N = $GATES_NUMBER$;

    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        types.gate_argument_local_vars memory gate_params,
        uint256 eval_proof_combined_value_offset,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external view returns (uint256 gates_evaluation) {
        // TODO: check witnesses number in proof
        gate_params.witness_evaluations = new uint256[][](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            gate_params.witness_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length;) {
                gate_params.witness_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }

        gate_params.selector_evaluations = new uint256[](GATES_N);
        for (uint256 i = 0; i < GATES_N;) {
            gate_params.selector_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns,
                    0
            );
            unchecked{i++;}
        }

        gate_params.constant_evaluations = new uint256[](ar_params.constant_columns);
        for (uint256 i = 0; i < ar_params.constant_columns;) {
            gate_params.constant_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns,
                    0
            );
            unchecked{i++;}
        }

        gate_params.theta_acc = 1;
        gate_params.gates_evaluation = 0;

$GATES_EXECUTION$

        gates_evaluation = gate_params.gates_evaluation;
    }
}
)";

std::string gate_sol_file_template = R"(
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.8.4;

import "../contracts/types.sol";
import "../contracts/logging.sol";

// TODO: name component
library gate$CONTRACT_NUMBER${
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;
    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x40;
    uint256 constant GATE_EVAL_OFFSET = 0x60;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x80;
    uint256 constant THETA_ACC_OFFSET = 0xa0;
    uint256 constant WITNESS_EVALUATIONS_OFFSET = 0xc0;
    uint256 constant CONSTANT_EVALUATIONS_OFFSET = 0xe0;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET =0x100;
    uint256 constant PUBLIC_INPUT_EVALUATIONS_OFFSET =0x120;

    function evaluate_gate_be(
        types.gate_argument_local_vars memory gate_params
    ) external pure returns (uint256 gates_evaluation, uint256 theta_acc) {
        gates_evaluation = gate_params.gates_evaluation;
        theta_acc = gate_params.theta_acc;
        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)

            function get_witness_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }

            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

            function get_public_input_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, PUBLIC_INPUT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

            // rot_idx is temporary unused
            function get_constant_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, CONSTANT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

$GATES_ASSEMBLY_CODE$
        }
    }
}
)";
    }
}

#endif //__GATE_ARGUMENT_TEMPLATE_HPP__