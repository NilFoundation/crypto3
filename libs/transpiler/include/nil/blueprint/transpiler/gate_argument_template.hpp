#ifndef __GATE_ARGUMENT_TEMPLATE_HPP__
#define __GATE_ARGUMENT_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
// Functions for columns with non-zero columns rotations
std::string field_rotated_witness_evaluations = "\t\tuint256[][] witness_evaluations;\n";
std::string load_rotated_witness_evaluations = R"(
        local_vars.witness_evaluations = new uint256[][](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            local_vars.witness_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length;) {
                local_vars.witness_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }
)";

std::string field_rotated_public_input_evaluations = "\t\tuint256[][] public_input_evaluations;\n";
std::string load_rotated_public_input_evaluations = R"(
        local_vars.public_input_evaluations = new uint256[][](ar_params.public_input_columns);
        for (uint256 i = 0; i < ar_params.public_input_columns;) {
            local_vars.public_input_evaluations[i] = new uint256[](columns_rotations[ar_params.withess_columns + i].length);
            for (uint256 j = 0; j < columns_rotations[ar_params.withess_columns + i].length;) {
                local_vars.public_input_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, ar_params.withess_columns + i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }
)";

std::string field_rotated_constant_evaluations = "\t\tuint256[][] constant_evaluations;\n";
std::string load_rotated_constant_evaluations = R"(
        local_vars.constant_evaluations = new uint256[][](ar_params.constant_columns);
        for (uint256 i = 0; i < ar_params.constant_columns;) {
            local_vars.constant_evaluations[i] = new uint256[](columns_rotations[ar_params.witness_colunms + ar_params.public_input_columns +i].length);
            for (uint256 j = 0; j < columns_rotations[ar_params.witness_colunms + ar_params.public_input_columns + i].length;) {
                local_vars.constant_evaluations[i][j] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, ar_params.permutation_columns + ar_params.permutation_columns + i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }
)";

std::string field_rotated_selector_evaluations = "\t\tuint256[][] selector_evaluations;\n";
std::string load_rotated_selector_evaluations = R"(
        local_vars.selector_evaluations = new uint256[][](ar_params.selector_columns);
        for (uint256 i = 0; i < ar_params.selector_columns;) {
            local_vars.selector_evaluations[i] = new uint256[](columns_rotations[ar_params.witness_colunms + ar_params.public_input_columns + ar_params.constant_columns + i].length);
            for (uint256 j = 0; j < columns_rotations[ar_params.witness_colunms + ar_params.public_input_columns + ar_params.constant_columns + i].length;) {
                local_vars.selector_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, ar_params.permutation_columns + ar_params.permutation_columns + i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }
)";

// Functions for columns with zero columns rotations
std::string field_witness_evaluations = "\t\tuint256[] witness_evaluations;\n";
std::string load_witness_evaluations = R"(
        local_vars.witness_evaluations = new uint256[](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            local_vars.witness_evaluations[i] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, 0
            );
            unchecked{i++;}
        }
)";
std::string field_public_input_evaluations = "\t\tuint256[] public_input_evaluations;\n";
std::string load_public_input_evaluations = R"(
        local_vars.public_input_evaluations = new uint256[](ar_params.public_input_columns);
        for (uint256 i = 0; i < ar_params.public_input_columns;) {
            local_vars.public_input_evaluations[i] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, 0
            );
            unchecked{i++;}
        }
)";
std::string field_constant_evaluations = "\t\tuint256[] constant_evaluations;\n";
std::string load_constant_evaluations = R"(
        local_vars.constant_evaluations = new uint256[](ar_params.constant_columns);
        for (uint256 i = 0; i < ar_params.constant_columns;) {
            local_vars.constant_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                blob, eval_proof_combined_value_offset, ar_params.permutation_columns + ar_params.permutation_columns + i, 0
            );
 
            unchecked{i++;}
        }
)";
std::string field_selector_evaluations = "\t\tuint256[] selector_evaluations;\n";
std::string load_selector_evaluations = R"(
        local_vars.selector_evaluations = new uint256[](ar_params.selector_columns);
        for (uint256 i = 0; i < ar_params.selector_columns;) {
            local_vars.selector_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                blob, eval_proof_combined_value_offset, ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns + i, 0
            );
            unchecked{i++;}
        }
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

import "../../../contracts/types.sol";
import "../../../contracts/basic_marshalling.sol";
import "../../../contracts/commitments/batched_lpc_verifier.sol";
import "../../../contracts/interfaces/gate_argument.sol";

$GATES_IMPORTS$

contract $TEST_ID$_gate_argument_split_gen  is IGateArgument{
    uint256 constant GATES_N = $GATES_NUMBER$;

    struct local_vars_type{
        // 0x0
        uint256 constraint_eval;
        // 0x20
        uint256 gate_eval;
        // 0x40
        uint256 gates_evaluation;
        // 0x60
        uint256 theta_acc;

$GATES_LOCAL_VARS_EVALUATION_FIELDS$
    }

    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        uint256 eval_proof_combined_value_offset,
        types.gate_argument_params memory gate_params,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external pure returns (uint256 gates_evaluation) {
        local_vars_type memory local_vars;

$GATES_LOAD_EVALUATIONS$

        local_vars.theta_acc = 1;
        local_vars.gates_evaluation = 0;

$GATES_EXECUTION$

        gates_evaluation = local_vars.gates_evaluation;
    }
}
)";

// Functions for extracting evaluations for rotated columns
std::string get_rotated_witness = R"(
            function get_witness_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }
)";
std::string get_rotated_witness_call = "get_witness_i_by_rotation_idx";

std::string get_rotated_public_input = R"(
            function get_public_input_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, PUBLIC_INPUT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }
)";
std::string get_rotated_public_input_call = "get_public_input_i_by_rotation_idx";

std::string get_rotated_constant = R"(
            function get_constant_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, CONSTANT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }
)";
std::string get_rotated_constant_call = "get_constant_i_by_rotation_idx";


std::string get_rotated_selector = R"(
            function get_selector_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }
)";
std::string get_rotated_selector_call = "get_selector_i_by_rotation_idx";

// Functions for extracting evaluations for non-rotated columns
std::string get_witness = R"(
            function get_witness_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }
)";
std::string get_witness_call = "get_witness_i";


std::string get_public_input = R"(
            function get_public_input_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, PUBLIC_INPUT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }
)";
std::string get_public_input_call = "get_public_input_i";

std::string get_constant = R"(
            function get_constant_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, CONSTANT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }
)";
std::string get_constant_call = "get_constant_i";

std::string get_selector = R"(
            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }
)";
std::string get_selector_call = "get_selector_i";

std::string gate_sol_file_template = R"(
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

import "../../../contracts/types.sol";
import "./gate_argument.sol";

library $TEST_ID$_gate$CONTRACT_NUMBER${
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;

    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x00;
    uint256 constant GATE_EVAL_OFFSET = 0x20;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x40;
    uint256 constant THETA_ACC_OFFSET = 0x60;
    
$GATE_ARGUMENT_LOCAL_VARS_OFFSETS$

    function evaluate_gate_be(
        types.gate_argument_params memory gate_params,
        $TEST_ID$_gate_argument_split_gen.local_vars_type memory local_vars
    ) external pure returns (uint256 gates_evaluation, uint256 theta_acc) {
        gates_evaluation = local_vars.gates_evaluation;
        theta_acc = local_vars.theta_acc;
        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            let theta := mload(add(gate_params, THETA_OFFSET))

            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
$GATES_GET_EVALUATIONS_FUNCTIONS$
$GATES_ASSEMBLY_CODE$
        }
    }
}
)";

std::string single_sol_file_template = R"(
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

import "../../../contracts/types.sol";
import "../../../contracts/basic_marshalling.sol";
import "../../../contracts/commitments/batched_lpc_verifier.sol";
import "../../../contracts/interfaces/gate_argument.sol";

contract $TEST_ID$_gate_argument_split_gen  is IGateArgument{
    uint256 constant GATES_N = $GATES_NUMBER$;

    struct local_vars_type{
        // 0x0
        uint256 constraint_eval;
        // 0x20
        uint256 gate_eval;
        // 0x40
        uint256 gates_evaluation;
        // 0x60
        uint256 theta_acc;

$GATES_LOCAL_VARS_EVALUATION_FIELDS$
    }

    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;

    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x00;
    uint256 constant GATE_EVAL_OFFSET = 0x20;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x40;
    uint256 constant THETA_ACC_OFFSET = 0x60;
$GATE_ARGUMENT_LOCAL_VARS_OFFSETS$

    function evaluate_gates_be(
        bytes calldata blob,
        uint256 eval_proof_combined_value_offset,
        types.gate_argument_params memory gate_params,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external pure returns (uint256 gates_evaluation) {
        local_vars_type memory local_vars;

$GATES_LOAD_EVALUATIONS$

        local_vars.theta_acc = 1;
        local_vars.gates_evaluation = 0;    

        uint256 theta_acc = local_vars.theta_acc;

        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            let theta := mload(add(gate_params, THETA_OFFSET))

$GATES_GET_EVALUATIONS_FUNCTIONS$
$GATES_EXECUTION$
        }
    }
}
)";
    }
}

#endif //__GATE_ARGUMENT_TEMPLATE_HPP__