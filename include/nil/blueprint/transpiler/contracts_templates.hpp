//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//
#ifndef __CONTRACTS_TEMPLATE_HPP__
#define __CONTRACTS_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string main_contract_template = R"(
pragma solidity >=0.8.4;

import "../../cryptography/transcript.sol";
// Move away unused structures from types.sol
import "../../types.sol";
import "../../basic_marshalling.sol";
import "../../interfaces/modular_verifier.sol";
import "../../interfaces/modular_commitment.sol";
import "../../interfaces/modular_gate_argument.sol";
import "../../interfaces/modular_lookup_argument.sol";
import "../../interfaces/modular_permutation_argument.sol";
import "hardhat/console.sol";

contract modular_verifier_circuit3 is IModularVerifier{
    uint256 constant modulus = $MODULUS$;
    bool    constant use_lookups = false;
    bytes32 constant vk1 = bytes32($VERIFICATION_KEY_1$);
    bytes32 constant vk2 = bytes32($VERIFICATION_KEY_2$);
    bytes32 transcript_state;
    address _gate_argument_address;
    address _permutation_argument_address;
    address _lookup_argument_address;
    address _commitment_contract_address;
    uint8   constant f_parts = 8;   // Individually on parts
    uint32  constant z_offset = 212;
    uint32  constant table_offset = z_offset + 0x20 * 10;
    uint32  constant z_end = 0x35 * 0x20;

    bytes   constant batched_points = hex"020202020202020202020303030203";
    bytes   constant variable_points = hex"010101";
    bytes   constant permutation_points = hex"0202";
    bytes   constant quotient_points = hex"010101010101";
    bytes   constant lookup_points = hex"0303";

    uint16 constant fixed_points_num = 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 3 + 3 + 3 + 2 + 3;
    uint16 constant variable_points_num = 3;
    uint16 constant permutation_points_num = 4;
    uint16 constant quotient_points_num = 6;
    uint16 constant lookup_points_num = 6;
    uint16 constant table_points_num = fixed_points_num - 10 + variable_points_num;

    constructor(){
    }

    function initialize(
        address permutation_argument_address,
        address lookup_argument_address, 
        address gate_argument_address,
        address commitment_contract_address
    ) public{
        console.log("Initialize");
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, hex"");
        transcript.update_transcript_b32(tr_state, vk1);
        transcript.update_transcript_b32(tr_state, vk2);

        _gate_argument_address = gate_argument_address;
        _permutation_argument_address = permutation_argument_address;
        _lookup_argument_address = lookup_argument_address;
        _commitment_contract_address = commitment_contract_address;

        ICommitmentScheme commitment_scheme = ICommitmentScheme(commitment_contract_address);
        tr_state.current_challenge = commitment_scheme.initialize(tr_state.current_challenge);
        transcript_state = tr_state.current_challenge;
    }

    function verify(
        bytes calldata blob
    ) public view{
        uint256 gas = gasleft();
        //0. Check proof size
        // No direct public input

        //1. Init transcript        
        types.transcript_data memory tr_state;
        tr_state.current_challenge = transcript_state;

        {
            //2. Push variable_values commitment to transcript
            transcript.update_transcript_b32_by_offset_calldata(tr_state, blob, 0x9);

            //3. Permutation argument
            $CALL_PERMUTATION_ARGUMENT$
            uint256 a = transcript.get_field_challenge(tr_state, modulus);//beta
            console.log("beta: ", a);
            uint256 b = transcript.get_field_challenge(tr_state, modulus);//beta
            console.log("gamma:", b);
            IModularPermutationArgument permutation_argument = IModularPermutationArgument(_permutation_argument_address);
            permutation_argument.verify(
                blob[z_offset:z_end], 
                a, 
                b
            );
        }

        {
            $CALL_LOOKUP_ARGUMENT$
            //4. Lookup argument
            IModularLookupArgument lookup_argument = IModularLookupArgument(_lookup_argument_address);
            ( , tr_state.current_challenge) = lookup_argument.verify(
                blob[table_offset: table_offset + table_points_num*0x20], blob[table_offset:z_end], basic_marshalling.get_uint256_be(blob, 0x81), tr_state.current_challenge
            );
        }
        
        //5. Push permutation batch to transcript
        transcript.update_transcript_b32_by_offset_calldata(tr_state, blob, 0x31);

        {
            $CALL_GATE_ARGUMENT$
            //6. Gate argument
            IModularGateArgument gate_argument = IModularGateArgument(_gate_argument_address);
            gate_argument.verify(blob[table_offset:table_offset + table_points_num*0x20], transcript.get_field_challenge(tr_state, modulus));
        }

        // No public input gate

        {
            //7. Push quotient to transcript
            uint256[f_parts] memory alphas;
            for( uint8 i = 0; i < f_parts;){
                alphas[i] = transcript.get_field_challenge(tr_state, modulus);
                console.log("alpha ", i, ":", alphas[i]);
                unchecked{i++;}
            }
            transcript.update_transcript_b32_by_offset_calldata(tr_state, blob, 0x59);
        }

        //8. Commitment scheme proof_eval
        {.
            $CALL_COMMITMENT_SCHEME$
            ICommitmentScheme commitment_scheme = ICommitmentScheme(_commitment_contract_address);

            uint256[] memory commitments = new uint256[](5);
            commitments[0] = uint256(vk2);
            commitments[1] = basic_marshalling.get_uint256_be(blob, 0x9);
            commitments[2] = basic_marshalling.get_uint256_be(blob, 0x31);
            commitments[3] = basic_marshalling.get_uint256_be(blob, 0x59);          
            commitments[4] = basic_marshalling.get_uint256_be(blob, 0x81);          
            if(!commitment_scheme.verify_eval(
                blob[z_offset:], commitments, basic_marshalling.get_uint256_be(blob, 0xa1), tr_state.current_challenge
            )) console.log("Error from commitment scheme!");
        }

        //9. Final check
        console.log("Gas for verification:", gas-gasleft());
    }
}
        )";
    }
}

#endif //__GATE_ARGUMENT_TEMPLATE_HPP__