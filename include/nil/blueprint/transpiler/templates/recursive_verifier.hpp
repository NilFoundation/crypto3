#ifndef __RECURSIVE_VERIFIER_TEMPLATE_HPP__
#define __RECURSIVE_VERIFIER_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string recursive_verifier_template = R"(
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

const bool use_lookups = false;
const size_t batches_num = $BATCHES_NUM$;
const size_t commitments_num = $COMMITMENTS_NUM$;
const size_t points_num = $POINTS_NUM$;
const size_t poly_num = $POLY_NUM$;
const size_t initial_proof_points_num = $INITIAL_PROOF_POINTS_NUM$;
const size_t round_proof_points_num = $ROUND_PROOF_POINTS_NUM$;
const size_t fri_roots_num = $FRI_ROOTS_NUM$;
const size_t initial_merkle_proofs_num = $INITIAL_MERKLE_PROOFS_NUM$;
const size_t initial_merkle_proofs_position_num = $INITIAL_MERKLE_PROOFS_POSITION_NUM$;
const size_t initial_merkle_proofs_hash_num = $INITIAL_MERKLE_PROOFS_HASH_NUM$;
const size_t round_merkle_proofs_position_num = $ROUND_MERKLE_PROOFS_POSITION_NUM$;
const size_t round_merkle_proofs_hash_num = $ROUND_MERKLE_PROOFS_HASH_NUM$;
const size_t final_polynomial_size = $FINAL_POLYNOMIAL_SIZE$;
const size_t lambda = $LAMBDA$;
const size_t rows_amount = $ROWS_AMOUNT$;
const size_t total_columns = $TOTAL_COLUMNS$;
const size_t permutation_size = $PERMUTATION_SIZE$;
const std::array<size_t, total_columns> zero_indices = {$ZERO_INDICES$};
const size_t table_values_num = $TABLE_VALUES_NUM$;
const size_t gates_amount = $GATES_AMOUNT$;
const size_t constraints_amount = $CONSTRAINTS_AMOUNT$;
const size_t witness_amount = $WITNESS_COLUMNS_AMOUNT$;
const size_t public_input_amount = $PUBLIC_INPUT_COLUMNS_AMOUNT$;
const size_t constant_amount = $CONSTANT_COLUMNS_AMOUNT$;
const size_t selector_amount = $SELECTOR_COLUMNS_AMOUNT$;
const size_t quotient_polys_start = $QUOTIENT_POLYS_START$;
const size_t quotient_polys_amount = $QUOTIENT_POLYS_AMOUNT$;
std::array<int, gates_amount> gates_sizes = {$GATES_SIZES$};

struct placeholder_proof_type{
    std::array<pallas::base_field_type::value_type, commitments_num> commitments;
    pallas::base_field_type::value_type challenge;
    std::array<pallas::base_field_type::value_type, points_num> z;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_roots;
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> initial_proof_values;
    std::array<pallas::base_field_type::value_type, round_proof_points_num> round_proof_values;
    std::array<pallas::base_field_type::value_type, initial_merkle_proofs_position_num> initial_proof_positions;
    std::array<pallas::base_field_type::value_type, initial_merkle_proofs_hash_num> initial_proof_hashes;
    std::array<pallas::base_field_type::value_type, round_merkle_proofs_position_num> round_merkle_proof_positions;
    std::array<pallas::base_field_type::value_type, round_merkle_proofs_hash_num> round_proof_hashes;
    std::array<pallas::base_field_type::value_type, final_polynomial_size> final_polynomial;
};

struct placeholder_challenges_type{
    pallas::base_field_type::value_type fri_etha;
    pallas::base_field_type::value_type perm_beta;
    pallas::base_field_type::value_type perm_gamma;
    pallas::base_field_type::value_type lookup_theta;
    pallas::base_field_type::value_type lookup_gamma;
    pallas::base_field_type::value_type lookup_beta;
    std::array<pallas::base_field_type::value_type, 1> lookup_alphas;
    pallas::base_field_type::value_type gate_theta;
    std::array<pallas::base_field_type::value_type, 8> alphas;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_alphas;
    std::array<pallas::base_field_type::value_type, lambda> fri_x_indices;
    pallas::base_field_type::value_type xi;
};

typedef __attribute__((ext_vector_type(2))) typename pallas::base_field_type::value_type permutation_argument_thetas_type;
typedef __attribute__((ext_vector_type(3))) typename pallas::base_field_type::value_type permutation_argument_output_type;

struct placeholder_permutation_argument_input_type{
    std::array<typename pallas::base_field_type::value_type, permutation_size> xi_values;
    std::array<typename pallas::base_field_type::value_type, permutation_size> id_perm;
    std::array<typename pallas::base_field_type::value_type, permutation_size> sigma_perm;
    permutation_argument_thetas_type thetas;
};

pallas::base_field_type::value_type transcript(pallas::base_field_type::value_type tr_state, pallas::base_field_type::value_type value) {
    return hash<hashes::poseidon>(value, hash<hashes::poseidon>(tr_state, tr_state));
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type > transcript_challenge(pallas::base_field_type::value_type tr_state) {
    return std::make_pair(hash<hashes::poseidon>(tr_state, tr_state), hash<hashes::poseidon>(tr_state, tr_state));
}

placeholder_challenges_type generate_challenges(
    const std::array<pallas::base_field_type::value_type, 2> &vk,
    const placeholder_proof_type &proof
){
    placeholder_challenges_type challenges;

    pallas::base_field_type::value_type tr_state(0x2fadbe2852044d028597455bc2abbd1bc873af205dfabb8a304600f3e09eeba8_cppui255);

    tr_state = transcript(tr_state, vk[0]);
    tr_state = transcript(tr_state, vk[1]);

    // LPC additional point
    std::tie(tr_state, challenges.fri_etha) = transcript_challenge(tr_state);

    tr_state = transcript(tr_state, proof.commitments[0]);

    std::tie(tr_state, challenges.perm_beta) = transcript_challenge(tr_state);
    std::tie(tr_state, challenges.perm_gamma) = transcript_challenge(tr_state);

    // Call lookup argument
    if( use_lookups ){
        __builtin_assigner_exit_check(false);
    }

    // Call gate argument
    tr_state = transcript(tr_state, proof.commitments[1]);
    std::tie(tr_state, challenges.gate_theta) = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < 8; i++){
        std::tie(tr_state, challenges.alphas[i]) = transcript_challenge(tr_state);
    }
    tr_state = transcript(tr_state, proof.commitments[2]);

    std::tie(tr_state, challenges.xi) = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < fri_roots_num; i++){
        tr_state = transcript(tr_state, proof.fri_roots[i]);
        std::tie(tr_state, challenges.fri_alphas[i]) = transcript_challenge(tr_state);
    }

    for(std::size_t i = 0; i < lambda; i++){
        std::tie(tr_state, challenges.fri_x_indices[i]) = transcript_challenge(tr_state);
    }

    return challenges;
}

pallas::base_field_type::value_type pow(pallas::base_field_type::value_type x, size_t p){
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 1; i < p; i++){
        result = result * x;
    }
    return result;
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type> xi_polys(
    pallas::base_field_type::value_type xi
){
    pallas::base_field_type::value_type xi_n = pow(xi, rows_amount) - pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type l0 = (xi - pallas::base_field_type::value_type(1))*pallas::base_field_type::value_type(rows_amount);
    l0 = xi_n / l0;
    return std::make_pair(l0, xi_n);
}

std::array<pallas::base_field_type::value_type, constraints_amount> calculate_constraints(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
$CONSTRAINTS_BODY$

    return constraints;
}

typename pallas::base_field_type::value_type
    gate_argument_verifier(
        std::array<typename pallas::base_field_type::value_type, gates_amount> selectors,
        std::array<typename pallas::base_field_type::value_type, constraints_amount> constraints,
        typename pallas::base_field_type::value_type theta
    ) {

    return __builtin_assigner_gate_arg_verifier(
        selectors.data(),
        (int*)gates_sizes.data(),
        gates_amount,
        constraints.data(),
        constraints_amount,
        theta
    );
}

constexpr std::size_t L0_IND = 0;
constexpr std::size_t Z_AT_XI_IND = 1;
constexpr std::size_t F_CONSOLIDATED_IND = 2;
constexpr std::size_t T_CONSOLIDATED_IND = 3;

[[circuit]] bool placeholder_verifier(
    std::array<pallas::base_field_type::value_type, 2> vk,
    placeholder_proof_type proof
) {
    placeholder_challenges_type challenges = generate_challenges(vk, proof);
    __builtin_assigner_exit_check(challenges.xi == proof.challenge);

    std::array<pallas::base_field_type::value_type, 4> different_values;
    std::tie(different_values[L0_IND], different_values[Z_AT_XI_IND]) = xi_polys(challenges.xi);

    std::array<pallas::base_field_type::value_type, 8> F = {0,0,0,0,0,0,0,0};

    // Call permutation argument
    placeholder_permutation_argument_input_type perm_arg_input;
    perm_arg_input.thetas[0] = challenges.perm_beta;
    perm_arg_input.thetas[1] = challenges.perm_gamma;

    for( std::size_t i = 0; i < permutation_size; i++ ){
        perm_arg_input.xi_values[i] = proof.z[4*permutation_size + 6 + zero_indices[i]];
        perm_arg_input.id_perm[i] = proof.z[2*i];
        perm_arg_input.sigma_perm[i] = proof.z[2*permutation_size + 2*i];
    }

    permutation_argument_output_type permutation_argument = __builtin_assigner_permutation_arg_verifier(
        perm_arg_input.xi_values.data(),
        perm_arg_input.id_perm.data(),
        perm_arg_input.sigma_perm.data(),
        permutation_size,
        different_values[L0_IND],
        proof.z[4*permutation_size + 6 + table_values_num],     // V
        proof.z[4*permutation_size + 6 + table_values_num + 1], // V_shifted
        proof.z[4*permutation_size],                            // q_last
        proof.z[4*permutation_size + 3],                        // q_blind
        perm_arg_input.thetas
    );

    F[0] = permutation_argument[0];
    F[1] = permutation_argument[1];
    F[2] = permutation_argument[2];
    {
        std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
        std::array<pallas::base_field_type::value_type, gates_amount> selectors;
        constraints = calculate_constraints(proof.z);

        for( std::size_t i = 0; i < gates_amount; i++ ){
            selectors[i] = proof.z[4 * permutation_size + 6 + zero_indices[i + witness_amount+public_input_amount + constant_amount]];
        }


        F[7] = gate_argument_verifier(
            selectors,
            constraints,
            challenges.gate_theta
        );
        F[7] *= (pallas::base_field_type::value_type(1) - proof.z[4*permutation_size] - proof.z[4*permutation_size + 3]);
    }

    different_values[F_CONSOLIDATED_IND] = pallas::base_field_type::value_type(0);
    for(std::size_t i = 0; i < 8; i++){
        F[i] *= challenges.alphas[i];
        different_values[F_CONSOLIDATED_IND] += F[i];
    }

    different_values[T_CONSOLIDATED_IND] = pallas::base_field_type::value_type(0);
    pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
    for(std::size_t i = 0; i < quotient_polys_amount; i++){
        different_values[T_CONSOLIDATED_IND] += proof.z[quotient_polys_start + i] * factor;
        factor *= (different_values[Z_AT_XI_IND] + pallas::base_field_type::value_type(1));
    }
    __builtin_assigner_exit_check(different_values[F_CONSOLIDATED_IND] == different_values[T_CONSOLIDATED_IND] * (different_values[Z_AT_XI_IND]));

    return true;
}
    )";
    }
}

#endif //__RECURSIVE_VERIFIER_TEMPLATE_HPP__