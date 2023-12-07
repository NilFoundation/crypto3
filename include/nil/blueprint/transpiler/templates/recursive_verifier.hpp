#ifndef __RECURSIVE_VERIFIER_TEMPLATE_HPP__
#define __RECURSIVE_VERIFIER_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string recursive_verifier_template = R"(
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

$USE_LOOKUPS_DEFINE$

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

const bool use_lookups = $USE_LOOKUPS$;
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
const size_t rows_log = $ROWS_LOG$;
const size_t total_columns = $TOTAL_COLUMNS$;
const size_t sorted_columns = $SORTED_COLUMNS$;
const size_t permutation_size = $PERMUTATION_SIZE$;
const std::array<size_t, total_columns> zero_indices = {$ZERO_INDICES$};
const size_t table_values_num = $TABLE_VALUES_NUM$;
const size_t gates_amount = $GATES_AMOUNT$;
constexpr std::array<std::size_t, gates_amount> gates_selector_indices = {$GATES_SELECTOR_INDICES$};
const size_t constraints_amount = $CONSTRAINTS_AMOUNT$;
const size_t witness_amount = $WITNESS_COLUMNS_AMOUNT$;
const size_t public_input_amount = $PUBLIC_INPUT_COLUMNS_AMOUNT$;
const size_t constant_amount = $CONSTANT_COLUMNS_AMOUNT$;
const size_t selector_amount = $SELECTOR_COLUMNS_AMOUNT$;
const size_t quotient_polys_start = $QUOTIENT_POLYS_START$;
const size_t quotient_polys_amount = $QUOTIENT_POLYS_AMOUNT$;
const size_t lookup_sorted_polys_start = $LOOKUP_SORTED_START$;
const size_t D0_size = $D0_SIZE$;
const size_t D0_log = $D0_LOG$;
const pallas::base_field_type::value_type D0_omega = $D0_OMEGA$;
const pallas::base_field_type::value_type omega = $OMEGA$;
const size_t fri_rounds = $FRI_ROUNDS$;
const std::array<int, gates_amount> gates_sizes = {$GATES_SIZES$};
const size_t unique_points = $UNIQUE_POINTS$;
const std::array<int, poly_num> point_ids = {$POINTS_IDS$};
const size_t singles_amount = $SINGLES_AMOUNT$;
std::array<std::size_t, batches_num> batches_amount_list = {$BATCHES_AMOUNT_LIST$};

#ifdef __USE_LOOKUPS__
const size_t lookup_table_amount = $LOOKUP_TABLE_AMOUNT$;
const size_t lookup_gate_amount = $LOOKUP_GATE_AMOUNT$;
constexpr std::array<std::size_t, lookup_table_amount> lookup_options_amount_list = {$LOOKUP_OPTIONS_AMOUNT_LIST$};
constexpr std::array<std::size_t, lookup_table_amount> lookup_tables_columns_amount_list = {$LOOKUP_TABLES_COLUMNS_AMOUNT_LIST$};
constexpr std::size_t lookup_options_amount = $LOOKUP_OPTIONS_AMOUNT$;
constexpr std::size_t lookup_table_columns_amount = $LOOKUP_TABLES_COLUMNS_AMOUNT$;

constexpr std::array<std::size_t, lookup_gate_amount> lookup_constraints_amount_list = {$LOOKUP_CONSTRAINTS_AMOUNT_LIST$};
constexpr std::size_t lookup_constraints_amount = $LOOKUP_CONSTRAINTS_AMOUNT$;
constexpr std::array<std::size_t, lookup_constraints_amount> lookup_expressions_amount_list = {$LOOKUP_EXPRESSIONS_AMOUNT_LIST$};
constexpr std::size_t lookup_expressions_amount = $LOOKUP_EXPRESSIONS_AMOUNT$;


constexpr std::size_t m_parameter = lookup_options_amount + lookup_constraints_amount;
constexpr std::size_t input_size_alphas = m_parameter - 1;

constexpr std::size_t input_size_lookup_gate_selectors = lookup_gate_amount;
constexpr std::size_t input_size_lookup_gate_constraints_table_ids = lookup_constraints_amount;
constexpr std::size_t input_size_lookup_gate_constraints_lookup_inputs = lookup_expressions_amount;

constexpr std::size_t input_size_lookup_table_selectors = lookup_table_amount;
constexpr std::size_t input_size_lookup_table_lookup_options = lookup_table_columns_amount;

constexpr std::size_t input_size_shifted_lookup_table_selectors = lookup_table_amount;
constexpr std::size_t input_size_shifted_lookup_table_lookup_options = lookup_table_columns_amount;

constexpr std::size_t input_size_sorted = m_parameter * 3 - 1;
#endif

struct placeholder_proof_type{
    std::array<pallas::base_field_type::value_type, commitments_num> commitments;
    pallas::base_field_type::value_type challenge;
    std::array<pallas::base_field_type::value_type, points_num> z;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_roots;
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> initial_proof_values;
    std::array<pallas::base_field_type::value_type, round_proof_points_num> round_proof_values;
    std::array<int, initial_merkle_proofs_position_num> initial_proof_positions;
    std::array<pallas::base_field_type::value_type, initial_merkle_proofs_hash_num> initial_proof_hashes;
    std::array<int, round_merkle_proofs_position_num> round_merkle_proof_positions;
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
    std::array<pallas::base_field_type::value_type, $SORTED_ALPHAS$> lookup_alphas;
    pallas::base_field_type::value_type gate_theta;
    std::array<pallas::base_field_type::value_type, 8> alphas;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_alphas;
    std::array<pallas::base_field_type::value_type, lambda> fri_x_indices;
    pallas::base_field_type::value_type lpc_theta;
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

struct transcript_state_type{
    std::array <pallas::base_field_type::value_type, 3> state;
    std::size_t cur;
};

void transcript(transcript_state_type &tr_state, pallas::base_field_type::value_type value) {
    tr_state.state[tr_state.cur] = value;
    if(tr_state.cur == 2){
        tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0],tr_state.state[1],tr_state.state[2]})[2];
        tr_state.state[1] = pallas::base_field_type::value_type(0);
        tr_state.state[2] = pallas::base_field_type::value_type(0);
        tr_state.cur = 1;
    } else{
        tr_state.state[tr_state.cur] = value;
        tr_state.cur++;
    }
}

pallas::base_field_type::value_type transcript_challenge(transcript_state_type &tr_state) {
    tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0], tr_state.state[1], tr_state.state[2]})[2];
    tr_state.state[1] = pallas::base_field_type::value_type(0);
    tr_state.state[2] = pallas::base_field_type::value_type(0);
    tr_state.cur = 1;
    return tr_state.state[0];
}

pallas::base_field_type::value_type pow2_p(pallas::base_field_type::value_type x, size_t plog){
    if(plog == 0) return pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 0; i < plog; i++){
        result = result * result;
    }
    return result;
}

pallas::base_field_type::value_type pow2(pallas::base_field_type::value_type x){
    return x*x;
}

pallas::base_field_type::value_type pow3(pallas::base_field_type::value_type x){
    return x*x*x;
}

pallas::base_field_type::value_type pow4(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result;
}

pallas::base_field_type::value_type pow5(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result * x;
}

pallas::base_field_type::value_type pow6(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x * x;
    result = result * result;
    return result;
}

pallas::base_field_type::value_type pow7(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x * x;
    result = result * result;
    return result * x;
}

pallas::base_field_type::value_type pow8(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result * result;
}

pallas::base_field_type::value_type pow9(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x;
    result = result * result;
    result = result * result;
    result = result * result;
    result = result * x;
    return result;
}

pallas::base_field_type::value_type pow(pallas::base_field_type::value_type x, size_t p){
    pallas::base_field_type::value_type result = 1;
	std::size_t mask = 1;
	while(mask < p){mask = mask * 2;} // 8
 	while(mask > 1){
		result = result * result;
        mask = mask / 2;
		if( p >= mask ){
			result = result * x;
			p = p - mask;
		}
	}
    return result;
}

std::array<pallas::base_field_type::value_type, singles_amount> fill_singles(
    pallas::base_field_type::value_type xi,
    pallas::base_field_type::value_type etha
){
    std::array<pallas::base_field_type::value_type, singles_amount> singles;
$SINGLES_COMPUTATION$;
    return singles;
}

placeholder_challenges_type generate_challenges(
    const std::array<pallas::base_field_type::value_type, 2> &vk,
    const placeholder_proof_type &proof
){
    placeholder_challenges_type challenges;

    transcript_state_type tr_state;
    tr_state.state[0] = pallas::base_field_type::value_type(0);
    tr_state.state[1] = pallas::base_field_type::value_type(0);
    tr_state.state[2] = pallas::base_field_type::value_type(0);
    tr_state.cur = 1;

    transcript(tr_state, vk[0]);
    transcript(tr_state, vk[1]);

    // LPC additional point
    challenges.fri_etha = transcript_challenge(tr_state);

    transcript(tr_state, proof.commitments[0]);

    challenges.perm_beta = transcript_challenge(tr_state);
    challenges.perm_gamma = transcript_challenge(tr_state);

    // Call lookup argument
    if( use_lookups ){
        challenges.lookup_theta = transcript_challenge(tr_state);
        transcript(tr_state, proof.commitments[3]);
        challenges.lookup_beta = transcript_challenge(tr_state);
        challenges.lookup_gamma = transcript_challenge(tr_state);

        for(std::size_t i = 0; i < sorted_columns-1; i++){
            challenges.lookup_alphas[i] = transcript_challenge(tr_state);
        }
    }

    // Call gate argument
    transcript(tr_state, proof.commitments[1]);
    challenges.gate_theta = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < 8; i++){
        challenges.alphas[i] = transcript_challenge(tr_state);
    }
    transcript(tr_state, proof.commitments[2]);

    challenges.xi = transcript_challenge(tr_state);

    transcript(tr_state, vk[1]);
    for(std::size_t i = 0; i < proof.commitments.size(); i++){
        transcript(tr_state, proof.commitments[i]);
    }

    challenges.lpc_theta = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < fri_roots_num; i++){
        transcript(tr_state, proof.fri_roots[i]);
        challenges.fri_alphas[i] = transcript_challenge(tr_state);
    }

    for(std::size_t i = 0; i < lambda; i++){
        challenges.fri_x_indices[i] = transcript_challenge(tr_state);
    }

    return challenges;
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type> xi_polys(
    pallas::base_field_type::value_type xi
){
    pallas::base_field_type::value_type xi_n = pow2_p(xi, rows_log) - pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type l0 = (xi - pallas::base_field_type::value_type(1))*pallas::base_field_type::value_type(rows_amount);
    l0 = xi_n / l0;
    return std::make_pair(l0, xi_n);
}

std::array<pallas::base_field_type::value_type, constraints_amount> calculate_constraints(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
$CONSTRAINTS_BODY$

    return constraints;
}

#ifdef __USE_LOOKUPS__
std::array<pallas::base_field_type::value_type, lookup_expressions_amount> calculate_lookup_expressions(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, lookup_expressions_amount> expressions;
$LOOKUP_EXPRESSIONS_BODY$

    return expressions;
}
#endif

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

std::array<pallas::base_field_type::value_type, 4> getV3(
    pallas::base_field_type::value_type xi0,pallas::base_field_type::value_type xi1,pallas::base_field_type::value_type xi2
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] = - xi0 * xi1 * xi2;
    result[1] = xi0 * xi1  + xi1 * xi2 + xi0 * xi2;
    result[2] = - xi0 - xi1 - xi2;
    result[3] = pallas::base_field_type::value_type(1);
//    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 4> getV2(
    pallas::base_field_type::value_type xi0,pallas::base_field_type::value_type xi1
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] =  xi0 * xi1;
    result[1] = - xi0 - xi1;
    result[2] = pallas::base_field_type::value_type(1);
    result[3] = pallas::base_field_type::value_type(0);
//    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 4> getV1(
    pallas::base_field_type::value_type xi0
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] = - xi0;
    result[1] = pallas::base_field_type::value_type(1);
    result[2] = pallas::base_field_type::value_type(0);
    result[3] = pallas::base_field_type::value_type(0);
//    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU3(
    pallas::base_field_type::value_type x0,pallas::base_field_type::value_type x1,pallas::base_field_type::value_type x2,
    pallas::base_field_type::value_type z0,pallas::base_field_type::value_type z1,pallas::base_field_type::value_type z2
){
    std::array<pallas::base_field_type::value_type, 3> result;
    pallas::base_field_type::value_type denom = (x0-x1)*(x1-x2)*(x2-x0);

    z0 = z0 * (x2-x1);
    z1 = z1 * (x0-x2);
    z2 = z2 * (x1-x0);

    result[0] = (z0*x1*x2 + z1*x0*x2 + z2*x0*x1)/denom;
    result[1] = (-z0*(x1 + x2) - z1*(x0 + x2) - z2 * (x0 + x1))/denom;
    result[2] = (z0 + z1 + z2)/denom;

//    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0/(x2-x1));
//    __builtin_assigner_exit_check(result[0] + x1 * result[1] + x1 * x1 * result[2] == z1/(x0-x2));
//    __builtin_assigner_exit_check(result[0] + x2 * result[1] + x2 * x2 * result[2] == z2/(x1-x0));

    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU2(
    pallas::base_field_type::value_type x0,pallas::base_field_type::value_type x1,
    pallas::base_field_type::value_type z0,pallas::base_field_type::value_type z1
){
    std::array<pallas::base_field_type::value_type, 3> result;
    pallas::base_field_type::value_type denom = (x0-x1);
    result[0] = (-z0*x1 + z1*x0)/denom;
    result[1] = (z0 - z1)/denom;
    result[2] = pallas::base_field_type::value_type(0);

//    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0);
//    __builtin_assigner_exit_check(result[0] + x1 * result[1] + x1 * x1 * result[2] == z1);

    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU1(
    pallas::base_field_type::value_type x0,
    pallas::base_field_type::value_type z0
){
    std::array<pallas::base_field_type::value_type, 3> result;
    result[0] = z0;
    result[1] = pallas::base_field_type::value_type(0);
    result[2] = pallas::base_field_type::value_type(0);

//    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0);

    return result;
}

pallas::base_field_type::value_type eval4(std::array<pallas::base_field_type::value_type, 4> poly, pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result;
    result = poly[3];
    result = result *x + poly[2];
    result = result *x + poly[1];
    result = result *x + poly[0];
//    __builtin_assigner_exit_check(poly[0] + x * poly[1] + x * x * poly[2] + x*x*x*poly[3] == result);
    return result;
}

pallas::base_field_type::value_type eval3(std::array<pallas::base_field_type::value_type, 3> poly, pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result;
    result = poly[2];
    result = result *x + poly[1];
    result = result *x + poly[0];
//    __builtin_assigner_exit_check(poly[0] + x * poly[1] + x * x * poly[2] == result);
    return result;
}

pallas::base_field_type::value_type calculate_leaf_hash(
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> val,
    std::size_t start_index,
    std::size_t leaf_size
){
    pallas::base_field_type::value_type hash_state = pallas::base_field_type::value_type(0);
    for(std::size_t pos = 0; pos < leaf_size; pos+=2){
        hash_state = __builtin_assigner_poseidon_pallas_base(
            {hash_state, val[start_index + pos], val[start_index + pos+1]}
        )[2];
    }
    return hash_state;
}

pallas::base_field_type::value_type calculate_reversed_leaf_hash(
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> &val,
    std::size_t start_index,
    std::size_t leaf_size
){
    pallas::base_field_type::value_type hash_state = pallas::base_field_type::value_type(0);
    for(std::size_t pos = 0; pos < leaf_size; pos+=2){
        hash_state = __builtin_assigner_poseidon_pallas_base(
            {hash_state, val[start_index + pos + 1], val[start_index + pos]}
        )[2];
    }
    return hash_state;
}

constexpr std::size_t L0_IND = 0;
constexpr std::size_t Z_AT_XI_IND = 1;
constexpr std::size_t F_CONSOLIDATED_IND = 2;
constexpr std::size_t T_CONSOLIDATED_IND = 3;

typedef __attribute__((ext_vector_type(2)))
                typename pallas::base_field_type::value_type pair_type;

typedef __attribute__((ext_vector_type(4)))
                typename pallas::base_field_type::value_type lookup_output_type;

typedef __attribute__((ext_vector_type(2)))
                typename pallas::base_field_type::value_type pair_type;


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

//    __builtin_assigner_exit_check(F[0] == pallas::base_field_type::value_type(0x2e55b062d92d4a6c8dc3e2db4f1e7e5f17605c7c45172c614cde1f97f69b2fc4_cppui255));
//    __builtin_assigner_exit_check(F[1] == pallas::base_field_type::value_type(0x18b0640a55f9108406cd93ee729c37150b635e94911bd0d6b99876e36dc47c6e_cppui255));
//    __builtin_assigner_exit_check(F[2] == pallas::base_field_type::value_type(0x1e713451797d9acbc945c8761b1e16d9f155a13f8ddfcab1e0322f2864d277e7_cppui255));
#ifdef __USE_LOOKUPS__
    {
        std::array<typename pallas::base_field_type::value_type, input_size_alphas> alphas = challenges.lookup_alphas;
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_selectors> lookup_gate_selectors;
$LOOKUP_GATE_SELECTORS_LIST$
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_constraints_table_ids> lookup_gate_constraints_table_ids = {$LOOKUP_CONSTRAINT_TABLE_IDS_LIST$};
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_constraints_lookup_inputs> lookup_gate_constraints_lookup_inputs = calculate_lookup_expressions(proof.z);
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_table_selectors> lookup_table_selectors;
$LOOKUP_TABLE_SELECTORS_LIST$
        std::array<typename pallas::base_field_type::value_type, input_size_shifted_lookup_table_selectors> shifted_lookup_table_selectors;
$LOOKUP_SHIFTED_TABLE_SELECTORS_LIST$
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_table_lookup_options> lookup_table_lookup_options;
$LOOKUP_OPTIONS_LIST$
        std::array<typename pallas::base_field_type::value_type, input_size_shifted_lookup_table_lookup_options> shifted_lookup_table_lookup_options;
$LOOKUP_SHIFTED_OPTIONS_LIST$

        std::array<typename pallas::base_field_type::value_type, input_size_sorted> sorted;
        for(std::size_t i = 0; i < input_size_sorted; i++){
            sorted[i] = proof.z[lookup_sorted_polys_start + i];
        }

        typename pallas::base_field_type::value_type theta = challenges.lookup_theta;
        typename pallas::base_field_type::value_type beta = challenges.lookup_beta;
        typename pallas::base_field_type::value_type gamma = challenges.lookup_gamma;
        typename pallas::base_field_type::value_type L0 = different_values[L0_IND];
        pair_type V_L_values = {
            proof.z[4*permutation_size + 6 + table_values_num + 2],     // V
            proof.z[4*permutation_size + 6 + table_values_num + 3], // V_shifted
        };
        pair_type q_last = {proof.z[4*permutation_size], proof.z[4*permutation_size + 1]};
        pair_type q_blind = {proof.z[4*permutation_size + 3], proof.z[4*permutation_size + 4]};

        lookup_output_type lookup_argument;

        std::array<pallas::base_field_type::value_type, lookup_constraints_amount> lookup_input;
        std::size_t cur = 0;
        std::size_t cur_e = 0;
        for(std::size_t g = 0; g < lookup_gate_amount; g++){
            for( std::size_t i = 0; i < lookup_constraints_amount_list[g]; i++ ){
                lookup_input[cur] = lookup_gate_selectors[g] * lookup_gate_constraints_table_ids[cur];
                pallas::base_field_type::value_type theta_acc = theta;
                for(std::size_t e = 0; e < lookup_expressions_amount_list[cur]; e++){
                    lookup_input[cur] = lookup_input[cur] + lookup_gate_selectors[g] * lookup_gate_constraints_lookup_inputs[cur_e] * theta_acc;
                    theta_acc = theta_acc * theta;
                    cur_e++;
                }
                cur++;
            }
        }

        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_value;
        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_shifted_value;
        cur = 0;
        std::size_t cur_o = 0;
        pallas::base_field_type::value_type tab_id = 1;
        for( std::size_t t = 0; t < lookup_table_amount; t++ ){
            for( std::size_t o = 0; o < lookup_options_amount_list[t]; o++ ){
                pallas::base_field_type::value_type theta_acc = theta;
                lookup_value[cur] = lookup_table_selectors[t] * tab_id;
                lookup_shifted_value[cur] = shifted_lookup_table_selectors[t] * tab_id;
                for( std::size_t c = 0; c < lookup_tables_columns_amount_list[t]; c++){
                    lookup_value[cur] = lookup_value[cur] + lookup_table_selectors[t] * lookup_table_lookup_options[cur_o] * theta_acc;
                    lookup_shifted_value[cur] = lookup_shifted_value[cur] + shifted_lookup_table_selectors[t] * shifted_lookup_table_lookup_options[cur_o] * theta_acc;
                    theta_acc = theta_acc * theta;
                    cur_o++;
                }
                lookup_value[cur] = lookup_value[cur] * (pallas::base_field_type::value_type(1) - q_last[0] - q_blind[0]);
                lookup_shifted_value[cur] = lookup_shifted_value[cur] * (pallas::base_field_type::value_type(1) - q_last[1] - q_blind[1]);
                cur++;
            }
            tab_id = tab_id + 1;
        }

        pallas::base_field_type::value_type g = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type h = pallas::base_field_type::value_type(1);

        for( std::size_t i = 0; i < lookup_constraints_amount; i++ ){
            g = g *(pallas::base_field_type::value_type(1)+beta)*(gamma + lookup_input[i]);
        }
        for( std::size_t i = 0; i < lookup_options_amount; i++ ){
            g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[i] + beta * lookup_shifted_value[i]);
        }
        for( std::size_t i = 0; i < m_parameter; i++ ){
            h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[3*i] + beta * sorted[3*i+1]);
        }

        lookup_argument[0] = (pallas::base_field_type::value_type(1) - V_L_values[0]) * L0;
        lookup_argument[1] = q_last[0]*(V_L_values[0] * V_L_values[0] - V_L_values[0]);
        lookup_argument[2] = (pallas::base_field_type::value_type(1) - q_last[0] - q_blind[0]) * (V_L_values[1] * h - V_L_values[0] * g);
        lookup_argument[3] = pallas::base_field_type::value_type(0);
        for(std::size_t i = 0; i < input_size_alphas; i++){
            lookup_argument[3] =  lookup_argument[3] + alphas[i] * (sorted[3*i + 3] - sorted[3*i + 2]);
        }
        lookup_argument[3] = lookup_argument[3] * L0;
        F[3] = lookup_argument[0];
        F[4] = lookup_argument[1];
        F[5] = lookup_argument[2];
        F[6] = lookup_argument[3];
    }
#endif

    if constexpr( gates_amount > 0) {
        std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
        std::array<pallas::base_field_type::value_type, gates_amount> selectors;
        constraints = calculate_constraints(proof.z);

        for( std::size_t i = 0; i < gates_amount; i++ ){
            selectors[i] = proof.z[4 * permutation_size + 6 + zero_indices[witness_amount + public_input_amount + constant_amount + gates_selector_indices[i]]];
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

    // Commitment scheme
    std::array<pallas::base_field_type::value_type, singles_amount> singles = fill_singles(challenges.xi, challenges.fri_etha);
    std::array<std::array<pallas::base_field_type::value_type, 4>, unique_points> V;
    std::array<std::array<pallas::base_field_type::value_type, 3>, poly_num> U;
    std::array<std::array<pallas::base_field_type::value_type, 3>, unique_points> combined_U;
    std::size_t z_ind = points_num - 1;
    pallas::base_field_type::value_type theta_acc(1);
    std::array<pallas::base_field_type::value_type, 3> tmp;

    for(std::size_t u = 0; u < unique_points; u++){
        combined_U[u][0] = pallas::base_field_type::value_type(0);
        combined_U[u][1] = pallas::base_field_type::value_type(0);
        combined_U[u][2] = pallas::base_field_type::value_type(0);
    }

$PREPARE_U_AND_V$

    std::array<std::array<typename pallas::base_field_type::value_type, 3>, D0_log> res;
    std::size_t round_proof_ind = 0;
    std::size_t initial_proof_ind = 0;
    std::size_t initial_proof_hash_ind = 0;
    pallas::base_field_type::value_type interpolant;
    std::size_t cur_val = 0;
    std::size_t round_proof_hash_ind = 0;

    for(std::size_t i = 0; i < lambda; i++){
        __builtin_assigner_fri_cosets(res.data(), D0_log, D0_omega, 256, challenges.fri_x_indices[i]);

        pallas::base_field_type::value_type hash_state;
        for(std::size_t b = 0; b < batches_num; b++){
            pallas::base_field_type::value_type hash_state(0);
            if(res[0][2] == pallas::base_field_type::value_type(0)){
                hash_state = calculate_leaf_hash(proof.initial_proof_values, cur_val, batches_amount_list[b] *2);
            } else if(res[0][2] == pallas::base_field_type::value_type(1)){
                hash_state = calculate_reversed_leaf_hash(proof.initial_proof_values, cur_val, batches_amount_list[b] *2);
            }
            cur_val += batches_amount_list[b] *2;
            for(std::size_t r = i * initial_merkle_proofs_position_num/lambda; r < (i + 1)* initial_merkle_proofs_position_num/lambda ; r++){
                if(proof.initial_proof_positions[r] == 1){
                    hash_state = __builtin_assigner_poseidon_pallas_base({0, hash_state, proof.initial_proof_hashes[initial_proof_hash_ind]})[2];
                } else{
                    hash_state = __builtin_assigner_poseidon_pallas_base({0, proof.initial_proof_hashes[initial_proof_hash_ind], hash_state})[2];
                }
                initial_proof_hash_ind ++;
            }
            if(b == 0)
                __builtin_assigner_exit_check(hash_state == vk[1]);
            else
                __builtin_assigner_exit_check(hash_state == proof.commitments[b-1]);
        }

        std::array<pallas::base_field_type::value_type, 2> y = {0,0};
		std::array<std::array<pallas::base_field_type::value_type, 2>, unique_points> V_evals;
        std::size_t ind = 0;
		pallas::base_field_type::value_type theta_acc(1);

		for(std::size_t u = 0; u < unique_points; u++){
			V_evals[u][0] = pallas::base_field_type::value_type(1) / eval4(V[u], res[0][0]);
			V_evals[u][1] = pallas::base_field_type::value_type(1) / eval4(V[u], res[0][1]);
			y[0] = y[0] - eval3(combined_U[u], res[0][0]) * V_evals[u][0];
			y[1] = y[1] - eval3(combined_U[u], res[0][1]) * V_evals[u][1];
		}

        initial_proof_ind = initial_proof_ind + poly_num * 2;
        std::size_t in = initial_proof_ind - 1;
		for(int k = poly_num; k > 0;){
            k--;
			y[0] = y[0] + theta_acc * proof.initial_proof_values[in-1] * V_evals[point_ids[k]][0];
			y[1] = y[1] + theta_acc * proof.initial_proof_values[in] * V_evals[point_ids[k]][1];
            in -= 2;
			theta_acc = theta_acc * challenges.lpc_theta;
		}

        std::size_t D = D0_log - 1;
        pallas::base_field_type::value_type rhash;
        for(std::size_t j = 0; j < fri_rounds; j++){
            if(res[j][2] == pallas::base_field_type::value_type(0)){
                rhash = __builtin_assigner_poseidon_pallas_base({0, y[0], y[1]})[2];
            } else {
                rhash = __builtin_assigner_poseidon_pallas_base({0, y[1], y[0]})[2];
            }
            for( std::size_t d = 0; d < D; d++){
                if(proof.round_merkle_proof_positions[round_proof_hash_ind] == 1){
                    rhash = __builtin_assigner_poseidon_pallas_base({0, rhash, proof.round_proof_hashes[round_proof_hash_ind]})[2];
                } else {
                    rhash = __builtin_assigner_poseidon_pallas_base({0, proof.round_proof_hashes[round_proof_hash_ind], rhash})[2];
                }
                round_proof_hash_ind++;
            }
            __builtin_assigner_exit_check(rhash == proof.fri_roots[j]);
            D--;

            interpolant = __builtin_assigner_fri_lin_inter(
                res[j][0],
                y[0],
                y[1],
                challenges.fri_alphas[j]
            );
            __builtin_assigner_exit_check(interpolant == proof.round_proof_values[round_proof_ind]);
            y[0] = proof.round_proof_values[round_proof_ind];
            y[1] = proof.round_proof_values[round_proof_ind + 1];

            pallas::base_field_type::value_type rhash;
            round_proof_ind += 2;
        }

        interpolant = pallas::base_field_type::value_type(0);
        pallas::base_field_type::value_type x = res[fri_rounds][0];
        pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y[0]);

        interpolant = pallas::base_field_type::value_type(0);
        x = res[fri_rounds][1];
        factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y[1]);
    }

    return true;
}
    )";
    }
}

#endif //__RECURSIVE_VERIFIER_TEMPLATE_HPP__