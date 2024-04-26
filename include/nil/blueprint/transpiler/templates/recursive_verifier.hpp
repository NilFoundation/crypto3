#ifndef __RECURSIVE_VERIFIER_TEMPLATE_HPP__
#define __RECURSIVE_VERIFIER_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string lookup_vars = R"(
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
$LPC_POLY_IDS_CONSTANT_ARRAYS$
        )";

        std::string lookup_expressions = R"(
std::array<pallas::base_field_type::value_type, lookup_expressions_amount> calculate_lookup_expressions(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, lookup_expressions_amount> expressions;
$LOOKUP_EXPRESSIONS_BODY$

    return expressions;
}
        )";

        std::string lookup_code = R"(
    {
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
        typename pallas::base_field_type::value_type L0 = precomputed_values.l0;
        precomputed_values.shifted_mask = pallas::base_field_type::value_type(1) - proof.z[2*permutation_size+1] - proof.z[2*permutation_size + 3];

        lookup_output_type lookup_argument;

        std::array<pallas::base_field_type::value_type, lookup_constraints_amount> lookup_input;
        pallas::base_field_type::value_type theta_acc;
$LOOKUP_INPUT_LOOP$
        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_value;
        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_shifted_value;
        pallas::base_field_type::value_type tab_id = 1;
$LOOKUP_TABLE_LOOP$

        pallas::base_field_type::value_type g = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type h = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type previous_value = proof.z[$V_L_INDEX$];
        pallas::base_field_type::value_type current_value;
        lookup_argument[2] = pallas::base_field_type::value_type(0);

$LOOKUP_CHUNKING_CODE$
        lookup_argument[0] = (pallas::base_field_type::value_type(1) - proof.z[$V_L_INDEX$]) * L0;
        lookup_argument[1] = proof.z[2*permutation_size]*(proof.z[$V_L_INDEX$] * proof.z[$V_L_INDEX$] - proof.z[$V_L_INDEX$]);
        lookup_argument[2] += (previous_value * g - proof.z[$V_L_INDEX$ + 1] * h);
        lookup_argument[2] *= -precomputed_values.mask;
        lookup_argument[3] = pallas::base_field_type::value_type(0);
        for(std::size_t i = 0; i < input_size_alphas; i++){
            lookup_argument[3] =  lookup_argument[3] + challenges.lookup_alphas[i] * (sorted[3*i + 3] - sorted[3*i + 2]);
        }
        lookup_argument[3] = lookup_argument[3] * L0;
        F[3] = lookup_argument[0];
        F[4] = lookup_argument[1];
        F[5] = lookup_argument[2];
        F[6] = lookup_argument[3];
    }
        )";

        std::string public_input_check_str = R"(
    //Check public input
    pallas::base_field_type::value_type Omega(1);
    pallas::base_field_type::value_type result(0);
    for( std::size_t j = 0; j < public_input_sizes[i]; j++){
        result += public_input[cur] * Omega / (challenges.xi - Omega);
        Omega *= omega;
        cur++;
    }
    __builtin_assigner_exit_check(rows_amount * proof.z[public_input_indices[i]] == precomputed_values.Z_at_xi * result);
)";
        std::string public_input_input_str = "\tstd::array<pallas::base_field_type::value_type, full_public_input_size> public_input,\n";

        std::string permutation_challenges_str = R"(
    // generate permutation argument challenges
    state = challenges.perm_beta = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    state = challenges.perm_gamma = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    for( std::size_t i = 0; i < $PERMUTATION_CHUNK_ALPHAS$; i++){
        challenges.perm_chunk_alphas[i] = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    }
);
)";
        std::string perm_arg_body = R"(
    // Call permutation argument
    {
        pallas::base_field_type::value_type g=1;
        pallas::base_field_type::value_type h=1;
        pallas::base_field_type::value_type tmp;
        pallas::base_field_type::value_type previous_value = proof.z[$V_P_INDEX$];
        pallas::base_field_type::value_type current_value = proof.z[$V_P_INDEX$];
$PERM_CODE$
        F[0] = precomputed_values.l0 * (1 - proof.z[$V_P_INDEX$]);
        F[1] += previous_value * g - proof.z[$V_P_INDEX$ + 1] * h;
        F[1] *= -precomputed_values.mask;
        F[2] = proof.z[2*permutation_size] * proof.z[$V_P_INDEX$] * (proof.z[$V_P_INDEX$] - 1);
    }
)";

        std::string lookup_challenges_str = R"(
// generate lookup argument challenges
    challenges.lookup_theta = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    state = challenges.perm_beta = state =  __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];
    state = challenges.perm_gamma = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    for( std::size_t i = 0; i < $LOOKUP_CHUNK_ALPHAS$; i++){
        challenges.lookup_chunk_alphas[i] = state =  __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    }
    for(std::size_t i = 0; i < sorted_columns-1; i++){
        challenges.lookup_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
    }
);
)";

        std::string recursive_verifier_template = R"(
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

namespace placeholder_verifier{

const size_t witness_amount = $WITNESS_COLUMNS_AMOUNT$;
const size_t public_input_amount = $PUBLIC_INPUT_COLUMNS_AMOUNT$;
const size_t constant_amount = $CONSTANT_COLUMNS_AMOUNT$;
const size_t selector_amount = $SELECTOR_COLUMNS_AMOUNT$;
const std::array<std::size_t, public_input_amount> public_input_sizes = {$PUBLIC_INPUT_SIZES$};
const std::size_t full_public_input_size = $FULL_PUBLIC_INPUT_SIZE$;

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
const std::array <std::size_t, public_input_amount> public_input_indices = {$PUBLIC_INPUT_INDICES$};
const size_t table_values_num = $TABLE_VALUES_NUM$;
const size_t gates_amount = $GATES_AMOUNT$;
constexpr std::array<std::size_t, gates_amount> gates_selector_indices = {$GATES_SELECTOR_INDICES$};
const size_t constraints_amount = $CONSTRAINTS_AMOUNT$;
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
const size_t singles_amount = $SINGLES_AMOUNT$;
const std::array<std::size_t, batches_num> batches_amount_list = {$BATCHES_AMOUNT_LIST$};
pallas::base_field_type::value_type vk0 = pallas::base_field_type::value_type(0x$VK0$_cppui255);
pallas::base_field_type::value_type vk1 = pallas::base_field_type::value_type(0x$VK1$_cppui255);


$LOOKUP_VARS$

struct placeholder_proof_type{
    std::array<pallas::base_field_type::value_type, commitments_num> commitments;
    pallas::base_field_type::value_type challenge;
    std::array<pallas::base_field_type::value_type, points_num> z;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_roots;
    std::array<std::array<pallas::base_field_type::value_type, initial_proof_points_num>, lambda> initial_proof_values;
    std::array<std::array<pallas::base_field_type::value_type, round_proof_points_num>, lambda> round_proof_values;                                // lambda times
    std::array<std::array<int, initial_merkle_proofs_position_num>, lambda> initial_proof_positions;
    std::array<std::array<pallas::base_field_type::value_type, initial_merkle_proofs_hash_num>, lambda> initial_proof_hashes;
    std::array<std::array<int, round_merkle_proofs_position_num>, lambda> round_merkle_proof_positions;                                            // lambda times
    std::array<std::array<pallas::base_field_type::value_type, round_merkle_proofs_hash_num>, lambda> round_proof_hashes;                          // lambda times
    std::array<pallas::base_field_type::value_type, final_polynomial_size> final_polynomial;
};

struct placeholder_challenges_type {
    pallas::base_field_type::value_type eta;

    pallas::base_field_type::value_type perm_beta;
    pallas::base_field_type::value_type perm_gamma;
    std::array<pallas::base_field_type::value_type, $PERMUTATION_CHUNK_ALPHAS$> perm_chunk_alphas;

    pallas::base_field_type::value_type lookup_theta;
    pallas::base_field_type::value_type lookup_gamma;
    pallas::base_field_type::value_type lookup_beta;
    std::array<pallas::base_field_type::value_type, $LOOKUP_CHUNK_ALPHAS$> lookup_chunk_alphas;

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
    if(tr_state.cur == 3){
        tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0],tr_state.state[1],tr_state.state[2]})[2];
        tr_state.state[1] = pallas::base_field_type::value_type(0);
        tr_state.state[2] = pallas::base_field_type::value_type(0);
        tr_state.cur = 1;
    }
	tr_state.state[tr_state.cur] = value;
	tr_state.cur++;
}

pallas::base_field_type::value_type transcript_challenge(transcript_state_type &tr_state) {
    tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0], tr_state.state[1], tr_state.state[2]})[2];
    tr_state.state[1] = pallas::base_field_type::value_type(0);
    tr_state.state[2] = pallas::base_field_type::value_type(0);
    tr_state.cur = 1;
    return tr_state.state[0];
}

pallas::base_field_type::value_type pow_rows_amount(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 0; i < rows_log; i++){
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

template<std::size_t p>
pallas::base_field_type::value_type pow(pallas::base_field_type::value_type x){
    if constexpr( p == 0 ) return pallas::base_field_type::value_type(1);
    if constexpr( p == 1 ) return x;
    pallas::base_field_type::value_type result = pow<p/2>(x);
    result = result * result;
    if constexpr( p%2 == 1 ) result = result * x;
    return result;
}

std::array<pallas::base_field_type::value_type, singles_amount> fill_singles(
    pallas::base_field_type::value_type xi,
    pallas::base_field_type::value_type eta
){
    std::array<pallas::base_field_type::value_type, singles_amount> singles;
$SINGLES_COMPUTATION$;
    return singles;
}

placeholder_challenges_type generate_challenges(
    const placeholder_proof_type &proof
){
    placeholder_challenges_type challenges;
    pallas::base_field_type::value_type state;
$PLACEHOLDER_CHALLENGES_STR$
    return challenges;
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type> xi_polys(
    pallas::base_field_type::value_type xi
){
    pallas::base_field_type::value_type xi_n = pow_rows_amount(xi) - pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type l0 = (xi - pallas::base_field_type::value_type(1))*pallas::base_field_type::value_type(rows_amount);
    l0 = xi_n / l0;
    return std::make_pair(l0, xi_n);
}

std::array<pallas::base_field_type::value_type, constraints_amount> calculate_constraints(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
$CONSTRAINTS_BODY$

    return constraints;
}

$LOOKUP_EXPRESSIONS$

template<std::size_t start_index, std::size_t leaf_size>
pallas::base_field_type::value_type calculate_leaf_hash(
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> val
){
    pallas::base_field_type::value_type hash_state = pallas::base_field_type::value_type(0);
    for(std::size_t pos = 0; pos < leaf_size*2; pos+=2){
        hash_state = __builtin_assigner_poseidon_pallas_base(
            {hash_state, val[start_index + pos], val[start_index + pos+1]}
        )[2];
    }
    return hash_state;
}

struct precomputed_values_type{
    pallas::base_field_type::value_type l0;
    pallas::base_field_type::value_type Z_at_xi;
    pallas::base_field_type::value_type F_consolidated;
    pallas::base_field_type::value_type T_consolidated;
    pallas::base_field_type::value_type mask;
    pallas::base_field_type::value_type shifted_mask;
};

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
    $PUBLIC_INPUT_INPUT$
    placeholder_proof_type proof
) {
   placeholder_challenges_type challenges = generate_challenges(proof);
   __builtin_assigner_exit_check_eq_pallas(challenges.xi, proof.challenge);

    precomputed_values_type precomputed_values;
    std::tie(precomputed_values.l0, precomputed_values.Z_at_xi) = xi_polys(challenges.xi);
    precomputed_values.mask = (pallas::base_field_type::value_type(1) - proof.z[2*permutation_size] - proof.z[2*permutation_size + 2]);

    // For loop in for loop removed
$PUBLIC_INPUT_CHECK$

    std::array<pallas::base_field_type::value_type, 8> F;
    F[0] = pallas::base_field_type::value_type(0);
    F[1] = pallas::base_field_type::value_type(0);
    F[2] = pallas::base_field_type::value_type(0);
    F[3] = pallas::base_field_type::value_type(0);
    F[4] = pallas::base_field_type::value_type(0);
    F[5] = pallas::base_field_type::value_type(0);
    F[6] = pallas::base_field_type::value_type(0);
    F[7] = pallas::base_field_type::value_type(0);

$PERM_BODY$
$LOOKUP_CODE$
    if constexpr( gates_amount > 0) {
        std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
        std::array<pallas::base_field_type::value_type, gates_amount> selectors;
        constraints = calculate_constraints(proof.z);

$GATE_ARG_PREPARE$
        F[7] *= precomputed_values.mask;
    }

    precomputed_values.F_consolidated = pallas::base_field_type::value_type(0);
    for(std::size_t i = 0; i < 8; i++){
        F[i] *= challenges.alphas[i];
        precomputed_values.F_consolidated += F[i];
    }

    precomputed_values.T_consolidated = pallas::base_field_type::value_type(0);
    pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
    for(std::size_t i = 0; i < quotient_polys_amount; i++){
        precomputed_values.T_consolidated += proof.z[quotient_polys_start + i] * factor;
        factor *= (precomputed_values.Z_at_xi + pallas::base_field_type::value_type(1));
    }
    __builtin_assigner_exit_check(precomputed_values.F_consolidated == precomputed_values.T_consolidated * precomputed_values.Z_at_xi);

    // Commitment scheme
    std::array<pallas::base_field_type::value_type, singles_amount> singles = fill_singles(challenges.xi, challenges.eta);
    std::array<pallas::base_field_type::value_type, unique_points+1> U;

$PREPARE_U_AND_V$


    std::array<std::array<typename pallas::base_field_type::value_type, 3>, D0_log> res;
    std::size_t round_proof_ind = 0;
    std::size_t initial_proof_ind = 0;
    std::size_t initial_proof_hash_ind = 0;
    pallas::base_field_type::value_type interpolant;
    std::size_t cur_val = 0;
    std::size_t round_proof_hash_ind = 0;

    for(std::size_t i = 0; i < lambda; i++){
        cur_val = 0;
        pallas::base_field_type::value_type x(1);
        pallas::base_field_type::value_type x_challenge = challenges.fri_x_indices[i];
        pallas::base_field_type::value_type x_2(1);
$X_CHALLENGE_POW$
        __builtin_assigner_exit_check(x == x_2 || x == -x_2);

        pallas::base_field_type::value_type hash_state;
        pallas::base_field_type::value_type pos;
        pallas::base_field_type::value_type npos;
$INITIAL_PROOF_CHECK$
        pallas::base_field_type::value_type y0;
        pallas::base_field_type::value_type y1;
        y0 = pallas::base_field_type::value_type(0);
        y1 = pallas::base_field_type::value_type(0);
        theta_acc = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type Q0;
        pallas::base_field_type::value_type Q1;

$LPC_Y_COMPUTATION$

        std::size_t D = D0_log - 1;
        pallas::base_field_type::value_type rhash;

$ROUND_PROOF_CHECK$

        interpolant = pallas::base_field_type::value_type(0);
        pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y0);

        x = -x;
        interpolant = pallas::base_field_type::value_type(0);
        factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y1);
	}
    return true;
}

}
    )";
    }
}

#endif //__RECURSIVE_VERIFIER_TEMPLATE_HPP__