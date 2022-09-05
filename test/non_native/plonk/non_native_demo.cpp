//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_basic_verifier_test

#include <assert.h>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <chrono>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/allocate.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/variable_base_multiplication_edwards25519.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha256_process.hpp>

using namespace nil::crypto3;

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;
    params.step_list = generate_random_step_list(r, max_step);

    return params;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_demo_verifier_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_demo_verifier_test) {
    auto start = std::chrono::high_resolution_clock::now();

    constexpr std::size_t complexity = 1;

    using curve_type = algebra::curves::pallas;
    using ed25519_type = algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 17;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using mul_component_type = zk::components::variable_base_multiplication<ArithmetizationType, curve_type,
                                                                            ed25519_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    using sha256_component_type =
        zk::components::sha256_process<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(29);

    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};
    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    typename sha256_component_type::params_type sha_params = {input_state_var, input_words_var};

    std::array<var, 4> input_var_Xa = {
        var(0, 24, false, var::column_type::public_input), var(0, 25, false, var::column_type::public_input),
        var(0, 26, false, var::column_type::public_input), var(0, 27, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 28, false, var::column_type::public_input), var(0, 29, false, var::column_type::public_input),
        var(0, 30, false, var::column_type::public_input), var(0, 31, false, var::column_type::public_input)};

    var b_var = var(0, 32, false, var::column_type::public_input);

    typename mul_component_type::params_type mul_params = {{input_var_Xa, input_var_Xb}, b_var};

    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type T =
        algebra::random_element<ed25519_type::template g1_type<algebra::curves::coordinates::affine>>();
    ed25519_type::scalar_field_type::value_type b = algebra::random_element<ed25519_type::scalar_field_type>();
    ed25519_type::base_field_type::integral_type integral_b = ed25519_type::base_field_type::integral_type(b.data);
    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::array<typename ArithmetizationType::field_type::value_type, 33> public_input = {0x6a09e667,
                                                                                         0xbb67ae85,
                                                                                         0x3c6ef372,
                                                                                         0xa54ff53a,
                                                                                         0x510e527f,
                                                                                         0x9b05688c,
                                                                                         0x1f83d9ab,
                                                                                         0x5be0cd19,
                                                                                         s - 5,
                                                                                         s + 5,
                                                                                         s - 6,
                                                                                         s + 6,
                                                                                         s - 7,
                                                                                         s + 7,
                                                                                         s - 8,
                                                                                         s + 8,
                                                                                         s - 9,
                                                                                         s + 9,
                                                                                         s + 10,
                                                                                         s - 10,
                                                                                         s + 11,
                                                                                         s - 11,
                                                                                         s + 12,
                                                                                         s - 12,
                                                                                         Tx & mask,
                                                                                         (Tx >> 66) & mask,
                                                                                         (Tx >> 132) & mask,
                                                                                         (Tx >> 198) & mask,
                                                                                         Ty & mask,
                                                                                         (Ty >> 66) & mask,
                                                                                         (Ty >> 132) & mask,
                                                                                         (Ty >> 198) & mask,
                                                                                         integral_b};

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
    zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = 0;
    zk::components::allocate<sha256_component_type>(bp, 1);
    zk::components::allocate<mul_component_type>(bp, complexity);

    bp.allocate_rows(public_input.size());

    sha256_component_type::generate_circuit(bp, public_assignment, sha_params, start_row);
    sha256_component_type::generate_assignments(assignment_bp, sha_params, start_row);
    start_row += sha256_component_type::rows_amount;

    for (std::size_t i = 0; i < complexity; i++) {

        std::size_t row = start_row + i * mul_component_type::rows_amount;

        mul_component_type::generate_circuit(bp, public_assignment, mul_params, row);

        mul_component_type::generate_assignments(assignment_bp, mul_params, row);
    }

    assignment_bp.padding();
    std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
    std::cout << "Padded rows: " << desc.rows_amount << std::endl;

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    // profiling(assignments);
    using params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2, 1>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        public_preprocessed_data = zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::process(
            bp, public_assignment, desc, fri_params, permutation_size);
    typename zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        private_preprocessed_data = zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::process(
            bp, private_assignment, desc, fri_params);

    auto placeholder_proof = zk::snark::placeholder_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, params>::process(
        public_preprocessed_data, placeholder_proof, bp, fri_params);
    std::cout << "Proof check: " << verifier_res << std::endl;

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
