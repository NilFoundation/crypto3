//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_proof_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <regex>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <algorithm>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
/*
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
*/
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include "./detail/circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const std::size_t max_step) {
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

template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
}

template<typename ProofIterator>
void print_placeholder_proof(ProofIterator proof_begin, ProofIterator proof_end, bool endl, const char *name) {
    std::ofstream out;
    out.open(name);
    out << "0x";
    print_hex_byteblob(out, proof_begin, proof_end, endl);
    out.close();
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e,
                         bool endline = true) {
    os << e.data;
    if (endline) {
        os << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e,
                         bool endline = true) {
    os << e.data[0].data << ", " << e.data[1].data;
    if (endline) {
        os << std::endl;
    }
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::affine>::value>::type
print_curve_point(std::ostream &os,
                  const nil::crypto3::algebra::curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "] )" << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0>::value
        // || std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::inverted>::value
>::type
print_curve_point(std::ostream &os,
                  const nil::crypto3::algebra::curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "], Z:[";
    print_field_element(os, p.Z, false);
    os << "] )" << std::endl;
}

template<typename Endianness, typename ProofType, typename CommitmentParamsType>
void test_placeholder_proof(const ProofType &proof, const CommitmentParamsType& params, std::string output_file = "") {

    using namespace nil::crypto3::marshalling;

    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using proof_marshalling_type = nil::crypto3::marshalling::types::placeholder_proof<TTypeBase, ProofType>;

    auto filled_placeholder_proof = types::fill_placeholder_proof<Endianness, ProofType>(proof, params);
    ProofType _proof = types::make_placeholder_proof<Endianness, ProofType>(filled_placeholder_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_placeholder_proof.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    if (output_file != "") {
        print_placeholder_proof(cv.cbegin(), cv.cend(), false, output_file.c_str());
    }

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = types::make_placeholder_proof<Endianness, ProofType>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

bool has_argv(std::string name){
    bool result = false;
    for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc); i++) {
        if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--print") {
            result = true;
        }
    }
    return result;
}

template<typename Endianness, typename PlaceholderParams>
void print_placeholder_proof_with_params(
    const typename placeholder_public_preprocessor<typename PlaceholderParams::field_type, PlaceholderParams>::preprocessed_data_type &preprocessed_data,
    const placeholder_proof<typename PlaceholderParams::field_type, PlaceholderParams> &proof,
    const typename PlaceholderParams::commitment_scheme_type &commitment_scheme,
    const plonk_table_description<typename PlaceholderParams::field_type> &table_description,
    std::string folder_name
){
    std::filesystem::create_directory(folder_name);
    test_placeholder_proof<Endianness, placeholder_proof<typename PlaceholderParams::field_type, PlaceholderParams>>(
        proof, commitment_scheme.get_commitment_params(), folder_name + "/proof.bin");
    print_placeholder_params<PlaceholderParams> (
        preprocessed_data, commitment_scheme, table_description, folder_name + "/params.json", folder_name
    );
}

template<typename ColumnType>
void print_public_input(ColumnType &public_input, std::string filename){
    std::size_t max_non_zero = 0;
    for(std::size_t i = 0; i < public_input.size(); i++){
        if( public_input[i] != 0u ){
            max_non_zero = i + 1;
        }
    }
    std::ofstream pi_stream;
    pi_stream.open(filename);
    for(std::size_t i = 0; i < std::min(public_input.size(), max_non_zero); i++ ){
        pi_stream <<  public_input[i] << "\n";
    }
    pi_stream.close();
}

BOOST_AUTO_TEST_SUITE(placeholder_circuit1_poseidon)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

    using merkle_hash_type = poseidon_type;
    using transcript_hash_type = poseidon_type;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m,
        crypto3::zk::commitments::proof_of_work<transcript_hash_type, std::uint32_t>
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_1<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true, 0xFFFF8000
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, lpc_scheme
    );

    if (has_argv("--print")) {
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            lpc_preprocessed_public_data,
            lpc_proof, lpc_scheme, desc, "circuit1"
        );
    } else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(lpc_proof, fri_params);
    }
    auto verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    using merkle_hash_type = hashes::keccak_1600<256>;
    using transcript_hash_type = hashes::keccak_1600<256>;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m,
        crypto3::zk::commitments::proof_of_work<transcript_hash_type, std::uint32_t>
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_1<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, false
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, lpc_scheme
    );

    if (has_argv("--print")) {
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            lpc_preprocessed_public_data,
            lpc_proof, lpc_scheme, desc, "circuit1"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit1/public_input.inp");
    } else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(lpc_proof, fri_params);
    }
    auto verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
    );
    for(auto &it:lpc_proof.commitments ){
        std::cout << "Commitment " << it.first << " = " << it.second << std::endl;
    }
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_t;
        constexpr static const std::size_t public_input_columns = public_columns_t;
        constexpr static const std::size_t constant_columns = constant_columns_t;
        constexpr static const std::size_t selector_columns = selector_columns_t;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>){
    auto pi0 = alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    bool verifier_res;

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, lpc_scheme
    );
    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            lpc_preprocessed_public_data,
            lpc_proof, lpc_scheme, desc, "circuit2"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit2/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(lpc_proof, fri_params);
    }

    verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_3<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);
    if (has_argv("--print")) {
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit3"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit3/public_input.inp");
    } else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);

}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_4<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit4"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit4/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_5;
        constexpr static const std::size_t public_input_columns = public_columns_5;
        constexpr static const std::size_t constant_columns = constant_columns_5;
        constexpr static const std::size_t selector_columns = selector_columns_5;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test100, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_5<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 100);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit5_chunk100"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit5_chunk100/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_5<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit5_chunk10"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit5_chunk10/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_6<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme
    );
    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit6"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit6/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }
    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_7<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );
    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(circuit.table_rows);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);
    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit7"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit7/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }
    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test10, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_7<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );
    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(circuit.table_rows);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);
    if( has_argv("--print") ){
        print_placeholder_proof_with_params<Endianness, lpc_placeholder_params_type>(
            preprocessed_public_data,
            proof, lpc_scheme, desc, "circuit7_chunk10"
        );
        print_public_input(desc.public_input_columns == 0? std::vector<typename field_type::value_type>({}):assignments.public_input(0), "circuit7_chunk10/public_input.inp");
    }else {
        test_placeholder_proof<Endianness, placeholder_proof<field_type, lpc_placeholder_params_type>>(proof, fri_params);
    }
    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

template<
    typename curve_type,
    typename merkle_hash_type,
    typename transcript_hash_type,
    std::size_t WitnessColumns,
    std::size_t PublicInputColumns,
    std::size_t ConstantColumns,
    std::size_t SelectorColumns,
    std::size_t usable_rows_amount,
    bool UseGrinding = false>
struct placeholder_kzg_test_fixture_v2 : public test_tools::random_test_initializer<typename curve_type::scalar_field_type> {
    // TODO: move to common file
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = WitnessColumns;
        constexpr static const std::size_t public_input_columns = PublicInputColumns;
        constexpr static const std::size_t constant_columns = ConstantColumns;
        constexpr static const std::size_t selector_columns = SelectorColumns;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme_v2<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
        circuit_description<field_type,
        placeholder_circuit_params<field_type>,
        usable_rows_amount>;

    placeholder_kzg_test_fixture_v2()
        : desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns)
    {
    }

    bool run_test() {
        typename field_type::value_type pi0 = this->alg_random_engines.template get_alg_engine<field_type>()();
        circuit_type circuit = circuit_test_t<field_type>(
            pi0,
            this->alg_random_engines.template get_alg_engine<field_type>(),
            this->generic_random_engine
        );
        desc.rows_amount = circuit.table_rows;
        desc.usable_rows_amount = circuit.usable_rows;
        std::size_t table_rows_log = std::log2(circuit.table_rows);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        // KZG commitment scheme
        typename kzg_type::field_type::value_type alpha(7u);
        auto kzg_params = kzg_scheme_type::create_params(1 << table_rows_log, alpha);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_public_data =
            placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, kzg_scheme
            );

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                    constraint_system, assignments.private_table(), desc
                    );

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system, kzg_scheme
                );

        using common_data_type = typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type::common_data_type;
        using Endianness = nil::marshalling::option::big_endian;
//        using TTypeBase = nil::marshalling::field_type<Endianness>;
//        nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, common_data_type> filled_data;

        if( has_argv("--print") ){
            print_placeholder_proof_with_params<
                Endianness, kzg_placeholder_params_type>
                (kzg_preprocessed_public_data, kzg_proof, kzg_scheme, desc,
                 std::string("circuit_") + typeid(curve_type).name());
        } else {
            test_placeholder_proof<
                Endianness, placeholder_proof<field_type, kzg_placeholder_params_type>>
                (kzg_proof, kzg_params);
        }
        bool verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme);
        BOOST_CHECK(verifier_res);
        return true;
    }

    plonk_table_description<field_type> desc;
};


BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg_v2)

    using TestFixtures = boost::mpl::list<
    placeholder_kzg_test_fixture_v2<
    algebra::curves::bls12_381,
    hashes::keccak_1600<256>,
    hashes::keccak_1600<256>,
    witness_columns_t,
    public_columns_t,
    constant_columns_t,
    selector_columns_t,
    usable_rows_t,
    true>
    /*
       , placeholder_kzg_test_fixture<
       algebra::curves::alt_bn128_254,
       hashes::keccak_1600<256>,
       hashes::keccak_1600<256>,
       witness_columns_t,
       public_columns_t,
       constant_columns_t,
       selector_columns_t,
       usable_rows_t,
       4, true>
       */
    , placeholder_kzg_test_fixture_v2<
    algebra::curves::mnt4_298,
    hashes::keccak_1600<256>,
    hashes::keccak_1600<256>,
    witness_columns_t,
    public_columns_t,
    constant_columns_t,
    selector_columns_t,
    usable_rows_t,
    true>
    , placeholder_kzg_test_fixture_v2<
    algebra::curves::mnt6_298,
    hashes::keccak_1600<256>,
    hashes::keccak_1600<256>,
    witness_columns_t,
    public_columns_t,
    constant_columns_t,
    selector_columns_t,
    usable_rows_t,
    true>
    /*, -- Not yet implemented
      placeholder_kzg_test_fixture<
      algebra::curves::mnt6_298,
      hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
      hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
      witness_columns_t,
      public_columns_t,
      constant_columns_t,
      selector_columns_t,
      usable_rows_t,
      4,
      true>
      */
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, F, TestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}

BOOST_AUTO_TEST_SUITE_END()
