//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/profiling.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

//#include <nil//blueprint/blueprint/plonk/assignment.hpp>
//#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>

//#include <../test/test_plonk_component.hpp>
#include "./detail/circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

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
    print_hex_byteblob(out, proof_begin, proof_end, endl);
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

template<typename Endianness, typename Proof>
void test_placeholder_proof_marshalling(const Proof &proof, bool print_proof = false) {

    using namespace nil::crypto3::marshalling;

    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using proof_marshalling_type = types::placeholder_proof<TTypeBase, Proof>;

    auto filled_placeholder_proof = types::fill_placeholder_proof<Endianness, Proof>(proof);
    Proof _proof = types::make_placeholder_proof<Endianness, Proof>(filled_placeholder_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());

    if(print_proof) print_placeholder_proof(cv.cbegin(), cv.cend(), false, "placeholder_proof.txt");

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_placeholder_proof<Endianness, Proof>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 4;

    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;
    params.step_list = generate_random_step_list(r, max_step);

    return params;
}

BOOST_AUTO_TEST_SUITE(marshalling_small_test_proof)

//using curve_type = algebra::curves::bls12<381>;
using curve_type = algebra::curves::pallas;
using FieldType = typename curve_type::base_field_type;

// lpc params
constexpr static const std::size_t m = 2;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

struct placeholder_test_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

struct placeholder_test_params_lookups {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 0;
    constexpr static const std::size_t constant_columns = 3;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    placeholder_test_params::witness_columns + placeholder_test_params::public_input_columns;

typedef commitments::fri<
    FieldType, 
    placeholder_test_params::merkle_hash_type,
    placeholder_test_params::transcript_hash_type, 
    placeholder_test_params::lambda, m, 4
>  fri_type;

typedef placeholder_params<FieldType, typename placeholder_test_params::arithmetization_params> circuit_2_params;
typedef placeholder_params<FieldType, typename placeholder_test_params_lookups::arithmetization_params>
    circuit_3_params;
    
BOOST_AUTO_TEST_CASE(marshalling_placeholder_proof_circuit_2_params_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

//    typedef commitments::list_polynomial_commitment<FieldType,
//        circuit_2_params::batched_commitment_params_type> lpc_type;
    typedef commitments::lpc<FieldType, circuit_2_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data =
        placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc,
            fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_private_data =
        placeholder_private_preprocessor<FieldType, circuit_2_params>::process(constraint_system,
                                                                               assignments.private_table(), desc, fri_params);

    auto proof = placeholder_prover<FieldType, circuit_2_params>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_placeholder_proof_marshalling<Endianness, placeholder_proof<FieldType, circuit_2_params>>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_placeholder_proof_circuit_3_params_test/*, *boost::unit_test::disabled() */) {
    circuit_description<FieldType, circuit_3_params, table_rows_log, 3> circuit =
        circuit_test_3<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_3_params>;

    typedef commitments::lpc<FieldType, circuit_3_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_3_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_public_data =
        placeholder_public_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.public_table(), desc,
            fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_private_data =
        placeholder_private_preprocessor<FieldType, circuit_3_params>::process(constraint_system,
                                                                               assignments.private_table(), desc, fri_params);

    auto proof = placeholder_prover<FieldType, circuit_3_params>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    
    test_placeholder_proof_marshalling<Endianness, placeholder_proof<FieldType, circuit_3_params>>(proof);
}
BOOST_AUTO_TEST_SUITE_END()
