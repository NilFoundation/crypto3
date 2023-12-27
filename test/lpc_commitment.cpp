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

#define BOOST_TEST_MODULE crypto3_marshalling_lpc_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>

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
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

using namespace nil::crypto3;

/*******************************************************************************
 * Printing functions
 *******************************************************************************/
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
void print_hex_byteblob_to_file(ProofIterator proof_begin, ProofIterator proof_end, bool endl, std::string name) {
    std::ofstream out;
    out.open(name);
    print_hex_byteblob(out, proof_begin, proof_end, endl);
}

//*******************************************************************************
//* Fill data structures with random data
//*******************************************************************************
template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
generate_random_data(std::size_t leaf_number, boost::random::mt11213b &rnd) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return rnd() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}
 
std::vector<std::vector<std::uint8_t>>
generate_random_data_for_merkle_tree(size_t leafs_number, size_t leaf_bytes, boost::random::mt11213b &rnd) {
    std::vector<std::vector<std::uint8_t>> rdata(leafs_number, std::vector<std::uint8_t>(leaf_bytes));

    for (std::size_t i = 0; i < leafs_number; ++i) {
        std::vector<uint8_t> leaf(leaf_bytes);
        for (size_t i = 0; i < leaf_bytes; i++) {
            leaf[i] = rnd() % (std::numeric_limits<std::uint8_t>::max() + 1);
        }
        rdata.emplace_back(leaf);
    }
    return rdata;
}

template<typename FRI>
typename FRI::merkle_proof_type generate_random_merkle_proof(std::size_t tree_depth, boost::random::mt11213b &rnd) {
    std::size_t leafs_number = 1 << tree_depth;
    std::size_t leaf_size = 32;

    auto rdata1 = generate_random_data_for_merkle_tree(leafs_number, leaf_size, rnd);
    auto tree1 = containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(rdata1.begin(),
                                                                                           rdata1.end());
    std::size_t idx1 = rnd() % leafs_number;
    typename FRI::merkle_proof_type mp1(tree1, idx1);
    return mp1;
}

inline std::vector<std::size_t>
generate_random_step_list(const std::size_t r, const int max_step, boost::random::mt11213b &rnd) {
    using dist_type = std::uniform_int_distribution<int>;

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
            step_list.emplace_back(dist_type(1, max_step)(rnd));
            steps_sum += step_list.back();
        }
    }

    return step_list;
}

template<typename FRI>
typename FRI::polynomial_values_type generate_random_polynomial_values(
        size_t step,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd
) {
    typename FRI::polynomial_values_type values;

    std::size_t coset_size = 1 << (step - 1);
    values.resize(coset_size);
    for (size_t i = 0; i < coset_size; i++) {
        for (size_t j = 0; j < FRI::m; j++) {
            values[i][j] = alg_rnd();
            values[i][j] = alg_rnd();
        }
    }
    return values;
}
 
template<typename FieldType>
math::polynomial<typename FieldType::value_type> generate_random_polynomial(
        size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &d
) {
    math::polynomial<typename FieldType::value_type> poly;
    poly.resize(degree);

    for (std::size_t i = 0; i < degree; ++i) {
        poly[i] = d();
    }
    return poly;
}

template<typename FRI>
typename FRI::round_proof_type generate_random_fri_round_proof(
        std::size_t r_i,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::round_proof_type res;
    res.p = generate_random_merkle_proof<FRI>(3, rnd);
    res.y = generate_random_polynomial_values<FRI>(r_i, alg_rnd);

    return res;
}

template<typename FRI>
typename FRI::initial_proof_type generate_random_fri_initial_proof(
        std::size_t polynomial_number,
        std::size_t r0,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::initial_proof_type res;

    std::size_t coset_size = 1 << r0;
    res.p = generate_random_merkle_proof<FRI>(3, rnd);
    res.values.resize(polynomial_number);
    for (std::size_t i = 0; i < polynomial_number; i++) {
        res.values[i].resize(coset_size / FRI::m);
        for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
            res.values[i][j][0] = alg_rnd();
            res.values[i][j][1] = alg_rnd();
        }
    }

    return res;
}

template<typename FRI>
typename FRI::query_proof_type generate_random_fri_query_proof(
        std::size_t max_batch_size,
        std::vector<std::size_t> step_list,
        nil::crypto3::marshalling::types::batch_info_type batch_info,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::query_proof_type res;

    for (const auto &it : batch_info) {
        res.initial_proof[it.first] = generate_random_fri_initial_proof<FRI>(it.second, step_list[0], alg_rnd, rnd);
    }
    res.round_proofs.resize(step_list.size());
    for (std::size_t i = 1; i < step_list.size(); i++) {
        res.round_proofs[i-1] = generate_random_fri_round_proof<FRI>(
            step_list[i], alg_rnd,  rnd
        );
    }
    res.round_proofs[step_list.size()-1] = generate_random_fri_round_proof<FRI>(
        1, alg_rnd,  rnd
    );
    return res;
}

template<typename FRI>
typename FRI::proof_type generate_random_fri_proof(
    std::size_t d,              //final polynomial degree
    std::size_t max_batch_size,
    std::vector<std::size_t> step_list,
    nil::crypto3::marshalling::types::batch_info_type batch_info,
    nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
    boost::random::mt11213b &rnd
) {
    typename FRI::proof_type res;
    for (std::size_t k = 0; k < FRI::lambda; k++) {
        res.query_proofs[k] = generate_random_fri_query_proof<FRI>(max_batch_size, step_list, batch_info, alg_rnd, rnd);
    }
    res.fri_roots.resize(step_list.size());
    for (std::size_t k = 0; k < step_list.size(); k++) {
        res.fri_roots[k] = nil::crypto3::hash<typename FRI::merkle_tree_hash_type>(
                generate_random_data<std::uint8_t, 32>(1, rnd).at(0)
        );
    }
    if constexpr(FRI::use_grinding){
        res.proof_of_work = rnd();
    }
    res.final_polynomial = generate_random_polynomial<typename FRI::field_type>(d, alg_rnd);
    return res;
}

template<typename LPC>
typename LPC::proof_type generate_random_lpc_proof(
    std::size_t d,              //final polynomial degree
    std::size_t max_batch_size,
    std::vector<std::size_t> step_list,
    nil::crypto3::random::algebraic_engine<typename LPC::basic_fri::field_type> &alg_rnd,
    boost::random::mt11213b &rnd
) { 
    typename LPC::proof_type res;

    nil::crypto3::marshalling::types::batch_info_type batch_info;
    for( std::size_t i = 0; i < 6; i++ ){
        batch_info[rnd()%6] = rnd()%9 + 1;
    }
    for( const auto&it: batch_info){
        res.z.set_batch_size(it.first, it.second);
        for( std::size_t i = 0; i < it.second; i++){
            res.z.set_poly_points_number(it.first, i, rnd()%3 + 1);
            for( std::size_t j = 0; j < res.z.get_poly_points_number(it.first, i); j++){
                res.z.set(it.first, i, j, alg_rnd());
            }
        }
    }
    res.fri_proof = generate_random_fri_proof<typename LPC::basic_fri>(d, max_batch_size, step_list, batch_info, alg_rnd, rnd);
    return res;
}


template<typename FieldType>
math::polynomial_dfs<typename FieldType::value_type>
generate_random_polynomial_dfs(std::size_t degree, nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    math::polynomial<typename FieldType::value_type> data = generate_random_polynomial<FieldType>(degree, rnd);
    math::polynomial_dfs<typename FieldType::value_type> result;
    result.from_coefficients(data);
    return result;
}

template<typename FieldType>
std::vector<math::polynomial<typename FieldType::value_type>> generate_random_polynomial_batch(
        std::size_t batch_size,
        std::size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &rnd
) {
    std::vector<math::polynomial<typename FieldType::value_type>> result;

    for (uint i = 0; i < batch_size; i++) {
        result.push_back(generate_random_polynomial<FieldType>(degree, rnd));
    }
    return result;
}

template<typename FieldType>
std::vector<math::polynomial_dfs<typename FieldType::value_type>>
generate_random_polynomial_dfs_batch(std::size_t batch_size,
                                     std::size_t degree,
                                     nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    auto data = generate_random_polynomial_batch(batch_size, degree, rnd);
    std::vector<math::polynomial_dfs<typename FieldType::value_type>> result;

    for (uint i = 0; i < data.size(); i++) {
        math::polynomial_dfs<typename FieldType::value_type> dfs;
        dfs.from_coefficients(data[i]);
        result.push_back(dfs);
    }
    return result;
}

// *******************************************************************************
// * Test marshalling function
// ******************************************************************************* /



template<typename Endianness, typename LPC>
void test_lpc_proof(typename LPC::proof_type &proof, typename LPC::fri_type::params_type fri_params, std::string filename = "") {
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_proof = nil::crypto3::marshalling::types::fill_eval_proof<Endianness, LPC>(proof, fri_params);
    auto _proof = nil::crypto3::marshalling::types::make_eval_proof<Endianness, LPC>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());

    typename nil::crypto3::marshalling::types::eval_proof<TTypeBase, LPC>::type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename LPC::proof_type constructed_val_read =
            nil::crypto3::marshalling::types::make_eval_proof<Endianness, LPC>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);

    if (filename != "") {
        print_hex_byteblob_to_file(cv.begin(), cv.end(), false, filename + ".data");
    }
}

// *******************************************************************************
// * Randomness setup
// *******************************************************************************/
using dist_type = std::uniform_int_distribution<int>;
std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_initializer {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::bls12<381>::scalar_field_type;

    test_initializer() {
        test_global_seed = 0;

        for (std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc - 1; i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed = " << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }

    void setup() {
    }

    void teardown() {
    }

    ~test_initializer() {
    }
};

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(
        std::size_t degree_log, const int max_step = 1, std::size_t expand_factor = 4) {
    std::size_t r = degree_log - 1;

    return typename fri_type::params_type(
        (1 << degree_log) - 1, // max_degree
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r),
        generate_random_step_list(r, max_step, test_global_rnd_engine),
        expand_factor
    );
}

BOOST_AUTO_TEST_SUITE(marshalling_random)
    // setup
    static constexpr std::size_t lambda = 40;
    static constexpr std::size_t m = 2;
    static constexpr std::size_t batches_num = 5;

    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t final_polynomial_degree = 1; // final polynomial degree
    constexpr static const std::size_t r = boost::static_log2<(d - final_polynomial_degree)>::value;

    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using value_type = typename field_type::value_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using FRI = typename nil::crypto3::zk::commitments::detail::basic_batched_fri<field_type, hash_type, hash_type, lambda, m>;
    using lpc_params_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment_params<
            hash_type, hash_type, lambda, m
    >;
    using LPC = typename nil::crypto3::zk::commitments::batched_list_polynomial_commitment<field_type, lpc_params_type>;

BOOST_FIXTURE_TEST_CASE(lpc_proof_test, test_initializer) {

    typename FRI::params_type fri_params = create_fri_params<FRI, field_type>(r + 1, 4);

    auto proof = generate_random_lpc_proof<LPC>(
            final_polynomial_degree, 5,
            fri_params.step_list,
            test_global_alg_rnd_engine<typename LPC::basic_fri::field_type>,
            test_global_rnd_engine
    );
    test_lpc_proof<Endianness, LPC>(proof, fri_params);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marshalling_real)
    // Setup common types.
    using Endianness = nil::marshalling::option::big_endian;
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = curve_type::scalar_field_type;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_tree_type = typename containers::merkle_tree<merkle_hash_type, 2>;

BOOST_FIXTURE_TEST_CASE(batches_num_3_test, test_initializer){
    // Setup types.
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, lambda, m> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, m>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<field_type, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<field_type>>> D =
        math::calculate_domain_set<field_type>(extended_log, r);

    // Setup params
    typename fri_type::params_type fri_params(
        d - 1, // max_degree
        D,
        generate_random_step_list(r, 1, test_global_rnd_engine),
        2 //expand_factor
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, math::polynomial<typename field_type::value_type>>;
    lpc_scheme_type lpc_scheme_prover(fri_params);
    lpc_scheme_type lpc_scheme_verifier(fri_params);

    // Generate polynomials
    lpc_scheme_prover.append_to_batch(0, {1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
    lpc_scheme_prover.append_to_batch(2, {0, 1});
    lpc_scheme_prover.append_to_batch(2, {0, 1, 2});
    lpc_scheme_prover.append_to_batch(2, {0, 1, 3});
    lpc_scheme_prover.append_to_batch(3, {0});

    // Commit
    std::map<std::size_t, typename lpc_type::commitment_type> commitments;
    commitments[0] = lpc_scheme_prover.commit(0);
    commitments[2] = lpc_scheme_prover.commit(2);
    commitments[3] = lpc_scheme_prover.commit(3);

    // Generate evaluation points. Generate points outside of the basic domain
    // Generate evaluation points. Choose poin1ts outside the domain
    auto point = algebra::fields::arithmetic_params<field_type>::multiplicative_generator;
    lpc_scheme_prover.append_eval_point(0, point);
    lpc_scheme_prover.append_eval_point(2, point);
    lpc_scheme_prover.append_eval_point(3, point);
    
    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = lpc_scheme_prover.proof_eval(transcript);

    test_lpc_proof<Endianness, lpc_type>(proof, fri_params);

    // Verify
/*  zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));
    lpc_scheme_verifier.set_batch_size(2, proof.z.get_batch_size(2));
    lpc_scheme_verifier.set_batch_size(3, proof.z.get_batch_size(3));

    lpc_scheme_verifier.append_eval_point(0, point);
    lpc_scheme_verifier.append_eval_point(2, point);
    lpc_scheme_verifier.append_eval_point(3, point);
    BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));

    // Check transcript state    
    typename field_type::value_type verifier_next_challenge = transcript_verifier.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);*/
}
BOOST_AUTO_TEST_SUITE_END()
