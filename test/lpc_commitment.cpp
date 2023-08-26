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
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>

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

template<typename FRI>
void print_params(
        typename FRI::params_type &fri_params,
        std::array<std::vector<std::vector<typename FRI::field_type::value_type>>, FRI::batches_num> evaluation_points,
        std::array<std::size_t, FRI::batches_num> batches_sizes,
        std::string filename
) {
    std::ofstream out;

    out.open(filename);
    out << "{" << std::endl;
    out << "\t\"modulus\":" << FRI::field_type::modulus << "," << std::endl;
    out << "\t\"m\":" << FRI::m << "," << std::endl;
    out << "\t\"batches_num\":" << FRI::batches_num << "," << std::endl;
    out << "\t\"lambda\":" << FRI::lambda << "," << std::endl;
    out << "\t\"r\":" << fri_params.r << "," << std::endl;
    out << "\t\"evaluation_points\":[";
    for (std::size_t i = 0; i < evaluation_points.size(); i++) {
        if (i != 0) out << ",";
        out << "[";
        for (std::size_t j = 0; j < evaluation_points[i].size(); j++) {
            if (j != 0) out << ",";
            out << "[";
            for (std::size_t k = 0; k < evaluation_points[i][j].size(); k++) {
                if (k != 0) out << ",";
                out << evaluation_points[i][j][k].data;
            }
            out << "]";
        }
        out << "]";
    }
    out << "]," << std::endl;
    out << "\t\"step_list\":[";
    for (size_t i = 0; i < fri_params.step_list.size(); i++) {
        if (i != 0) out << ",";
        out << fri_params.step_list[i];
    }
    out << "]," << std::endl;
    out << "\t\"D_omegas\":[" << std::endl;
    for (size_t i = 0; i < fri_params.D.size(); i++) {
        if (i != 0) out << "," << std::endl;
        out << "\t\t" << fri_params.D[i]->get_domain_element(1).data;
    }
    out << std::endl << "\t]," << std::endl;
    out << "\t\"batches_sizes\":[";
    for (size_t i = 0; i < FRI::batches_num; i++) {
        if (i != 0) out << ",";
        out << batches_sizes[i];
    }
    out << "\t]," << std::endl;
    out << "\t\"max_degree\":" << fri_params.max_degree << "," << std::endl;
    out << "\t\"omega\":" << fri_params.D[0]->get_domain_element(1).data << std::endl;
    out << "}" << std::endl;
    out.close();
}


/*******************************************************************************
 * Fill data structures with random data
 *******************************************************************************/
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

template<typename FieldType>
math::polynomial<typename FieldType::value_type>
generate_random_polynomial(std::size_t degree, nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    math::polynomial<typename FieldType::value_type> result(degree);
    std::generate(std::begin(result), std::end(result), [&rnd]() { return rnd(); });
    return result;
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

template<typename FRI>
typename FRI::round_proof_type generate_random_fri_round_proof(
        std::size_t r_i,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::round_proof_type res;
    res.p = generate_random_merkle_proof<FRI>(3, rnd);
    res.y = generate_random_polynomial_values<FRI>(2, alg_rnd);

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
typename FRI::query_proof_type generate_random_fri_query_proof(std::size_t max_batch_size,
                                                               std::vector<std::size_t> step_list,
                                                               nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
                                                               boost::random::mt11213b &rnd) {
    typename FRI::query_proof_type res;

    for (std::size_t k = 0; k < FRI::batches_num; k++) {
        auto batch_size = rnd() % (max_batch_size - 1) + 1;
        res.initial_proof[k] = generate_random_fri_initial_proof<FRI>(batch_size, step_list[0], alg_rnd, rnd);
    }
    res.round_proofs.resize(step_list.size());
    for (std::size_t i = 0; i < step_list.size(); i++) {
        res.round_proofs[i] = generate_random_fri_round_proof<FRI>(
                (i == step_list.size() - 1) ? step_list[i + 1] : 1,
                alg_rnd,
                rnd
        );
    }
    return res;
}

template<typename FRI>
typename FRI::proof_type generate_random_fri_proof(std::size_t d,              //final polynomial degree
                                                   std::size_t max_batch_size,
                                                   std::vector<std::size_t> step_list,
                                                   nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
                                                   boost::random::mt11213b &rnd) {
    typename FRI::proof_type res;
    for (std::size_t k = 0; k < FRI::lambda; k++) {
        res.query_proofs[k] = generate_random_fri_query_proof<FRI>(max_batch_size, step_list, alg_rnd, rnd);
    }
    res.fri_roots.resize(step_list.size());
    for (std::size_t k = 0; k < step_list.size(); k++) {
        res.fri_roots[k] = nil::crypto3::hash<typename FRI::merkle_tree_hash_type>(
                generate_random_data<std::uint8_t, 32>(1, rnd).at(0)
        );
    }
    res.final_polynomial = generate_random_polynomial<typename FRI::field_type>(d, alg_rnd);
    return res;
}

template<typename LPC>
typename LPC::proof_type generate_random_lpc_proof(std::size_t d,              //final polynomial degree
                                                   std::size_t max_batch_size,
                                                   std::vector<std::size_t> step_list,
                                                   nil::crypto3::random::algebraic_engine<typename LPC::basic_fri::field_type> &alg_rnd,
                                                   boost::random::mt11213b &rnd) {
    typename LPC::proof_type res;
    for (std::size_t i = 0; i < LPC::batches_num; i++) {
        res.z[i].resize(rnd() % (max_batch_size - 1) + 1);
        for (std::size_t j = 0; j < res.z[i].size(); j++) {
            res.z[i][j].resize(rnd() % (3) + 1);
            for (std::size_t k = 0; k < res.z[i][j].size(); k++) {
                res.z[i][j][k] = alg_rnd();
            }
        }
    }
    res.fri_proof = generate_random_fri_proof<typename LPC::basic_fri>(d, max_batch_size, step_list, alg_rnd, rnd);
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

/*******************************************************************************
 * Test marshalling function
 *******************************************************************************/
template<typename Endianness, typename LPC>
void test_lpc_proof(typename LPC::proof_type &proof, std::string filename = "") {
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_proof = nil::crypto3::marshalling::types::fill_lpc_proof<Endianness, LPC>(proof);
    auto _proof = nil::crypto3::marshalling::types::make_lpc_proof<Endianness, LPC>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());

    nil::crypto3::marshalling::types::lpc_proof<TTypeBase, LPC> test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename LPC::proof_type constructed_val_read =
            nil::crypto3::marshalling::types::make_lpc_proof<Endianness, LPC>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);

    if (filename != "") {
        print_hex_byteblob_to_file(cv.begin(), cv.end(), false, filename + ".data");
    }
}

/*******************************************************************************
 * Randomness setup
 *******************************************************************************/
using dist_type = std::uniform_int_distribution<int>;
std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_fixture {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::bls12<381>::scalar_field_type;
    using field2_type = algebra::curves::vesta::scalar_field_type;

    test_fixture() {
        test_global_seed = 0;

        for (std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc - 1; i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed: " << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);

        // Initialize algebraic engines for all fields
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
        test_global_alg_rnd_engine<field2_type> = nil::crypto3::random::algebraic_engine<field2_type>(test_global_seed);
    }

    ~test_fixture() {
    }
};

BOOST_AUTO_TEST_SUITE(marshalling_random_test_suite)
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
    using FRI = typename nil::crypto3::zk::commitments::detail::basic_batched_fri<field_type, hash_type, hash_type, lambda, m, batches_num>;
    using lpc_params_type = typename nil::crypto3::zk::commitments::list_polynomial_commitment_params<
            hash_type, hash_type, r, lambda, m, batches_num
    >;
    using LPC = typename nil::crypto3::zk::commitments::batched_list_polynomial_commitment<field_type, lpc_params_type>;

    BOOST_FIXTURE_TEST_CASE(marshalling_lpc_random_test, test_fixture) {
        auto proof = generate_random_lpc_proof<LPC>(
                final_polynomial_degree, 5,
                generate_random_step_list(r, 4, test_global_rnd_engine),
                test_global_alg_rnd_engine<typename LPC::basic_fri::field_type>,
                test_global_rnd_engine
        );
        test_lpc_proof<Endianness, LPC>(proof);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marshalling_real_lpc_proofs)
    // Setup common types.
    using Endianness = nil::marshalling::option::big_endian;
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using FieldType = curve_type::scalar_field_type;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_tree_type = typename containers::merkle_tree<merkle_hash_type, 2>;

    BOOST_FIXTURE_TEST_CASE(lpc_basic_test, test_fixture) {
        // Setup types
        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 16;
        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

        constexpr static const std::size_t m = 2;
        constexpr static const std::size_t batches_num = 4;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, batches_num> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, batches_num>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        typedef typename lpc_type::proof_type proof_type;

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, batches_num> f;
        f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
        f[1].push_back({0, 1});
        f[1].push_back({0, 1, 2});
        f[1].push_back({0, 1, 3});
        f[2].push_back({0});
        f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
        f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::array<merkle_tree_type, 4> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
        tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

        // Generate evaluation points. Generate points outside of the basic domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[2].push_back(evaluation_point);
        evaluation_points[3].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_basic_test");

        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_basic_test.json");

        std::array<typename lpc_type::commitment_type, 4> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
        commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

    BOOST_FIXTURE_TEST_CASE(lpc_basic_skipping_layers_test, test_fixture) {
        // Setup types
        typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

        constexpr static const std::size_t lambda = 2;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 2048;

        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
        constexpr static const std::size_t m = 2;
        constexpr static const std::size_t batches_num = 4;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, batches_num> fri_type;

        typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, batches_num>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        typedef typename lpc_type::proof_type proof_type;

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, batches_num> fri_type;
        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 5, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, 4> f;
        f[0] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d,
                                                           test_global_alg_rnd_engine<FieldType>);
        f[1] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d,
                                                           test_global_alg_rnd_engine<FieldType>);
        f[2] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d,
                                                           test_global_alg_rnd_engine<FieldType>);
        f[3] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d,
                                                           test_global_alg_rnd_engine<FieldType>);

        // Commit
        std::array<merkle_tree_type, 4> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
        tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

        std::array<typename lpc_type::commitment_type, 4> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
        commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

        // Generate evaluation points. Choose poin1ts outside the domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[2].push_back(evaluation_point);
        evaluation_points[3].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_skipping_layers_test");

        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_skipping_layers_test.json");

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

    BOOST_FIXTURE_TEST_CASE(lpc_batches_num_3_test, test_fixture) {
        // Setup types.
        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t k = 1;

        constexpr static const std::size_t d = 16;

        constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
        constexpr static const std::size_t m = 2;
        constexpr static const std::size_t batches_num = 3;

        typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, batches_num> fri_type;

        typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, batches_num>
                lpc_params_type;
        typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

        static_assert(zk::is_commitment<fri_type>::value);
        static_assert(zk::is_commitment<lpc_type>::value);
        static_assert(!zk::is_commitment<merkle_hash_type>::value);
        static_assert(!zk::is_commitment<merkle_tree_type>::value);
        static_assert(!zk::is_commitment<std::size_t>::value);

        typedef typename lpc_type::proof_type proof_type;

        constexpr static const std::size_t d_extended = d;
        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, 3> f;
        f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
        f[1].push_back({0, 1});
        f[1].push_back({0, 1, 2});
        f[1].push_back({0, 1, 3});
        f[2].push_back({0});

        // Commit
        std::array<merkle_tree_type, 3> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());

        // Generate evaluation points. Generate points outside of the basic domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[2].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_batches_num_3_test");
        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_batches_num_3_test.json");

        std::array<typename lpc_type::commitment_type, 3> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(lpc_eval_points)
    // Setup common types.
    using Endianness = nil::marshalling::option::big_endian;
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using FieldType = curve_type::scalar_field_type;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_tree_type = typename containers::merkle_tree<merkle_hash_type, 2>;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t batches_num = 4;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, batches_num> fri_type;

    typedef zk::commitments::
    list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, batches_num>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;

    BOOST_FIXTURE_TEST_CASE(lpc_eval_point2_test, test_fixture) {
        // Setup types and constants

        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, batches_num> f;
        f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
        f[1].push_back({0, 1});
        f[1].push_back({0, 1, 2});
        f[1].push_back({0, 1, 3});
        f[2].push_back({1, 2, 3, 4});
        f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
        f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::array<merkle_tree_type, 4> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
        tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

        // Generate evaluation points. Generate points outside of the basic domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);

        std::vector<typename FieldType::value_type> evaluation_point1;
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::vector<typename FieldType::value_type> evaluation_point2;
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator /
                                    fri_params.D[0]->get_domain_element(1));
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point1);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[2].push_back(evaluation_point);
        evaluation_points[3].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_eval_point2_test");

        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_eval_point2_test.json");

        std::array<typename lpc_type::commitment_type, 4> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
        commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

    BOOST_FIXTURE_TEST_CASE(lpc_eval_point3_test, test_fixture) {
        // Setup types and constants

        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, batches_num> f;
        f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
        f[1].push_back({0, 1});
        f[1].push_back({0, 1, 2});
        f[1].push_back({0, 1, 3});
        f[2].push_back({1, 2, 3, 4});
        f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
        f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::array<merkle_tree_type, 4> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
        tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

        // Generate evaluation points. Generate points outside of the basic domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);

        std::vector<typename FieldType::value_type> evaluation_point1;
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::vector<typename FieldType::value_type> evaluation_point2;
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator /
                                    fri_params.D[0]->get_domain_element(1));
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point2);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[2].push_back(evaluation_point);
        evaluation_points[3].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_eval_point3_test");

        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_eval_point3_test.json");

        std::array<typename lpc_type::commitment_type, 4> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
        commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

    BOOST_FIXTURE_TEST_CASE(lpc_eval_points_test, test_fixture) {
        // Setup types and constants

        std::size_t extended_log = boost::static_log2<d_extended>::value;
        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
                math::calculate_domain_set<FieldType>(extended_log, r);

        typename fri_type::params_type fri_params;

        // Setup params
        fri_params.r = r;
        fri_params.D = D;
        fri_params.max_degree = d - 1;
        fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

        // Generate polynomials
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, batches_num> f;
        f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
        f[1].push_back({0, 1});
        f[1].push_back({0, 1, 2});
        f[1].push_back({0, 1, 3});
        f[2].push_back({1, 2, 3, 4});
        f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
        f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

        // Commit
        std::array<merkle_tree_type, 4> tree;
        tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
        tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
        tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
        tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

        // Generate evaluation points. Generate points outside of the basic domain
        std::vector<typename FieldType::value_type> evaluation_point;
        evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);

        std::vector<typename FieldType::value_type> evaluation_point1;
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point1.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::vector<typename FieldType::value_type> evaluation_point2;
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator /
                                    fri_params.D[0]->get_domain_element(1));
        evaluation_point2.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator *
                                    fri_params.D[0]->get_domain_element(1));

        std::array<std::vector<std::vector<typename FieldType::value_type>>, batches_num> evaluation_points;
        evaluation_points[0].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point);
        evaluation_points[1].push_back(evaluation_point1);
        evaluation_points[1].push_back(evaluation_point2);
        evaluation_points[2].push_back(evaluation_point1);
        evaluation_points[3].push_back(evaluation_point);

        std::vector<std::uint8_t> x_data{};

        // Prove
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
        auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);
        test_lpc_proof<Endianness, lpc_type>(proof, "lpc_eval_points_test");

        std::array<std::size_t, batches_num> batch_sizes;
        for (std::size_t i = 0; i < batches_num; ++i) {
            batch_sizes[i] = f[i].size();
        }
        print_params<fri_type>(fri_params, evaluation_points, batch_sizes, "lpc_eval_points_test.json");

        std::array<typename lpc_type::commitment_type, 4> commitment;
        commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
        commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
        commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
        commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

        // Verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
                evaluation_points, proof, commitment, fri_params, transcript_verifier
        ));
    }

BOOST_AUTO_TEST_SUITE_END()