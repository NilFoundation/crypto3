//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE redshift_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

//#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/relations/non_linear_combination.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>


using namespace nil::crypto3;

template<typename FieldType> 
    std::vector<typename FieldType::value_type> prepare_domain(const std::size_t d) {
    typename FieldType::value_type omega = math::unity_root<FieldType>(math::detail::get_power_of_two(d));
    std::vector<typename FieldType::value_type> D_0(d);
    for (std::size_t power = 1; power <= d; power++) {
        D_0.emplace_back(omega.pow(power));
    }
    return D_0;
}

template<typename FieldType> 
math::polynomial::polynomial<typename FieldType::value_type> 
    lagrange_polynomial(std::vector<typename FieldType::value_type> domain, std::size_t number) {
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
        evaluation_points;
    for (std::size_t i = 0; i < domain.size(); i++) {
        evaluation_points.push_back(std::make_pair(domain[i], (i != number) ? 
            FieldType::value_type::zero() : FieldType::value_type::one()));
    }
    math::polynomial::polynomial<typename FieldType::value_type> f = 
        math::polynomial::lagrange_interpolation(evaluation_points);
    return f;
}


BOOST_AUTO_TEST_SUITE(redshift_prover_test_suite)

BOOST_AUTO_TEST_CASE(redshift_prover_basic_test) {

    using curve_type = algebra::curves::mnt4<298>;

    //zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    //zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_CASE(redshift_permutation_argument_test) {

    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    const std::size_t circuit_rows = 4;
    const std::size_t permutation_size = 2;

    std::vector<typename FieldType::value_type> domain = prepare_domain<FieldType>(circuit_rows);
    math::polynomial::polynomial<typename FieldType::value_type> lagrange_0 = lagrange_polynomial<FieldType>(domain, 0);

    //TODO: implement it in a proper way in generator.hpp
    std::vector<math::polynomial::polynomial<typename FieldType::value_type>> S_id(permutation_size);
    std::vector<math::polynomial::polynomial<typename FieldType::value_type>> S_sigma(permutation_size);

    typename FieldType::value_type omega = math::unity_root<FieldType>(
        math::detail::get_power_of_two(circuit_rows));

    typename FieldType::value_type delta = 
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

    for (std::size_t i = 0; i < permutation_size; i++) {
        std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
            interpolation_points;
        for (std::size_t j = 0; j < circuit_rows; j++) {
            interpolation_points.emplace_back(omega.pow(j), delta.pow(i) * omega.pow(j));
        }

        S_id[i] = math::polynomial::lagrange_interpolation(interpolation_points);
    }

    for (std::size_t i = 0; i < permutation_size; i++) {
        std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
            interpolation_points;
        for (std::size_t j = 0; j < circuit_rows; j++) {
            if (i == 1 && j == 1) {
                interpolation_points.emplace_back(omega.pow(j), delta.pow(2) * omega.pow(2));
            } else if (i == 2 && j == 2) {
                interpolation_points.emplace_back(omega.pow(j), delta.pow(1) * omega.pow(1));
            } else {
                interpolation_points.emplace_back(omega.pow(j), delta.pow(i) * omega.pow(j));
            }
            
        }

        S_sigma[i] = math::polynomial::lagrange_interpolation(interpolation_points);
    }

    // construct circuit values
    std::vector<math::polynomial::polynomial<typename FieldType::value_type>> f(permutation_size);
    for (std::size_t i = 0; i < permutation_size; i++) {
        std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
            interpolation_points;
        for (std::size_t j = 0; j < circuit_rows; j++) {
            if (i == 2 && j == 2) {
                interpolation_points.emplace_back(omega.pow(j), interpolation_points[1].second);
            } else {
                interpolation_points.emplace_back(omega.pow(j), algebra::random_element<FieldType>());
            }
            
        }

        f[i] = math::polynomial::lagrange_interpolation(interpolation_points);
    }

    // construct q_last, q_blind
    math::polynomial::polynomial<typename FieldType::value_type> q_last;
    math::polynomial::polynomial<typename FieldType::value_type> q_blind;
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
        interpolation_points_last;
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> 
        interpolation_points_blind;
    for (std::size_t j = 0; j < circuit_rows; j++) {
        if (j == circuit_rows - 1) {
            interpolation_points_last.emplace_back(omega.pow(j), FieldType::value_type::one());
            interpolation_points_blind.emplace_back(omega.pow(j), FieldType::value_type::zero());
        } else {
            interpolation_points_last.emplace_back(omega.pow(j), FieldType::value_type::zero());
            interpolation_points_blind.emplace_back(omega.pow(j), FieldType::value_type::zero());
        }
        
    }
    q_last = math::polynomial::lagrange_interpolation(interpolation_points_last);
    q_blind = math::polynomial::lagrange_interpolation(interpolation_points_blind);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::snark::fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> transcript(init_blob);

    std::array<math::polynomial::polynomial<typename FieldType::value_type>, 3> prove_res = 
        zk::snark::redshift_permutation_argument<FieldType>::prove_argument(
            transcript,
            circuit_rows,
            permutation_size,
            domain,
            lagrange_0,
            S_id,
            S_sigma,
            f,
            q_last,
            q_blind
        );

    //zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    //zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_CASE(redshift_lookup_argument_test) {

    using curve_type = algebra::curves::mnt4<298>;

    //zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    //zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_CASE(redshift_witness_argument_test) {

    using curve_type = algebra::curves::mnt4<298>;

    //zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    //zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_SUITE_END()