#define BOOST_TEST_MODULE mpc_generator_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/commitments/polynomial/powers_of_tau.hpp>
#include <nil/crypto3/zk/commitments/polynomial/r1cs_gg_ppzksnark_mpc.hpp>

#include "../systems/ppzksnark/r1cs_examples.hpp"

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::zk::commitments;

BOOST_AUTO_TEST_SUITE(mpc_generator_test_suite)

BOOST_AUTO_TEST_CASE(mpc_generator_compare_keypairs_without_delta_contribution_test) {

    using curve_type = curves::bls12<381>;
    using scalar_field_type = curve_type::scalar_field_type;
    using scalar_field_value_type = scalar_field_type::value_type;

    using g1_value_type = curve_type::g1_type<>::value_type;
    using g2_value_type = curve_type::g2_type<>::value_type;
    using powers_of_tau_scheme_type = powers_of_tau<curve_type, 32>;
    using proving_scheme_type = r1cs_gg_ppzksnark<curve_type>;
    using proving_scheme_generator_type = r1cs_gg_ppzksnark_generator<curve_type, proving_mode::basic>;

    auto acc = powers_of_tau_scheme_type::accumulator_type();
    auto sk = powers_of_tau_scheme_type::generate_private_key();
    auto pk = powers_of_tau_scheme_type::proof_eval(sk, acc);
    acc.transform(sk);

    auto r1cs_example = generate_r1cs_example_with_field_input<curve_type::scalar_field_type>(20, 3);

    std::size_t m = r1cs_example.constraint_system.num_constraints() + r1cs_example.constraint_system.num_inputs() + 1;

    auto result = powers_of_tau_scheme_type::result_type::from_accumulator(acc, m);

    auto mpc_kp =
        commitments::detail::make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(r1cs_example.constraint_system, result);
    auto g1_generator = g1_value_type::one();
    auto g2_generator = g2_value_type::one();

    auto [alpha_g1, beta_g1, beta_g2, delta_g1, delta_g2, gamma_g2, A_query, B_query, H_query, L_query, r1cs_copy,
          alpha_g1_beta_g2, gamma_ABC_g1, gamma_g1] =
        proving_scheme_generator_type::deterministic_basic_process(
            r1cs_example.constraint_system, sk.tau, sk.alpha, sk.beta, scalar_field_value_type::one(),
            scalar_field_value_type::one(), g1_generator, g2_generator);

    BOOST_CHECK(mpc_kp.first.alpha_g1 == alpha_g1);
    BOOST_CHECK(mpc_kp.first.beta_g1 == beta_g1);
    BOOST_CHECK(mpc_kp.first.beta_g2 == beta_g2);
    BOOST_CHECK(mpc_kp.first.delta_g1 == delta_g1);
    BOOST_CHECK(mpc_kp.first.delta_g2 == delta_g2);

    BOOST_CHECK_EQUAL(mpc_kp.first.A_query.size(), A_query.size());
    BOOST_CHECK_EQUAL(mpc_kp.first.B_query.domain_size(), B_query.domain_size());
    BOOST_CHECK_EQUAL(mpc_kp.first.H_query.size(), H_query.size());
    BOOST_CHECK_EQUAL(mpc_kp.first.L_query.size(), L_query.size());

    for (std::size_t i = 0; i < A_query.size(); ++i) {
        BOOST_CHECK_MESSAGE(mpc_kp.first.A_query[i] == A_query[i], std::string("i=") + std::to_string(i));
    }
    for (std::size_t i = 0; i < B_query.domain_size(); ++i) {
        BOOST_CHECK_MESSAGE(mpc_kp.first.B_query[i] == B_query[i], std::string("i=") + std::to_string(i));
    }
    for (std::size_t i = 0; i < H_query.size(); ++i) {
        BOOST_CHECK_MESSAGE(mpc_kp.first.H_query[i] == H_query[i], std::string("i=") + std::to_string(i));
    }
    for (std::size_t i = 0; i < L_query.size(); ++i) {
        BOOST_CHECK_MESSAGE(mpc_kp.first.L_query[i] == L_query[i], std::string("i=") + std::to_string(i));
    }

    BOOST_CHECK(mpc_kp.second.alpha_g1_beta_g2 == alpha_g1_beta_g2);
    BOOST_CHECK(mpc_kp.second.gamma_g2 == gamma_g2);
    BOOST_CHECK(mpc_kp.second.delta_g2 == delta_g2);

    BOOST_CHECK(mpc_kp.second.gamma_ABC_g1.first == gamma_ABC_g1.first);

    BOOST_CHECK_EQUAL(mpc_kp.second.gamma_ABC_g1.rest.domain_size(), gamma_ABC_g1.rest.domain_size());

    for (std::size_t i = 0; i < gamma_ABC_g1.rest.domain_size(); ++i) {
        BOOST_CHECK_MESSAGE(mpc_kp.second.gamma_ABC_g1.rest[i] == gamma_ABC_g1.rest[i],
                            std::string("i=") + std::to_string(i));
    }

    auto proof = proving_scheme_type::prove(mpc_kp.first, r1cs_example.primary_input, r1cs_example.auxiliary_input);
    auto verification_result = proving_scheme_type::verify(mpc_kp.second, r1cs_example.primary_input, proof);
    BOOST_CHECK(verification_result);
}

BOOST_AUTO_TEST_CASE(mpc_generator_proof_verification_without_delta_contribution_test) {

    using curve_type = curves::bls12<381>;
    using powers_of_tau_scheme_type = powers_of_tau<curve_type, 32>;
    using proving_scheme_type = r1cs_gg_ppzksnark<curve_type>;

    auto acc = powers_of_tau_scheme_type::accumulator_type();
    auto sk = powers_of_tau_scheme_type::generate_private_key();
    auto pk = powers_of_tau_scheme_type::proof_eval(sk, acc);
    acc.transform(sk);

    auto r1cs_example = generate_r1cs_example_with_field_input<curve_type::scalar_field_type>(20, 5);
    auto result = powers_of_tau_scheme_type::result_type::from_accumulator(acc, 32);

    auto mpc_kp =
        commitments::detail::make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(r1cs_example.constraint_system, result);

    auto proof = proving_scheme_type::prove(mpc_kp.first, r1cs_example.primary_input, r1cs_example.auxiliary_input);
    auto verification_result = proving_scheme_type::verify(mpc_kp.second, r1cs_example.primary_input, proof);
    BOOST_CHECK(verification_result);
}

BOOST_AUTO_TEST_CASE(mpc_generator_proof_verification_with_delta_contribution_test) {

    using curve_type = curves::bls12<381>;
    using powers_of_tau_scheme_type = powers_of_tau<curve_type, 32>;
    using proving_scheme_type = r1cs_gg_ppzksnark<curve_type>;
    using crs_mpc_type = r1cs_gg_ppzksnark_mpc<curve_type>;
    using public_key_type = crs_mpc_type::public_key_type;

    auto acc = powers_of_tau_scheme_type::accumulator_type();
    auto pot_sk = powers_of_tau_scheme_type::generate_private_key();
    auto pot_pk = powers_of_tau_scheme_type::proof_eval(pot_sk, acc);
    acc.transform(pot_sk);
    auto result = powers_of_tau_scheme_type::result_type::from_accumulator(acc, 32);

    auto r1cs_example = generate_r1cs_example_with_field_input<curve_type::scalar_field_type>(20, 5);

    auto mpc_kp =
        commitments::detail::make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(r1cs_example.constraint_system, result);

    std::vector<public_key_type> pks;

    auto mpc_sk1 = crs_mpc_type::generate_private_key();
    pks.emplace_back(crs_mpc_type::proof_eval(mpc_sk1, boost::none, mpc_kp));
    commitments::detail::transform_keypair(mpc_kp, mpc_sk1);
    BOOST_CHECK(crs_mpc_type::verify_eval(mpc_kp, pks, r1cs_example.constraint_system, result));

    auto mpc_sk2 = crs_mpc_type::generate_private_key();
    pks.emplace_back(crs_mpc_type::proof_eval(mpc_sk2, pks[0], mpc_kp));
    commitments::detail::transform_keypair(mpc_kp, mpc_sk2);
    BOOST_CHECK(crs_mpc_type::verify_eval(mpc_kp, pks, r1cs_example.constraint_system, result));

    auto proof = proving_scheme_type::prove(mpc_kp.first, r1cs_example.primary_input, r1cs_example.auxiliary_input);
    auto verification_result = proving_scheme_type::verify(mpc_kp.second, r1cs_example.primary_input, proof);
    BOOST_CHECK(verification_result);
}

BOOST_AUTO_TEST_SUITE_END()
