#define BOOST_TEST_MODULE powers_of_tau_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/zk/commitments/polynomial/powers_of_tau.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::commitments;

BOOST_AUTO_TEST_SUITE(powers_of_tau_test_suite)

BOOST_AUTO_TEST_CASE(powers_of_tau_result_basic_test) {
    using curve_type = curves::bls12<381>;
    using g1_value_type = curve_type::g1_type<>::value_type;
    using g2_value_type = curve_type::g2_type<>::value_type;
    using scalar_field_type = curve_type::scalar_field_type;

    constexpr const unsigned tau_powers = 1 << 5;

    using scheme_type = powers_of_tau<curve_type, tau_powers>;

    auto acc1 = scheme_type::accumulator_type();
    auto acc2 = acc1;
    auto sk = scheme_type::generate_private_key();
    auto pk = scheme_type::proof_eval(sk, acc1);
    acc2.transform(sk);

    BOOST_CHECK(scheme_type::verify_eval(pk, acc1, acc2));
    auto result = scheme_type::result_type::from_accumulator(acc2, tau_powers);

    auto g1_generator = g1_value_type::one();
    auto g2_generator = g2_value_type::one();

    BOOST_CHECK(result.alpha_g1 == g1_generator * sk.alpha);
    BOOST_CHECK(result.beta_g1 == g1_generator * sk.beta);
    BOOST_CHECK(result.beta_g2 == g2_generator * sk.beta);

    BOOST_CHECK_EQUAL(result.coeffs_g1.size(), tau_powers);
    BOOST_CHECK_EQUAL(result.coeffs_g2.size(), tau_powers);
    BOOST_CHECK_EQUAL(result.alpha_coeffs_g1.size(), tau_powers);
    BOOST_CHECK_EQUAL(result.beta_coeffs_g1.size(), tau_powers);

    auto domain = nil::crypto3::math::make_evaluation_domain<scalar_field_type>(tau_powers);
    auto u = domain->evaluate_all_lagrange_polynomials(sk.tau);

    for (std::size_t i = 0; i < domain->m; ++i) {
        BOOST_CHECK_MESSAGE(result.coeffs_g1[i] == g1_generator * u[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.coeffs_g2[i] == g2_generator * u[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.alpha_coeffs_g1[i] == g1_generator * (sk.alpha * u[i]),
                            std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.beta_coeffs_g1[i] == g1_generator * (sk.beta * u[i]),
                            std::string("i=") + std::to_string(i));
    }

    BOOST_CHECK_EQUAL(result.h.size(), domain->m - 1);
    auto Zt = domain->compute_vanishing_polynomial(sk.tau);
    for (std::size_t i = 0; i < domain->m - 1; ++i) {
        BOOST_CHECK_MESSAGE(result.h[i] == g1_generator * (sk.tau.pow(i) * Zt), std::string("i=") + std::to_string(i));
    }

    auto result_16 = scheme_type::result_type::from_accumulator(acc2, 16);
    auto domain_16 = nil::crypto3::math::make_evaluation_domain<scalar_field_type>(16);
    auto u_16 = domain_16->evaluate_all_lagrange_polynomials(sk.tau);

    BOOST_CHECK_EQUAL(u_16.size(), 16);

    BOOST_CHECK(result_16.alpha_g1 == g1_generator * sk.alpha);
    BOOST_CHECK(result_16.beta_g1 == g1_generator * sk.beta);
    BOOST_CHECK(result_16.beta_g2 == g2_generator * sk.beta);

    BOOST_CHECK_EQUAL(result_16.coeffs_g1.size(), 16);
    BOOST_CHECK_EQUAL(result_16.coeffs_g2.size(), 16);
    BOOST_CHECK_EQUAL(result_16.alpha_coeffs_g1.size(), 16);
    BOOST_CHECK_EQUAL(result_16.beta_coeffs_g1.size(), 16);

    for (std::size_t i = 0; i < domain_16->m; ++i) {
        BOOST_CHECK_MESSAGE(result_16.coeffs_g1[i] == g1_generator * u_16[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.coeffs_g2[i] == g2_generator * u_16[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.alpha_coeffs_g1[i] == g1_generator * (sk.alpha * u_16[i]),
                            std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.beta_coeffs_g1[i] == g1_generator * (sk.beta * u_16[i]),
                            std::string("i=") + std::to_string(i));
    }

    BOOST_CHECK_EQUAL(result_16.h.size(), domain_16->m - 1);
    auto Zt_16 = domain_16->compute_vanishing_polynomial(sk.tau);
    for (std::size_t i = 0; i < domain_16->m - 1; ++i) {
        BOOST_CHECK_MESSAGE(result_16.h[i] == g1_generator * (sk.tau.pow(i) * Zt_16),
                            std::string("i=") + std::to_string(i));
    }

    auto result_24 = scheme_type::result_type::from_accumulator(acc2, 24);
    auto domain_24 = nil::crypto3::math::make_evaluation_domain<scalar_field_type>(24);
    auto u_24 = domain_24->evaluate_all_lagrange_polynomials(sk.tau);

    BOOST_CHECK_EQUAL(u_24.size(), 24);

    BOOST_CHECK(result_24.alpha_g1 == g1_generator * sk.alpha);
    BOOST_CHECK(result_24.beta_g1 == g1_generator * sk.beta);
    BOOST_CHECK(result_24.beta_g2 == g2_generator * sk.beta);

    BOOST_CHECK_EQUAL(result_24.coeffs_g1.size(), 24);
    BOOST_CHECK_EQUAL(result_24.coeffs_g2.size(), 24);
    BOOST_CHECK_EQUAL(result_24.alpha_coeffs_g1.size(), 24);
    BOOST_CHECK_EQUAL(result_24.beta_coeffs_g1.size(), 24);

    for (std::size_t i = 0; i < domain_24->m; ++i) {
        BOOST_CHECK_MESSAGE(result_24.coeffs_g1[i] == g1_generator * u_24[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_24.coeffs_g2[i] == g2_generator * u_24[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_24.alpha_coeffs_g1[i] == g1_generator * (sk.alpha * u_24[i]),
                            std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_24.beta_coeffs_g1[i] == g1_generator * (sk.beta * u_24[i]),
                            std::string("i=") + std::to_string(i));
    }

    BOOST_CHECK_EQUAL(result_24.h.size(), domain_24->m - 1);
    auto Zt_24 = domain_24->compute_vanishing_polynomial(sk.tau);
    for (std::size_t i = 0; i < domain_24->m - 1; ++i) {
        BOOST_CHECK_MESSAGE(result_24.h[i] == g1_generator * (sk.tau.pow(i) * Zt_24),
                            std::string("i=") + std::to_string(i));
    }
}

BOOST_AUTO_TEST_CASE(powers_of_tau_basic_test) {
    using curve_type = curves::bls12<381>;
    using scheme_type = powers_of_tau<curve_type, 32>;
    auto acc1 = scheme_type::accumulator_type();
    auto acc2 = acc1;
    auto sk = scheme_type::generate_private_key();
    auto pubkey = scheme_type::proof_eval(sk, acc2);
    acc2.transform(sk);

    BOOST_CHECK(acc1.tau_powers_g1[0] == acc2.tau_powers_g1[0]);
    BOOST_CHECK(scheme_type::verify_eval(pubkey, acc1, acc2));
    auto acc3 = acc2;
    std::vector<std::uint8_t> beacon {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    auto rng = scheme_type::rng_from_beacon(beacon);
    auto beacon_sk = scheme_type::generate_private_key(rng);
    auto beacon_pubkey = scheme_type::proof_eval(beacon_sk, acc2, rng);
    acc3.transform(beacon_sk);
    BOOST_CHECK(scheme_type::verify_eval(beacon_pubkey, acc2, acc3));

    // Check reproducibility
    auto rng_reproduced = scheme_type::rng_from_beacon(beacon);
    auto beacon_sk_reproduced = scheme_type::generate_private_key(rng_reproduced);
    BOOST_CHECK(beacon_sk.tau == beacon_sk_reproduced.tau);
    BOOST_CHECK(beacon_sk.alpha == beacon_sk_reproduced.alpha);
    BOOST_CHECK(beacon_sk.beta == beacon_sk_reproduced.beta);
    auto beacon_pubkey_reproduced = scheme_type::proof_eval(beacon_sk_reproduced, acc2, rng_reproduced);
    BOOST_CHECK(scheme_type::verify_eval(beacon_pubkey_reproduced, acc2, acc3));

    auto result = scheme_type::result_type::from_accumulator(acc3, 32);
}

BOOST_AUTO_TEST_CASE(keypair_generation_basic_test) {
    using curve_type = curves::bls12<381>;
    using scheme_type = powers_of_tau<curve_type, 32>;
    auto sk = scheme_type::generate_private_key();
    auto acc = scheme_type::accumulator_type();

    std::vector<std::uint8_t> transcript = scheme_type::compute_transcript(acc);

    auto pubkey = scheme_type::proof_eval(sk, acc);
    auto tau_gs2 = scheme_type::proof_of_knowledge_scheme_type::compute_g2_s(pubkey.tau_pok.g1_s, pubkey.tau_pok.g1_s_x,
                                                                             transcript, 0);
    BOOST_CHECK(scheme_type::proof_of_knowledge_scheme_type::verify_eval(pubkey.tau_pok, tau_gs2));
    auto alpha_gs2 = scheme_type::proof_of_knowledge_scheme_type::compute_g2_s(pubkey.alpha_pok.g1_s,
                                                                               pubkey.alpha_pok.g1_s_x, transcript, 1);
    BOOST_CHECK(scheme_type::proof_of_knowledge_scheme_type::verify_eval(pubkey.alpha_pok, alpha_gs2));
    auto beta_gs2 = scheme_type::proof_of_knowledge_scheme_type::compute_g2_s(pubkey.beta_pok.g1_s,
                                                                              pubkey.beta_pok.g1_s_x, transcript, 2);
    BOOST_CHECK(scheme_type::proof_of_knowledge_scheme_type::verify_eval(pubkey.beta_pok, beta_gs2));
}

BOOST_AUTO_TEST_SUITE_END()
