#define BOOST_TEST_MODULE powers_of_tau_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/powers_of_tau/helpers.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(powers_of_tau_test_suite)

BOOST_AUTO_TEST_CASE(powers_of_tau_result_basic_test) {
    using curve_type = curves::bls12<381>;
    using g1_value_type = curve_type::g1_type<>::value_type;
    using g2_value_type = curve_type::g2_type<>::value_type;
    using scalar_field_type = curve_type::scalar_field_type;
    using scalar_field_value_type = scalar_field_type::value_type;
        
    constexpr const unsigned tau_powers = 1 << 5;

    using scheme_type = powers_of_tau<curve_type, tau_powers>;
    using helpers_type = powers_of_tau_helpers<curve_type, tau_powers>;
    
    auto acc1 = scheme_type::initial_accumulator();
    auto acc2 = acc1;
    auto transcript = helpers_type::compute_transcript(acc1);
    auto [pk, sk] = helpers_type::generate_keypair(transcript);
    acc2.transform(sk);

    BOOST_CHECK(scheme_type::verify_contribution(acc1, acc2, pk));
    auto result = scheme_type::finalize(acc2, tau_powers);

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

    for(std::size_t i = 0; i < domain->m; ++i) {
        BOOST_CHECK_MESSAGE(result.coeffs_g1[i] == g1_generator * u[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.coeffs_g2[i] == g2_generator * u[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.alpha_coeffs_g1[i] == g1_generator *(sk.alpha * u[i]), std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result.beta_coeffs_g1[i] == g1_generator * (sk.beta * u[i]), std::string("i=") + std::to_string(i));
    }

    auto result_16 = scheme_type::finalize(acc2, 16);
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

    for(std::size_t i = 0; i < domain_16->m; ++i) {
        BOOST_CHECK_MESSAGE(result_16.coeffs_g1[i] == g1_generator * u_16[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.coeffs_g2[i] == g2_generator * u_16[i], std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.alpha_coeffs_g1[i] == g1_generator *(sk.alpha * u_16[i]), std::string("i=") + std::to_string(i));
        BOOST_CHECK_MESSAGE(result_16.beta_coeffs_g1[i] == g1_generator * (sk.beta * u_16[i]), std::string("i=") + std::to_string(i));
    }
}

BOOST_AUTO_TEST_CASE(powers_of_tau_basic_test) {
    using curve_type = curves::bls12<381>;
    using scheme_type = powers_of_tau<curve_type, 32>;
    auto acc1 = scheme_type::initial_accumulator();
    auto acc2 = acc1;
    auto pubkey = scheme_type::contribute_randomness(acc2);
    BOOST_CHECK(acc1.tau_powers_g1[0] == acc2.tau_powers_g1[0]);
    BOOST_CHECK(scheme_type::verify_contribution(acc1, acc2, pubkey));
    auto acc3 = acc2;
    std::vector<std::uint8_t> beacon {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    auto beacon_pubkey = scheme_type::apply_randomness_beacon(acc3, beacon);
    BOOST_CHECK(scheme_type::verify_contribution(acc2, acc3, beacon_pubkey));
    BOOST_CHECK(scheme_type::verify_beacon_contribution(acc2, acc3, beacon));
    auto result = scheme_type::finalize(acc3, 32);
}

BOOST_AUTO_TEST_CASE(keypair_generation_basic_test) {
    using curve_type = curves::bls12<381>;
    using helpers_type = powers_of_tau_helpers<curve_type, 32>;
    std::vector<std::uint8_t> transcript(64, 1);
    auto keypair = helpers_type::generate_keypair(transcript);
    auto pubkey = keypair.first;
    auto tau_gs2 = helpers_type::compute_g2_s(pubkey.tau_pok.g1_s, pubkey.tau_pok.g1_s_x, transcript, 0);
    BOOST_CHECK(helpers_type::verify_pok(pubkey.tau_pok, tau_gs2));
    auto alpha_gs2 = helpers_type::compute_g2_s(pubkey.alpha_pok.g1_s, pubkey.alpha_pok.g1_s_x, transcript, 1);
    BOOST_CHECK(helpers_type::verify_pok(pubkey.alpha_pok, alpha_gs2));
    auto beta_gs2 = helpers_type::compute_g2_s(pubkey.beta_pok.g1_s, pubkey.beta_pok.g1_s_x, transcript, 2);
    BOOST_CHECK(helpers_type::verify_pok(pubkey.beta_pok, beta_gs2));
}

BOOST_AUTO_TEST_CASE(pok_basic_test) {
    using curve_type = curves::bls12<381>;
    using scalar_field_type = curve_type::scalar_field_type;
    using helpers_type = powers_of_tau_helpers<curve_type, 32>;
    std::vector<std::uint8_t> transcript(64, 1);
    scalar_field_type::value_type tau =
        random_element<scalar_field_type>();
    
    auto tau_pok = helpers_type::construct_pok(tau, transcript, 0);

    auto tau_gs2 = helpers_type::compute_g2_s(tau_pok.g1_s, tau_pok.g1_s_x, transcript, 0);
    BOOST_CHECK(helpers_type::verify_pok(tau_pok, tau_gs2));
}

BOOST_AUTO_TEST_CASE(is_same_ratio_basic_test) {
    using curve_type = curves::bls12<381>;
    using scalar_field_type = curve_type::scalar_field_type;
    using g1_type = curve_type::g1_type<>;
    using g1_value_type = g1_type::value_type;
    using g2_type = curve_type::g2_type<>;
    using g2_value_type = g2_type::value_type;
    using helpers_type = powers_of_tau_helpers<curve_type, 32>;

    scalar_field_type::value_type s =
        random_element<scalar_field_type>();
    
    g1_value_type g1 = g1_value_type::one();
    g1_value_type g1_s = s * g1;
    g2_value_type g2 = g2_value_type::one();
    g2_value_type g2_s = s * g2;
    BOOST_CHECK(helpers_type::is_same_ratio(std::make_pair(g1, g1_s), std::make_pair(g2, g2_s)));
}

BOOST_AUTO_TEST_SUITE_END()
