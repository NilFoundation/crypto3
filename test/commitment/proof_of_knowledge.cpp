#define BOOST_TEST_MODULE powers_of_a_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/zk/commitments/polynomial/proof_of_knowledge.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::commitments;

BOOST_AUTO_TEST_SUITE(proof_of_knowledge_test_suite)

BOOST_AUTO_TEST_CASE(pok_basic_test) {
    using curve_type = curves::bls12<381>;
    using scalar_field_type = curve_type::scalar_field_type;
    using scheme_type = proof_of_knowledge<curve_type>;
    std::vector<std::uint8_t> transcript(64, 1);
    scalar_field_type::value_type a = random_element<scalar_field_type>();

    auto a_pok = scheme_type::proof_eval(a, transcript, 0);

    auto a_gs2 = scheme_type::compute_g2_s(a_pok.g1_s, a_pok.g1_s_x, transcript, 0);
    BOOST_CHECK(scheme_type::verify_eval(a_pok, a_gs2));
    BOOST_CHECK(scheme_type::verify_eval(a_pok, transcript, 0));
}

BOOST_AUTO_TEST_SUITE_END()
