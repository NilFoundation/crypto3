//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE kzg_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/edwards.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/edwards.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::kzg<curve_type, transcript_hash_type> kzg_type;
    typedef kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(10 * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(100 * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(1000 * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, f, transcript);

    transcript_type transcript_verifier = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(kzg_random_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::kzg<curve_type, transcript_hash_type> kzg_type;
    typedef kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = algebra::random_element<scalar_field_type>();
    std::size_t n = 298;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3, 5, -15};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, f, transcript);

    transcript_type transcript_verifier = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(kzg_false_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::kzg<curve_type, transcript_hash_type> kzg_type;
    typedef kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    const polynomial<scalar_value_type> f = {100, 1, 2, 3};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, f, transcript);

    transcript_type transcript_verifier = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verifier));

    // wrong transcript - already used
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verifier));

    // wrong params
    auto ck2 = params.commitment_key;
    ck2[0] = ck2[0] * 2;
    auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
    transcript_type transcript_verifier_wp = zk::algorithms::setup_transcript<kzg_type>(params2);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk, transcript_verifier_wp));

    // wrong commit
    auto pk2 = pk;
    pk2.commit = pk2.commit * 2;
    transcript_type transcript_verifier_wc = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2, transcript_verifier_wc));

    // wrong eval
    pk2 = pk;
    pk2.eval *= 2;
    transcript_type transcript_verifier_we = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2, transcript_verifier_we));

    // wrong proof
    {
        // wrong params
        typename kzg_type::proof_type proof2;
        typename kzg_type::public_key_type pk2;
        bool exception = false;
        transcript_type transcript_wp = zk::algorithms::setup_transcript<kzg_type>(params);
        try {auto [proof2, pk2] = zk::algorithms::proof_eval<kzg_type>(params2, f, transcript_wp);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            transcript_type transcript_wp_verifier = zk::algorithms::setup_transcript<kzg_type>(params2);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_wp_verifier), "wrong params");
        }

        // wrong transcript
        exception = false;
        try {auto [proof2, pk2] = zk::algorithms::proof_eval<kzg_type>(params, f, transcript_wp);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            transcript_type transcript_wt_verifier = zk::algorithms::setup_transcript<kzg_type>(params);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_wt_verifier), "wrong transcript");
        }
    }
    auto proof2 = proof * 2;
    transcript_type transcript_wp_verifier = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_wp_verifier));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_batched_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 2> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    std::size_t n = 8;
    const std::vector<polynomial<scalar_value_type>> fs{{
        {{1, 2, 3, 4, 5, 6, 7, 8}},
        {{11, 12, 13, 14, 15, 16, 17, 18}},
        {{21, 22, 23, 24, 25, 26, 27, 28}},
        {{31, 32, 33, 34, 35, 36, 37, 38}},
    }};
    const std::vector<polynomial<scalar_value_type>> gs{{
        {{71, 72, 73, 74, 75, 76, 77, 78}},
        {{81, 82, 83, 84, 85, 86, 87, 88}},
        {{91, 92, 93, 94, 95, 96, 97, 98}},
    }};
    typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, polys, transcript);

    transcript_type transcript_verification = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_CASE(kzg_batched_random_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    std::size_t n = 298;
    scalar_value_type alpha = algebra::random_element<scalar_field_type>();
    const std::vector<polynomial<scalar_value_type>> f0{{
        {{1, 2, 3, 4, 5, 6, 7, 8}},
        {{11, 12, 13, 14, 15, 16, 17}},
        {{21, 22, 23, 24, 25, 26, 27, 28}},
        {{31, 32, 33, 34, 35, 36, 37, 38, 39}},
    }};
    const std::vector<polynomial<scalar_value_type>> f1{{
        {{71, 72}},
        {{81, 82, 83, 85, 86, 87, 88}},
        {{91, 92, 93, 94, 95, 96, 97, 98, 99, 100}},
    }};
    const std::vector<polynomial<scalar_value_type>> f2{{
        {{73, 74, 25}},
        {{87}},
        {{91, 92, 93, 94, 95, 96, 97, 100, 1, 2, 3}},
    }};
    const kzg_type::batch_of_batches_of_polynomials_type polys = {f0, f1, f2};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, polys, transcript);

    transcript_type transcript_verification = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_CASE(kzg_batched_false_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    std::size_t n = 298;
    const std::vector<polynomial<scalar_value_type>> fs{{
        {{1, 2, 3, 4, 5, 6, 7, 8}},
        {{11, 12, 13, 14, 15, 16, 17, 18}},
        {{21, 22, 23, 24, 25, 26, 27, 28}},
        {{31, 32, 33, 34, 35, 36, 37, 38}},
    }};
    const std::vector<polynomial<scalar_value_type>> gs{{
        {{71, 72, 73, 74, 75, 76, 77, 78}},
        {{81, 82, 83, 84, 85, 86, 87, 88}},
        {{91, 92, 93, 94, 95, 96, 97, 98}},
    }};
    const std::vector<polynomial<scalar_value_type>> hs{{
        {{71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81}},
    }};
    typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs, hs};

    auto params = zk::algorithms::setup<kzg_type>(n, alpha);

    transcript_type transcript = zk::algorithms::setup_transcript<kzg_type>(params);
    auto [proof, pk] = zk::algorithms::proof_eval<kzg_type>(params, polys, transcript);

    transcript_type transcript_verification = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

    // wrong params
    auto ck2 = params.commitment_key;
    ck2[0] = ck2[0] * 2;
    auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
    transcript_type transcript_verification_wp = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk, transcript_verification_wp));

    // wrong transcript - used
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

    // wrong transcript - wrong params
    transcript_type transcript_verification_wpt = zk::algorithms::setup_transcript<kzg_type>(params2);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification_wpt));

    // wrong evals
    auto pk_we = pk;
    pk_we.evals[0].back() = pk_we.evals[0].back() * 2;
    transcript_type transcript_verification_we = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_we, transcript_verification_we));

    // wrong commitments
    auto pk_wc = pk;
    pk_wc.commits[0].back() = pk_wc.commits[0].back() * 2;
    transcript_type transcript_verification_wc = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_wc, transcript_verification_wc));

    // wrong pk
    auto pk2 = pk;
    pk2.commits[0].back() = pk2.commits[0].back() * 2;
    pk2.evals[0].back() = pk2.evals[0].back() * 2;
    transcript_type transcript_verification_wpk = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2, transcript_verification_wpk));

    // wrong proof
    {
        // wrong params
        typename kzg_type::batched_proof_type proof2;
        typename kzg_type::batched_public_key_type pk2;
        bool exception = false;
        transcript_type transcript_wpp = zk::algorithms::setup_transcript<kzg_type>(params2);
        try {auto [proof2, pk2] = zk::algorithms::proof_eval<kzg_type>(params2, polys, transcript_wpp);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            transcript_type transcript_verification_wpp = zk::algorithms::setup_transcript<kzg_type>(params);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
        }

        // wrong transcript - used
        exception = false;
        try {auto [proof2, pk2] = zk::algorithms::proof_eval<kzg_type>(params, polys, transcript_wpp);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            transcript_type transcript_verification_wpt = zk::algorithms::setup_transcript<kzg_type>(params);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpt), "wrong transcript");
        }
        
        // wrong evals
        exception = false;
        transcript_type transcript_wpe = zk::algorithms::setup_transcript<kzg_type>(params);
        try {auto [proof2, pk2] = zk::algorithms::proof_eval<kzg_type>(params, polys, transcript_wpe);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            transcript_type transcript_verification_wpe = zk::algorithms::setup_transcript<kzg_type>(params);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpe), "wrong evals");
        }
    }
    auto proof2 = proof;
    proof2.back() = proof2.back() * 2;
    transcript_type transcript_verification_wpr = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpr));

    // wrong combination of all
    transcript_type transcript_verification_2 = zk::algorithms::setup_transcript<kzg_type>(params);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof2, pk2, transcript_verification_2));
}

BOOST_AUTO_TEST_SUITE_END()