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

#include <boost/test/included/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}

BOOST_AUTO_TEST_CASE(kzg_basic_test_mnt6) {

    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 2;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}


BOOST_AUTO_TEST_CASE(kzg_random_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    std::size_t n = 298;
    scalar_value_type z = algebra::random_element<scalar_field_type>();
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3, 5, -15};

    auto params = typename kzg_type::params_type(n);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}

BOOST_AUTO_TEST_CASE(kzg_false_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    std::size_t n = 16;
    scalar_value_type z = 5;
    const polynomial<scalar_value_type> f = {100, 1, 2, 3};

    auto params = typename kzg_type::params_type(n, alpha);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));

    // wrong params
    auto ck2 = params.commitment_key;
    ck2[0] = ck2[0] * 2;
    auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk));

    // wrong commit
    auto pk2 = pk;
    pk2.commit = pk2.commit * 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong eval
    pk2 = pk;
    pk2.eval *= 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong proof
    {
        // wrong params
        typename kzg_type::proof_type proof2;
        bool exception = false;
        try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params2, f, pk);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk), "wrong params");
        }

        // wrong transcript
        exception = false;
        try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, f, pk2);}
        catch (std::runtime_error& e) {exception = true;}
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk), "wrong transcript");
        }
    }
    auto proof2 = proof * 2;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk));
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

// BOOST_AUTO_TEST_CASE(kzg_batched_basic_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 2> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     scalar_value_type alpha = 7;
//     std::size_t n = 8;
//     const std::vector<polynomial<scalar_value_type>> fs{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17, 18}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> gs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78}},
//         {{81, 82, 83, 84, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98}},
//     }};
//     typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs};
//     std::array<scalar_value_type, 2> zs = {101, 3};

//     auto params = typename kzg_type::params_type(n, alpha);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
// }

// BOOST_AUTO_TEST_CASE(kzg_batched_random_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     std::size_t n = 298;
//     const std::vector<polynomial<scalar_value_type>> f0{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38, 39}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> f1{{
//         {{71, 72}},
//         {{81, 82, 83, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98, 99, 100}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> f2{{
//         {{73, 74, 25}},
//         {{87}},
//         {{91, 92, 93, 94, 95, 96, 97, 100, 1, 2, 3}},
//     }};
//     const kzg_type::batch_of_batches_of_polynomials_type polys = {f0, f1, f2};
//     std::array<scalar_value_type, 3> zs = {101, 3, 5};

//     auto params = typename kzg_type::params_type(n);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
// }

// BOOST_AUTO_TEST_CASE(kzg_batched_false_test) {

//     typedef algebra::curves::bls12<381> curve_type;
//     typedef typename curve_type::base_field_type::value_type base_value_type;
//     typedef typename curve_type::base_field_type base_field_type;
//     typedef typename curve_type::scalar_field_type scalar_field_type;
//     typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

//     typedef hashes::sha2<256> transcript_hash_type;
//     typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, 3> kzg_type;
//     typedef typename kzg_type::transcript_type transcript_type;

//     scalar_value_type alpha = 7;
//     std::size_t n = 298;
//     const std::vector<polynomial<scalar_value_type>> fs{{
//         {{1, 2, 3, 4, 5, 6, 7, 8}},
//         {{11, 12, 13, 14, 15, 16, 17, 18}},
//         {{21, 22, 23, 24, 25, 26, 27, 28}},
//         {{31, 32, 33, 34, 35, 36, 37, 38}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> gs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78}},
//         {{81, 82, 83, 84, 85, 86, 87, 88}},
//         {{91, 92, 93, 94, 95, 96, 97, 98}},
//     }};
//     const std::vector<polynomial<scalar_value_type>> hs{{
//         {{71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81}},
//     }};
//     typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs, hs};
//     std::array<scalar_value_type, 3> zs = {101, 3, 5};

//     auto params = typename kzg_type::params_type(n, alpha);

//     typename kzg_type::batched_public_key_type pk = zk::algorithms::setup_public_key<kzg_type>(params, polys, zs);;
//     transcript_type transcript =
//     auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

//     transcript_type transcript_verification =
//     BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

//     // wrong params
//     auto ck2 = params.commitment_key;
//     ck2[0] = ck2[0] * 2;
//     auto params2 = kzg_type::params_type(ck2, params.verification_key * 2);
//     transcript_type transcript_verification_wp =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk, transcript_verification_wp));

//     // wrong transcript - used
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));

//     // wrong transcript - wrong params
//     transcript_type transcript_verification_wpt =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification_wpt));

//     // wrong evals
//     auto pk_we = pk;
//     pk_we.evals[0].back() = pk_we.evals[0].back() * 2;
//     transcript_type transcript_verification_we =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_we, transcript_verification_we));

//     // wrong commitments
//     auto pk_wc = pk;
//     pk_wc.commits[0].back() = pk_wc.commits[0].back() * 2;
//     transcript_type transcript_verification_wc =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk_wc, transcript_verification_wc));

//     // wrong pk
//     auto pk2 = pk;
//     pk2.commits[0].back() = pk2.commits[0].back() * 2;
//     pk2.evals[0].back() = pk2.evals[0].back() * 2;
//     transcript_type transcript_verification_wpk =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2, transcript_verification_wpk));

//     // wrong proof
//     {
//         // wrong params
//         typename kzg_type::batched_proof_type proof2;
//         typename kzg_type::batched_public_key_type pk2 = zk::algorithms::setup_public_key<kzg_type>(params2, polys, zs);
//         bool exception = false;
//         transcript_type transcript_wpp =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params2, polys, pk, transcript_wpp);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong transcript - used
//         exception = false;
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript_wpp);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpt =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpt), "wrong transcript");
//         }

//         // wrong evals
//         exception = false;
//         transcript_type transcript_wpe =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_we, transcript_wpe);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpe =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpe), "wrong evals");
//         }

//         // wrong zs
//         auto pk_zs = pk;
//         pk_zs.zs[0] = pk_zs.zs[0] * 2;
//         exception = false;
//         transcript_type transcript_wzs =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_zs, transcript_wzs);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong commits
//         exception = false;
//         transcript_type transcript_wcs =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk_we, transcript_wcs);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }

//         // wrong pk
//         exception = false;
//         transcript_type transcript_wpk =
//         try {auto proof2 = zk::algorithms::proof_eval<kzg_type>(params, polys, pk2, transcript_wpk);}
//         catch (std::runtime_error& e) {exception = true;}
//         if (!exception) {
//             BOOST_CHECK(proof2 != proof);
//             transcript_type transcript_verification_wpp =
//             BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpp), "wrong params");
//         }
//     }
//     auto proof2 = proof;
//     proof2.back() = proof2.back() * 2;
//     transcript_type transcript_verification_wpr =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk, transcript_verification_wpr));

//     // wrong combination of all
//     transcript_type transcript_verification_2 =
//     BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof2, pk2, transcript_verification_2));
// }

// BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

BOOST_AUTO_TEST_CASE(batched_kzg_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    const std::size_t batch_size = 1;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    typename kzg_type::batch_of_polynomials_type polys = {{{1, 2, 3, 4, 5, 6, 7, 8}}};

    scalar_value_type alpha = 7;
    std::size_t d = 8;
    std::size_t t = 8;
    auto params = typename kzg_type::params_type(d, t, alpha);

    std::vector<std::vector<scalar_value_type>> eval_points = {{{101, 2, 3},}};
    std::vector<scalar_value_type> merged_eval_points = zk::algorithms::merge_eval_points<kzg_type>(eval_points);
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, eval_points);

    BOOST_CHECK(rs.size() == batch_size);
    for (std::size_t i = 0; i < batch_size; ++i) {
        for (auto s : eval_points[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }

    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, merged_eval_points, eval_points, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_CASE(batched_kzg_bigger_basic_test) {
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    typename kzg_type::batch_of_polynomials_type polys = {{{{1, 2, 3, 4, 5, 6, 7, 8}},
                                                        {{11, 12, 13, 14, 15, 16, 17, 18}},
                                                        {{21, 22, 23, 24, 25, 26, 27, 28}},
                                                        {{31, 32, 33, 34, 35, 36, 37, 38}}}};

    auto params = typename kzg_type::params_type(8, 8, alpha);

    std::vector<std::vector<scalar_value_type>> S = {{{101, 2, 3}, {102, 2, 3}, {1, 3}, {101, 4}}};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {1, 2, 3, 4, 101, 102};
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(rs[i].degree() < polys[i].degree());
        for (auto s : S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}
/*
BOOST_AUTO_TEST_CASE(batched_kzg_bigger_basic_test_mnt6) {
    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::sha2<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    scalar_value_type alpha = 7;
    typename kzg_type::batch_of_polynomials_type polys = {{{{1, 2, 3, 4, 5, 6, 7, 8}},
                                                        {{11, 12, 13, 14, 15, 16, 17, 18}},
                                                        {{21, 22, 23, 24, 25, 26, 27, 28}},
                                                        {{31, 32, 33, 34, 35, 36, 37, 38}}}};

    auto params = typename kzg_type::params_type(8, 8, alpha);

    std::vector<std::vector<scalar_value_type>> S = {{{101, 2, 3}, {102, 2, 3}, {1, 3}, {101, 4}}};
    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {1, 2, 3, 4, 101, 102};
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(rs[i].degree() < polys[i].degree());
        for (auto s : S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}
*/

BOOST_AUTO_TEST_SUITE_END()
