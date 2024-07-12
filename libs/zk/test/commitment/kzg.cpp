//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

void dump_vector(std::vector<uint8_t> const &x, std::string label = "") {
    std::cout << label << "[" << std::dec << x.size() << "] [31;1m";
    for (auto v: x) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(v);
    }
    std::cout << "[0m" << std::endl;
}

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

template<typename curve_type>
struct kzg_basic_test_runner {

    bool run_test() {
        typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

        typedef zk::commitments::kzg<curve_type> kzg_type;

        scalar_value_type alpha = 10u;
        std::size_t n = 16;
        scalar_value_type z = 2u;
        const polynomial<scalar_value_type> f = {{scalar_value_type::modulus - 1u, 1u, 2u, 3u}};

        auto params = typename kzg_type::params_type(n, alpha);
        BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
        BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
        BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
        BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
        BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

        auto commit = zk::algorithms::commit<kzg_type>(params, f);

        BOOST_CHECK_EQUAL(3209u * curve_type::template g1_type<>::value_type::one(), commit);

        typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
        auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

        return zk::algorithms::verify_eval<kzg_type>(params, proof, pk);
    }

};

using BasicTestFixtures = boost::mpl::list<
    kzg_basic_test_runner<algebra::curves::bls12_381>,
    kzg_basic_test_runner<algebra::curves::mnt4_298>,
    kzg_basic_test_runner<algebra::curves::mnt6_298>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(kzg_basic_test, F, BasicTestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}


template<typename curve_type>
struct kzg_random_test_runner {

    bool run_test() {
        typedef typename curve_type::scalar_field_type scalar_field_type;
        typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

        typedef zk::commitments::kzg<curve_type> kzg_type;

        std::size_t n = 298;
        scalar_value_type z = algebra::random_element<scalar_field_type>();
        const polynomial<scalar_value_type> f = {
                scalar_value_type::modulus - 1u, 1u, 2u, 3u, 5u, scalar_value_type::modulus - 15u};

        auto params = typename kzg_type::params_type(n);
        auto commit = zk::algorithms::commit<kzg_type>(params, f);

        typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
        auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

        return zk::algorithms::verify_eval<kzg_type>(params, proof, pk);
    }
};

using RandomTestFixtures = boost::mpl::list<
    kzg_random_test_runner<algebra::curves::bls12_381>,
    kzg_random_test_runner<algebra::curves::mnt4_298>,
    kzg_random_test_runner<algebra::curves::mnt6_298>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(kzg_random_test, F, RandomTestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}

BOOST_AUTO_TEST_CASE(kzg_false_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 10u;
    std::size_t n = 16;
    scalar_value_type z = 5u;
    const polynomial<scalar_value_type> f = {100u, 1u, 2u, 3u};

    auto params = typename kzg_type::params_type(n, alpha);

    auto commit = zk::algorithms::commit<kzg_type>(params, f);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));

    // wrong params
    auto ck2 = params.commitment_key;
    ck2[0] = ck2[0] * 2;
    auto params2 = kzg_type::params_type(ck2, params.verification_key * 2u);
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params2, proof, pk));

    // wrong commit
    auto pk2 = pk;
    pk2.commit = pk2.commit * 2u;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong eval
    pk2 = pk;
    pk2.eval *= 2u;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof, pk2));

    // wrong proof
    {
        // wrong params
        typename kzg_type::proof_type proof2;
        bool exception = false;
        try { proof2 = zk::algorithms::proof_eval<kzg_type>(params2, f, pk); }
        catch (std::runtime_error &e) { exception = true; }
        if (!exception) {
            BOOST_CHECK(proof2 != proof);
            BOOST_CHECK_MESSAGE(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk), "wrong params");
        }
    }
    auto proof2 = proof * 2u;
    BOOST_CHECK(!zk::algorithms::verify_eval<kzg_type>(params, proof2, pk));
}

BOOST_AUTO_TEST_CASE(kzg_test_mnt6_accumulated) {

    typedef algebra::curves::mnt6_298 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef zk::commitments::kzg<curve_type> kzg_type;

    scalar_value_type alpha = 7u;
    std::size_t n = 8;
    scalar_value_type z = 2u;
    const polynomial<scalar_value_type> f = {
            0x0ed6fb07f52c1f1ef7952250702368474f20fd7af906ba3a5842cdb7946c69b603852bf1069_cppui_modular298,
            0x14db9efba58de09f8ccb1d73fefce45393856e6a7509006561fe67ea354ec69d791b44c1476_cppui_modular298,
            0x0e9fa83a6f8891bc7e6aa1afae85e11dd80cdef32dfcef7cedc12792cf74141c899c8fb1f98_cppui_modular298,
            0x101cc0b43782ca40ae5bf96aabf461e1a623ab9284acac3bb6d55bff4429356dad714ee0bd0_cppui_modular298,
            0x1310586a4d1ed251d1e4c95711fb9346a2b233649f5ce32fe1cf3aea423d131787187a13799_cppui_modular298,
            0x0d9ed064a24e83ac6134de7cca08bdc3e31ffd4db0a004b63039f76821ec2cc53b7e6a74735_cppui_modular298,
            0x2839e48822f55b4e487b817ddf06a6e32e0dcc0c2ced1e738d38fec15bd4717d7680dda90ec_cppui_modular298,
    };

    auto f_eval = f.evaluate(alpha);

    auto params = typename kzg_type::params_type(n, alpha);
    auto commit = zk::algorithms::commit<kzg_type>(params, f);
    nil::marshalling::status_type status;
    using endianness = nil::marshalling::option::big_endian;
    std::vector<uint8_t> single_commitment_bytes =
            nil::marshalling::pack<endianness>(commit, status);
    dump_vector(single_commitment_bytes, "commitment");

    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == params.commitment_key[0]);
    BOOST_CHECK(alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[1]);
    BOOST_CHECK(alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[2]);
    BOOST_CHECK(alpha * alpha * alpha * curve_type::template g1_type<>::value_type::one() == params.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == params.verification_key);

    BOOST_CHECK(f_eval * curve_type::template g1_type<>::value_type::one() == commit);

    typename kzg_type::public_key_type pk = {commit, z, f.evaluate(z)};
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, f, pk);

    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_kzg_test_suite)

template<typename curve_type>
struct batched_kzg_basic_test_runner {

    bool run_test() {
        typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

        typedef hashes::sha2<256> transcript_hash_type;
        const std::size_t batch_size = 1;
        typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
        typedef typename kzg_type::transcript_type transcript_type;

        typename kzg_type::batch_of_polynomials_type polys = {{{1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u}}};

        scalar_value_type alpha = 7u;
        std::size_t d = 8;
        std::size_t t = 8;
        auto params = typename kzg_type::params_type(d, t, alpha);

        std::vector<std::vector<scalar_value_type>> eval_points = {{{101u, 2u, 3u},}};
        std::vector<scalar_value_type> merged_eval_points = zk::algorithms::merge_eval_points<kzg_type>(eval_points);
        std::vector<typename kzg_type::polynomial_type> rs = zk::algorithms::create_evals_polys<kzg_type>(polys,
                eval_points);

        BOOST_CHECK(rs.size() == batch_size);
        for (std::size_t i = 0; i < batch_size; ++i) {
            for (const auto &s: eval_points[i]) {
                BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
            }

        }
        auto commits = zk::algorithms::commit<kzg_type>(params, polys);
        auto pk = typename kzg_type::public_key_type(commits, merged_eval_points, eval_points, rs);

        transcript_type transcript;
        auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

        transcript_type transcript_verification;

        return zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification);
    }

};

using BatchedBasicTestFixtures = boost::mpl::list<
    batched_kzg_basic_test_runner<algebra::curves::bls12_381>,
    batched_kzg_basic_test_runner<algebra::curves::mnt4_298>,
    batched_kzg_basic_test_runner<algebra::curves::mnt6_298>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(batched_kzg_basic_test, F, BatchedBasicTestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}

template<typename curve_type>
struct batched_kzg_bigger_test_runner {

    bool run_test() {
        typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

        typedef hashes::keccak_1600<256> transcript_hash_type;
        typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
        typedef typename kzg_type::transcript_type transcript_type;

        scalar_value_type alpha = 7u;
        typename kzg_type::batch_of_polynomials_type polys = {{
            {{ 1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u}},
            {{11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u}},
            {{21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u}},
            {{31u, 32u, 33u, 34u, 35u, 36u, 37u, 38u}}
        }};

        auto params = typename kzg_type::params_type(8, 8, alpha);

        std::vector<std::vector<scalar_value_type>> S = {{
            {101u, 2u, 3u},
            {102u, 2u, 3u},
            {1u, 3u},
            {101u, 4u}
        }};
        std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
        {
            std::vector<scalar_value_type> T_check = {1u, 2u, 3u, 4u, 101u, 102u};
            std::sort(T.begin(), T.end());
            BOOST_CHECK(T == T_check);
        }
        auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
        BOOST_CHECK(rs.size() == polys.size());
        for (std::size_t i = 0; i < polys.size(); ++i) {
            BOOST_CHECK(rs[i].degree() < polys[i].degree());
            for (auto s: S[i]) {
                BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
            }
        }
        auto commits = zk::algorithms::commit<kzg_type>(params, polys);
        auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

        transcript_type transcript;
        auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

        transcript_type transcript_verification;
        return zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification);
    }
};

using BatchedBiggerTestFixtures = boost::mpl::list<
    batched_kzg_bigger_test_runner<algebra::curves::bls12_381>,
    batched_kzg_bigger_test_runner<algebra::curves::mnt4_298>,
    batched_kzg_bigger_test_runner<algebra::curves::mnt6_298>
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(batched_kzg_bigger_test, F, BatchedBiggerTestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}

template<typename kzg_type>
typename kzg_type::params_type create_kzg_params(std::size_t degree_log) {
    typename kzg_type::field_type::value_type alpha(7u);
    std::size_t d = 1 << degree_log;
    typename kzg_type::params_type params(d, d, alpha);
    return params;
}

/* This test contains data from sample Placeholder run.
 * Could be reused to test internals of KZG step from Placeholder*/
BOOST_AUTO_TEST_CASE(batched_kzg_placeholder_repr) {
    typedef algebra::curves::mnt6_298 curve_type;
//    typedef algebra::curves::bls12_381 curve_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

    typedef hashes::keccak_1600<256> transcript_hash_type;
    typedef zk::commitments::batched_kzg<curve_type, transcript_hash_type, math::polynomial<scalar_value_type>> kzg_type;
    typedef typename kzg_type::transcript_type transcript_type;

    std::vector<math::polynomial_dfs<scalar_value_type>> polys_dfs = {{
        //~-~-~-~ commiting to batch: 0~-~-~-~
        {8, {
                0x1u,
                0x29ab55a4b34e699f13959ce2c174be01985b7a0c88268d41489977b2219cd8a8a4e33032230_cppui_modular298,
                0x00f73779fe09916dfdcc2fd1f968d534beb17daf7518cd9fae5c1f7bdcf94dd5d7def6980c4_cppui_modular298,
                0x0078fe16f00d3d46d50e74ed550e57c9dda4ca5bc69da7a1820913abb7f1f371dd044f1a9c9_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a71660000_cppui_modular298,
                0x1224262893ebbcc33644de228777f0eafdda5726867d8d5ced4b9a4ebf8fb824c0c3e62ddd1_cppui_modular298,
                0x3ad84453493094f44c0e4b334f83d9b7d7845383998b4cfe8788f285043342f78dc81fc7f3d_cppui_modular298,
                0x3b567db6572ce91b74cc0617f3de5722b89106d7480672fcb3dbfe55293a9d5b88a2c745638_cppui_modular298,
        }},
        {8, {
                0x11u,
                0x32765e1dd8b55d57208c21d4b69519f0a9c31da369823c8981592cca8e802a5f94e83d34525_cppui_modular298,
                0x106aaf19dea2a84dda8f2cf18ff62880a9c958a6c6a5a79a941e1739ac8e2b3355ce6018d04_cppui_modular298,
                0x0808df85f0e111b425f5c3c2a5f3d467b7f17018307821b9a29a4e6737112a8fad4940c4659_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165fff0_cppui_modular298,
                0x09591daf6e84c90b294e5930925794fbec72b38fa521de14b48be53652ac666dd0bed92badc_cppui_modular298,
                0x2b64ccb368977e146f4b4e13b8f6866bec6c788c47fe7303a1c6fac7349e659a0fd8b6472fd_cppui_modular298,
                0x33c69c47565914ae23e4b742a2f8da84de44611ade2bf8e4934ac399aa1b663db85dd59b9a8_cppui_modular298,
        }},
        {8, {
                0x121u,
                0x14837ac17edd19691f5b84d622f5280b0f03870f34ac907aa464fd672612e51d5448d739767_cppui_modular298,
                0x27d7b182abe493a25c180ff56ba5f4d8ed879e46f66fb6cafe6b42d0f0be9b331c180825d40_cppui_modular298,
                0x10f7e04a707de031f19d09e27357bd0a0a9ccf351ab20817607510d8e5cab1efb68f204abe7_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165fee0_cppui_modular298,
                0x274c010bc85d0cf92a7ef62f25f786e187324a23d9f78a2391801499bb19abb0115e3f2689a_cppui_modular298,
                0x13f7ca4a9b5592bfedc26b0fdd46ba13a8ae32ec183463d33779cf2ff06df59a498f0e3a2c1_cppui_modular298,
                0x2ad79b82d6bc4630583d7122d594f1e28b9901fdf3f21286d5700127fb61deddaf17f61541a_cppui_modular298,
        }},
        {8, {
                0x1331u,
                0x31adbbd7088bf00fa3cf6b1de5a83e1d102ee2033641130ddd3b79d5216262ef9c92daf0dd2_cppui_modular298,
                0x136877db5aae278ef135c61203d9be3d51b18584bc5dfeae9447a9d64fbe15917f6a9463135_cppui_modular298,
                0x3137f5bc5b7349c7e403bbf48520d1f85b927dba8b421f149031d663bdc38db588e4cb76a53_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165ecd0_cppui_modular298,
                0x0a21bff63eae3652a60b0fe7634470cf8606ef2fd863079058a9982bbfca2dddc9143b6f22f_cppui_modular298,
                0x286703f1ec8bfed358a4b4f34512f0af44844bae52461befa19d682a916e7b3be63c81fcecc_cppui_modular298,
                0x0a978610ebc6dc9a65d6bf10c3cbdcf43aa353788361fb89a5b33b9d23690317dcc24ae95ae_cppui_modular298,
        }},
        {8, {
                0x1u,
                0x29ab55a4b34e699f13959ce2c174be01985b7a0c88268d41489977b2219cd8a8a4e33032230_cppui_modular298,
                0x00f73779fe09916dfdcc2fd1f968d534beb17daf7518cd9fae5c1f7bdcf94dd5d7def6980c4_cppui_modular298,
                0x0078fe16f00d3d46d50e74ed550e57c9dda4ca5bc69da7a1820913abb7f1f371dd044f1a9c9_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a71660000_cppui_modular298,
                0x1224262893ebbcc33644de228777f0eafdda5726867d8d5ced4b9a4ebf8fb824c0c3e62ddd1_cppui_modular298,
                0x3ad84453493094f44c0e4b334f83d9b7d7845383998b4cfe8788f285043342f78dc81fc7f3d_cppui_modular298,
                0x3b567db6572ce91b74cc0617f3de5722b89106d7480672fcb3dbfe55293a9d5b88a2c745638_cppui_modular298,
        }},
        {8, {
                0x11u,
                0x32765e1dd8b55d57208c21d4b69519f0a9c31da369823c8981592cca8e802a5f94e83d34525_cppui_modular298,
                0x106aaf19dea2a84dda8f2cf18ff62880a9c958a6c6a5a79a941e1739ac8e2b3355ce6018d04_cppui_modular298,
                0x0808df85f0e111b425f5c3c2a5f3d467b7f17018307821b9a29a4e6737112a8fad4940c4659_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165fff0_cppui_modular298,
                0x09591daf6e84c90b294e5930925794fbec72b38fa521de14b48be53652ac666dd0bed92badc_cppui_modular298,
                0x2b64ccb368977e146f4b4e13b8f6866bec6c788c47fe7303a1c6fac7349e659a0fd8b6472fd_cppui_modular298,
                0x33c69c47565914ae23e4b742a2f8da84de44611ade2bf8e4934ac399aa1b663db85dd59b9a8_cppui_modular298,
        }},
        {8, {
                0x121u,
                0x14837ac17edd19691f5b84d622f5280b0f03870f34ac907aa464fd672612e51d5448d739767_cppui_modular298,
                0x27d7b182abe493a25c180ff56ba5f4d8ed879e46f66fb6cafe6b42d0f0be9b331c180825d40_cppui_modular298,
                0x10f7e04a707de031f19d09e27357bd0a0a9ccf351ab20817607510d8e5cab1efb68f204abe7_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165fee0_cppui_modular298,
                0x274c010bc85d0cf92a7ef62f25f786e187324a23d9f78a2391801499bb19abb0115e3f2689a_cppui_modular298,
                0x13f7ca4a9b5592bfedc26b0fdd46ba13a8ae32ec183463d33779cf2ff06df59a498f0e3a2c1_cppui_modular298,
                0x2ad79b82d6bc4630583d7122d594f1e28b9901fdf3f21286d5700127fb61deddaf17f61541a_cppui_modular298,
        }},
        {8, {
                0x1331u,
                0x31adbbd7088bf00fa3cf6b1de5a83e1d102ee2033641130ddd3b79d5216262ef9c92daf0dd2_cppui_modular298,
                0x136877db5aae278ef135c61203d9be3d51b18584bc5dfeae9447a9d64fbe15917f6a9463135_cppui_modular298,
                0x3137f5bc5b7349c7e403bbf48520d1f85b927dba8b421f149031d663bdc38db588e4cb76a53_cppui_modular298,
                0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a7165ecd0_cppui_modular298,
                0x0a21bff63eae3652a60b0fe7634470cf8606ef2fd863079058a9982bbfca2dddc9143b6f22f_cppui_modular298,
                0x286703f1ec8bfed358a4b4f34512f0af44844bae52461befa19d682a916e7b3be63c81fcecc_cppui_modular298,
                0x0a978610ebc6dc9a65d6bf10c3cbdcf43aa353788361fb89a5b33b9d23690317dcc24ae95ae_cppui_modular298,
        }},
        {8, {0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x1u, 0x0u, 0x0u,}},
        {8, {0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x1u, 0x1u,}},
        {8, {
                0x0u,
                0x1u,
                0x1u,
                0x0u,
                0x0u,
                0x1f8915cc2533543f2bc6164e6238fc23a81c0f463c4646f1d40c1d7dfd0ae08ab78492cbef1_cppui_modular298,
                0x39bef1b52e65b396fbac77780f097c34e4287e259355a4ea31e0dcfacd0677a359e136b2fdd_cppui_modular298,
                0x173564dab75ba19b463030c03996325d30e7829fc226518b459919e6d64278946b02141888b_cppui_modular298,
        }},
        {8, {
                0x0u,
                0x0u,
                0x0u,
                0x1u,
                0x1u,
                0x0722a67f49f9ecfe9f0874df295dcd87a484fabc9ed6fa56696cb563b4ded702bbe2984c787_cppui_modular298,
                0x3b1bf86dcd7b7526048b0705c8287a3b97ca771ba445718a3614352160278d229349a1b7d08_cppui_modular298,
                0x1e127023ee88eeab382e9d07a328168599c3a9e3c0fe99eadb31575515db872426d7356b1bb_cppui_modular298,
        }},
        //~-~-~-~ commiting to batch: 1~-~-~-~
        {8, {
                0x39ef702ef59ff1816e4f51f2ae7fe2d78108c006d5f3039cd1a474ba8c48c16a62518f86863_cppui_modular298,
                0x17dadc1965bae6d9426ef1a2e6d3640ac4cd96089c55c7dc3800924668fcc450cbaa7de9f4c_cppui_modular298,
                0x1202bd2e4122c826d8ba7cd66346c0df0326468fd6e7989c8eebe3dedfcbd9b0ecdc1fb41c2_cppui_modular298,
                0x3b718dda0c9262c55640bd1e364df577ec246e46cb05109733008263282cc1a8959b4bf6fa7_cppui_modular298,
                0x27b08d175547d973e48f341c081c3851eee512d6e73200bfa47b1e049e1d268409ad2ce21c9_cppui_modular298,
                0x1872fd6e208095436bfcb92388e0d1c8509c3f8e89235d0430c61add0ab203ac30370518ce6_cppui_modular298,
                0x304c1332568ebbe7347b598eef6cb41f198a574c4ff7cd151337211efea753ec6fc7d61330b_cppui_modular298,
                0x1b41e76a1c5a4daa01029a0ec27b5f0b06ca7b480b600b8b573ae00feaab4ad9f1146a99459_cppui_modular298,
        }},
        {8, {
                0x11cccdf2e5ccc50aa597c4194181c1fe652f508e4aafb2a0137f878c4b3b9d09511285954a1_cppui_modular298,
                0x1e2f5a14babe0e0d4adcace1969a3c78807ea6da4ae1cca797a6bf88c3101397d8d2452a9dc_cppui_modular298,
                0x360a362e2078f4e68d4b9e847d6da083454c3ce2e7379483cfa751cf2c0cd7e8a47cc314928_cppui_modular298,
                0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui_modular298,
                0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui_modular298,
                0x011394bbd52cee496c395d41b68e0732c88572384d492e195f8f5b1c7a1c61f6ed67f94c950_cppui_modular298,
                0x194e4123c5669a48341b2f6b127f0a8b109818666a3d2229f23414de9c5d23d2d63c05309be_cppui_modular298,
                0x30641ec0f843aeb8202263821cac300d11b237ce42e2876763c8c16513494b993aaf5941f61_cppui_modular298,
        }},
        {8, {
                0x1e2f5a14babe0e0d4adcace1969a3c78807ea6da4ae1cca797a6bf88c3101397d8d2452a9dc_cppui_modular298,
                0x360a362e2078f4e68d4b9e847d6da083454c3ce2e7379483cfa751cf2c0cd7e8a47cc314928_cppui_modular298,
                0x0c3d778f1a6196ab1c2ba05597c7b275b23cb23faf7b128228ae23ad2aac20cc2bb1cc68ae9_cppui_modular298,
                0x1d871330c3db0fc34493247dc5f22570c08e3c4d3019e89ccadb340ddf48317d9dda6bf5cd9_cppui_modular298,
                0x114ac4e3bcbc6bf412878efb87080a493920fdbdb54535e797af6c6f15cacfa5a93c46626f0_cppui_modular298,
                0x0cfede4389503774cda3e57a7034cc1c54ad074f86f551b54a44118a30afd0fc06ad7393ee6_cppui_modular298,
                0x3b079297527c765d71f9db51a85f47c081d4047080ad9352f6a325410e1e8490ddc59988939_cppui_modular298,
                0x299eacd3439bb98b27f8cbaafb3983162a895d3de16cb29360ad4b12f5f114dee4f5a065b97_cppui_modular298,
        }},
        {8, {
                0x126a1e24bba3895afe1e9d30005f807b7df2082352cd5c31f79e7e1faee22ae9ef6d091bb5c_cppui_modular298,
                0x0u, 0x1u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u,
        }},

        //~-~-~-~ commiting to batch: 2~-~-~-~
        {8, {0x1u, 0x1u, 0x1u, 0x1u, 0x1u, 0x1u, 0x1u, 0x1u,}},

        //~-~-~-~ commiting to batch: 3~-~-~-~
        {8, {
                0x2783a8a7c5cf7e94e4d1fdc4aa6eb807ea4eddbf81ea87939f040dc851e9212b9dca604ac9a_cppui_modular298,
                0x13230785fb96c79b65251354a51866632384c4dc7ceff4e48dc2fac8f09db1ce7367e20608b_cppui_modular298,
                0x2ccbbf5a905e4515c62fede907c2625d90bfda58027217f7e58155b67d5851fb4cf46f04364_cppui_modular298,
                0x17adaf6b5019e118bc7ac6213b0dc84cf1a9cada9cc620471384b7a191db27251337ec3d3b7_cppui_modular298,
                0x05b19c26a34901d91528679eeac2c7f311aa3f5f0fa669855b10522373949671df3f1e23c38_cppui_modular298,
                0x37421ad4e9cf2ccadc50246390593aa253e4ca3ba5767e931130a2f905a49443e0e02fc0ce8_cppui_modular298,
                0x2a2814a40ce271f86b0369793c4c79d31686212ad02a382f6288ef94cabe1e2cff80ce74bd5_cppui_modular298,
                0x383fcb086d115688ba77b1449bd46480f3bd7cbb070242833338005e60dcaa9ba238c801961_cppui_modular298,
        }},
        {8, {
                0x0710f09328ac0442d2d93a61f4eda9b265a27ea0570484e3a1cf1aaa249974ea1a99377a11c_cppui_modular298,
                0x2bb0eec490c8ac0bbe164c6ee7072a8989e33a7006d8f222b1476b15c2ef0386b49b7d6bc28_cppui_modular298,
                0x3552ef5f48bc3702e4e9f8fc7b236de25d1a78e256d8417ff106bbc75b7cbfc36c8977b2896_cppui_modular298,
                0x3871e84395a7af9c0fdd19321af6b742815a982bb5f59bcf7be6793caa98f4a919032d2969d_cppui_modular298,
                0x153bd600c1074537112d1df7afd22932c713cc84c08d3c197cbdd9d84b675ab9c62e78d36a0_cppui_modular298,
                0x12d86d35994854ef3606ae63e5114209bec8dbb0d3ebb1bb9a786fd27ced58870d3779d3d7a_cppui_modular298,
                0x2e0895904268862017c64e0a495813bf84b1d2137a53102097557bd90c2aac21c0802fc1787_cppui_modular298,
                0x0742ee092a59ae6b7169ac51e7339c52adc1dc74471e0d207a3d29dd37d60ea9bc9438e5c15_cppui_modular298,
        }},
        math::polynomial_dfs<scalar_value_type>::zero(),
        math::polynomial_dfs<scalar_value_type>::zero(),
        math::polynomial_dfs<scalar_value_type>::zero(),
        math::polynomial_dfs<scalar_value_type>::zero(),
    }};

    std::vector<math::polynomial<scalar_value_type>> polys;
    for (auto const &p_dfs: polys_dfs) {
        auto p = math::polynomial<scalar_value_type>(p_dfs.coefficients());
        polys.push_back(p);
    }

    //    auto params = typename kzg_type::params_type(8, 8, alpha);
    auto params = create_kzg_params<kzg_type>(3 /*degree_log*/);
    auto commits = zk::algorithms::commit<kzg_type>(params, polys);
    using endianness = nil::marshalling::option::big_endian;
    for (auto &c: commits) {
        nil::marshalling::status_type status;
        std::vector<uint8_t> single_commitment_bytes =
                nil::marshalling::pack<endianness>(c, status);
        dump_vector(single_commitment_bytes, "commitment");
    }

    std::vector<std::vector<scalar_value_type>> S = {
            /* points_k_i:0,0: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,1: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,2: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,3: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,4: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,5: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,6: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,7: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,8: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,
                                   0x3afff0e9becdc8be161a77a403b466aa7d696ebe365418763ba1157a5aa27fd000e04d44b99_cppui_modular298,},
            /* points_k_i:0,9: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,
                                   0x3afff0e9becdc8be161a77a403b466aa7d696ebe365418763ba1157a5aa27fd000e04d44b99_cppui_modular298,},
            /* points_k_i:0,10:*/ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:0,11:*/ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:1,0: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:1,1: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:1,2: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:1,3: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:2,0: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,
                                   0x3afff0e9becdc8be161a77a403b466aa7d696ebe365418763ba1157a5aa27fd000e04d44b99_cppui_modular298,},
            /* points_k_i:3,0: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:3,1: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:3,2: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:3,3: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:3,4: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
            /* points_k_i:3,5: */ {0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,},
    };

    std::vector<scalar_value_type> T = zk::algorithms::merge_eval_points<kzg_type>(S);
    {
        std::vector<scalar_value_type> T_check = {
                0x3a3eeb9eda157d043c7a56f0bb263b4d1bc21dc74cfb1b5e9a80f65a461c3916_cppui_modular298,
                0x3afff0e9becdc8be161a77a403b466aa7d696ebe365418763ba1157a5aa27fd000e04d44b99_cppui_modular298,
        };
        std::sort(T.begin(), T.end());
        BOOST_CHECK(T == T_check);
    }
    auto rs = zk::algorithms::create_evals_polys<kzg_type>(polys, S);
    BOOST_CHECK(rs.size() == polys.size());
    for (std::size_t i = 0; i < polys.size(); ++i) {
        BOOST_CHECK(polys[i].degree() == 0 || rs[i].degree() < polys[i].degree());
        for (auto s: S[i]) {
            BOOST_CHECK(polys[i].evaluate(s) == rs[i].evaluate(s));
        }
    }
    auto pk = typename kzg_type::public_key_type(commits, T, S, rs);

    transcript_type transcript;
    auto proof = zk::algorithms::proof_eval<kzg_type>(params, polys, pk, transcript);

    transcript_type transcript_verification;
    BOOST_CHECK(zk::algorithms::verify_eval<kzg_type>(params, proof, pk, transcript_verification));
}

BOOST_AUTO_TEST_SUITE_END()

