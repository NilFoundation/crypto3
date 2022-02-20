//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE pubkey_ecdsa_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/ecdsa.hpp>

#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/pkpad/emsa/emsa1.hpp>

#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os //<< std::hex
       << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename FpCurveGroupElement>
void print_fp_affine_curve_group_element(std::ostream &os, const FpCurveGroupElement &e) {
    os //<< std::hex
       << "( " << e.X.data << " : " << e.Y.data << " )" << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(std::ostream &os, const Fp2CurveGroupElement &e) {
    os //<< std::hex
       << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<typename curves::secp_r1<256>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::secp_r1<256>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<>
            struct print_log_value<typename curves::secp_k1<256>::g1_type<>::value_type> {
                void operator()(std::ostream &os, typename curves::secp_k1<256>::g1_type<>::value_type const &e) {
                    print_fp_curve_group_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

template<typename PolicyType, typename InputRange>
void rfc6979_test(
    const typename PolicyType::curve_type::scalar_field_type::value_type &x,
    const InputRange &msg,
    const typename PolicyType::curve_type::template g1_type<curves::coordinates::affine>::value_type &etalon_pk,
    const typename pubkey::public_key<PolicyType>::signature_type &etalon_sig) {
    using policy_type = PolicyType;
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

    pubkey::private_key<policy_type> sk(x);
    const auto &pk = static_cast<pubkey::public_key<policy_type>>(sk);

    BOOST_CHECK(etalon_pk == pk.pubkey_data().to_affine());

    signature_type sig1 = sign<policy_type>(msg, sk);
    BOOST_CHECK(etalon_sig == sig1);
    BOOST_CHECK(static_cast<bool>(verify<policy_type>(msg, sig1, pk)));
    auto sig1_wrong1 = sig1;
    sig1_wrong1.first -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong1, pk)));
    auto sig1_wrong2 = sig1;
    sig1_wrong2.second -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong2, pk)));
    sig1_wrong1.second -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong1, pk)));
}

template<typename PolicyType, typename InputRange>
void rfc6979_test_wo_pk_check(
    const typename PolicyType::curve_type::scalar_field_type::value_type &x,
    const InputRange &msg,
    const typename pubkey::public_key<PolicyType>::signature_type &etalon_sig) {
    using policy_type = PolicyType;
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

    pubkey::private_key<policy_type> sk(x);
    const auto &pk = static_cast<pubkey::public_key<policy_type>>(sk);

    signature_type sig1 = sign<policy_type>(msg, sk);
    BOOST_CHECK(etalon_sig == sig1);
    BOOST_CHECK(static_cast<bool>(verify<policy_type>(msg, sig1, pk)));
    auto sig1_wrong1 = sig1;
    sig1_wrong1.first -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong1, pk)));
    auto sig1_wrong2 = sig1;
    sig1_wrong2.second -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong2, pk)));
    sig1_wrong1.second -= 1;
    BOOST_CHECK(!static_cast<bool>(verify<policy_type>(msg, sig1_wrong1, pk)));
}


BOOST_AUTO_TEST_SUITE(ecdsa_manual_test_suite)

BOOST_AUTO_TEST_CASE(ecdsa_dummy_test) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::algebraic_random_device<scalar_field_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

    generator_type key_gen;
    pubkey::private_key<policy_type> privkey(key_gen());

    std::string text = "Hello, world!";
    std::vector<std::uint8_t> text_bytes(text.begin(), text.end());
    signature_type sig = sign<policy_type>(text_bytes, privkey);
    bool result = verify<policy_type>(text_bytes, sig, privkey);
    std::cout << result << std::endl;

    bool wrong_result = verify<policy_type>(text_bytes.begin(), text_bytes.end() - 1, sig, privkey);
    std::cout << wrong_result << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ecdsa_conformity_test_suite)

// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.3
BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp192r1_sha1_range_sign) {
    using curve_type = algebra::curves::secp192r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("2738091856095668696411541285481651538517235492429819322324");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("3746064528323905448614259422127567429422464404319222798591")),
            scalar_field_value_type(
                scalar_integral_type("2148766409948291628095385623409954629654691532883124968292"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("370984256434167747581047542350048843767064604504395481965")),
            scalar_field_value_type(
                scalar_integral_type("5764552547213450224003286117676227661608049734032827023543"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp192r1_sha224_range_sign) {
    using curve_type = algebra::curves::secp192r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("2738091856095668696411541285481651538517235492429819322324");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("3970701063966708871664579863216162975607852156173968177397")),
            scalar_field_value_type(
                scalar_integral_type("5504604701309298433102410446644795707377107352225209973114"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("2581261916193129091025347656926809995846752674212066290996")),
            scalar_field_value_type(
                scalar_integral_type("4511235810823295367395596984382054578161664436101192962707"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp192r1_sha256_range_sign) {
    using curve_type = algebra::curves::secp192r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("2738091856095668696411541285481651538517235492429819322324");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1840100961263083710623367090499191253309337908038449679189")),
            scalar_field_value_type(
                scalar_integral_type("5023041631781708045212851554060961543112660311254607862661"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1433031434470410322804225070384423839487998263142969612206")),
            scalar_field_value_type(
                scalar_integral_type("2118186646343382029478296149214691300582031424876384424527"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp192r1_sha384_range_sign) {
    using curve_type = algebra::curves::secp192r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("2738091856095668696411541285481651538517235492429819322324");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("5354898241243303802332309752106141676659771267993493997525")),
            scalar_field_value_type(
                scalar_integral_type("4797685534256901509793099681873243449623935073428895296606"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("4369596021698351344508449564504220149358176520708543423335")),
            scalar_field_value_type(
                scalar_integral_type("2981090334504566404661273874447634282899821337978910795642"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp192r1_sha512_range_sign) {
    using curve_type = algebra::curves::secp192r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("2738091856095668696411541285481651538517235492429819322324");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1897303436105410652692172982610439268695187646060100248760")),
            scalar_field_value_type(
                scalar_integral_type("1555340594905771381437280080293638721437565760833627983719"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("4221686972693711597846017334586518767782741265666324032854"),
                             base_integral_type("1465749634281639091955516932500199697567738736585249397827")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("6235656601174526473105455096340962935933028741718169610041")),
            scalar_field_value_type(
                scalar_integral_type("2864170569785310181220523163903251215244325438151696130704"))));
}

// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.4
BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp224r1_sha1_range_sign) {
    using curve_type = algebra::curves::secp224r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("25498800374793671048762784949265672262924700173077254356588179904449");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("3594784062681563414260306942712680659433068818015189088255593895852")),
                       scalar_field_value_type(scalar_integral_type(
                           "10828162142991797407688523184203113189288941632148958529571222732137"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "23449424083165108781282849555979002728826794694850953570928681017884")),
                       scalar_field_value_type(scalar_integral_type(
                           "15754252805037495002172362327653525254480656794675529506638307818450"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp224r1_sha224_range_sign) {
    using curve_type = algebra::curves::secp224r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("25498800374793671048762784949265672262924700173077254356588179904449");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("3040851282929486539308965527528058893920708295078492293528438963518")),
                       scalar_field_value_type(scalar_integral_type(
                           "17525163212076526285188361048541253897411325542035799279707245264572"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "20668280537613865722259681635297300883712571832834747940136258826265")),
                       scalar_field_value_type(scalar_integral_type(
                           "15184411568310093834440439622297445424213525846570899873835523417076"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp224r1_sha256_range_sign) {
    using curve_type = algebra::curves::secp224r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("25498800374793671048762784949265672262924700173077254356588179904449");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "10285325263507802766229769997721510955259231208172419008156865333178")),
                       scalar_field_value_type(scalar_integral_type(
                           "19851881707228090854079491931555539971691724700028417348239486943489"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "18221028555841736243241666276691572695942301895769495662956393200550")),
                       scalar_field_value_type(scalar_integral_type(
                           "2480305165826971169916584104053072982152540890975025076766131281149"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp224r1_sha384_range_sign) {
    using curve_type = algebra::curves::secp224r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("25498800374793671048762784949265672262924700173077254356588179904449");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("1165580246293624738827861081600383653579740347210398540277340432723")),
                       scalar_field_value_type(scalar_integral_type(
                           "13802165697468181258697693059824076590441960858326479996986944761629"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("5961486901941875763841122371478952078743527293475219720251008290468")),
                       scalar_field_value_type(scalar_integral_type(
                           "6875923273291320048631259169012804475587363487170905841828082588331"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp224r1_sha512_range_sign) {
    using curve_type = algebra::curves::secp224r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("25498800374793671048762784949265672262924700173077254356588179904449");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("768376467299403323419229836392460922793690019298553326354963825559")),
                       scalar_field_value_type(scalar_integral_type(
                           "17356284079411933083889943062626875417095616389095490485068546093188"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("85169086981300973633076620064537412795220981060560574098317708652"),
            base_integral_type("25134849495752264029320115180130970063068156967960389612653206648922")),
        std::make_pair(scalar_field_value_type(
                           scalar_integral_type("486666035563180327796777451122790327000763072859856702671480668540")),
                       scalar_field_value_type(scalar_integral_type(
                           "789304255196425501002033411119287810112806251040682643772145724671"))));
}

// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256r1_sha1_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("91225253027397101270059260515990221874496108017261222445699397644687913215777");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "43966308868060433803164900480198633312455350476969656826750381389126362930482")),
                       scalar_field_value_type(scalar_integral_type(
                           "49526631495840403763193427434860707548628401085039417773265937725198492547051"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "5761304795608484033883999669185686806878981050925767959163454154095436765833")),
                       scalar_field_value_type(scalar_integral_type(
                           "780668371229228211176408935687056773926433288878674321708486731460593875377"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256r1_sha224_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("91225253027397101270059260515990221874496108017261222445699397644687913215777");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "37858231782505497035447955460968542311805164699810948147863210269419772684863")),
                       scalar_field_value_type(scalar_integral_type(
                           "83988333495081693679795465009658025015957451040373275538006319878662941689676"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "88425142680051452890134230489222413421578964016641825261316224085604686931602")),
                       scalar_field_value_type(scalar_integral_type(
                           "90519144895711213315612495722351360799749845891987092840006005346136978722605"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256r1_sha256_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("91225253027397101270059260515990221874496108017261222445699397644687913215777");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "108478302882382504386260635397250479524259298414270181541635698882548524332822")),
                       scalar_field_value_type(scalar_integral_type(
                           "112080140797967428609887221250561337109878063180226093183577605221974133099944"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "109310743016183789158813179180442557552743432958726649231075208249083690189671")),
                       scalar_field_value_type(scalar_integral_type(
                           "733690669868130419205717178732978403087586120777027455044488497843407880323"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256r1_sha384_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("91225253027397101270059260515990221874496108017261222445699397644687913215777");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "6643193222363880480668506208063285599325260201200789895683380644158324569881")),
                       scalar_field_value_type(scalar_integral_type(
                           "32739567653680828342387243083196625468305224550718929259152082716890284427604"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "59509276368341636757008474328238004590080745554329840337598559697691317550774")),
                       scalar_field_value_type(scalar_integral_type(
                           "64164682256057969704412798994377977083315319632255748793344960696549491449644"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256r1_sha512_range_sign) {
    using curve_type = algebra::curves::secp256r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x("91225253027397101270059260515990221874496108017261222445699397644687913215777");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "59971469069124135554338281962456481803975612787885341292769048612138781343488")),
                       scalar_field_value_type(scalar_integral_type(
                           "16005281635503179441256175877112687087264654743915690928249731625490803000062"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("43872280807156713839160376167191808430140484563252114113014272064716834774966"),
            base_integral_type("54736908695619294235531183715189990111299271757105154178488727263331972686489")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "31714159076572323233048040523236018395820409455260983335331650616697588029956")),
                       scalar_field_value_type(scalar_integral_type(
                           "26092128572795394786824874155448392570426641569961121690823539518370146242133"))));
}

// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.6
BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp384r1_sha1_range_sign) {
    using curve_type = algebra::curves::secp384r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "16563344750737000670434776486849190643381365404921930010598574414830758121888225911341090814368865334313953669"
        "606901");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("3639379913437819836951623684626795985743477239569176894677001"
                                                         "6432362932183553482448864743056101127312791116725440178")),
            scalar_field_value_type(scalar_integral_type("2520161528812242800490967724899540129279469533046189465792872"
                                                         "0619360583631433547028768098162011452538644001011835971"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1166101469803426392436531457505637622401738597960261029985136"
                                                         "4375174648463833570781395749164380936413522389438763463")),
            scalar_field_value_type(scalar_integral_type("3288362255423899818576209587788517709104243181963054935165720"
                                                         "3064295421464083612910589094758162575593517871160369794"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp384r1_sha224_range_sign) {
    using curve_type = algebra::curves::secp384r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "16563344750737000670434776486849190643381365404921930010598574414830758121888225911341090814368865334313953669"
        "606901");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1019045417698543818188810937365559695585719982696965312496388"
                                                         "0983550149645651571319902958243128278142834395079639330")),
            scalar_field_value_type(scalar_integral_type("2426117784118011896696557910471091526984332056924815869501460"
                                                         "1587632178367467019446593018313792550361838365075098253"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("3582940489754756702732652878577494849066855771325193024280351"
                                                         "3592816340733634112400683963283497706859829551266532978")),
            scalar_field_value_type(scalar_integral_type("1079872305520380941958160962533570930979602718678641578536558"
                                                         "761193208209568903166452598423936712486031099618224998"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp384r1_sha256_range_sign) {
    using curve_type = algebra::curves::secp384r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "16563344750737000670434776486849190643381365404921930010598574414830758121888225911341090814368865334313953669"
        "606901");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("5185725559126311638054950096150948983859744951806459097663104"
                                                         "607227769695552376194383887370996310881068750528819917")),
            scalar_field_value_type(scalar_integral_type("3750349192763741976187588388295347162133018498723520326333709"
                                                         "3231101455577294203440042242290173284800175433871657648"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("1684273206818688925427105570266839819581697681741510122906629"
                                                         "2307741725886407154022743280411729761358547514026386283")),
            scalar_field_value_type(scalar_integral_type("6968792231003128972190773981285726846499360787495160723721396"
                                                         "468201361288024514859025229701792142280507083936264805"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp384r1_sha384_range_sign) {
    using curve_type = algebra::curves::secp384r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "16563344750737000670434776486849190643381365404921930010598574414830758121888225911341090814368865334313953669"
        "606901");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("2292221613068484608193699704943188472452414863517892541569270"
                                                         "8039676510643442408969596918936763701011754307670425158")),
            scalar_field_value_type(scalar_integral_type("2369272444402450292069241042530424679182396385871438100379675"
                                                         "4679813477336361692558312835173542686467475483893336776"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("2001106294884267595334386976115649949662305304829211834573727"
                                                         "0591289500107882752969036703346739100382407066796434395")),
            scalar_field_value_type(scalar_integral_type("3414034552450934521008025084587101299865496898588043223199897"
                                                         "6450668487468088118988277234951376255814243418226992549"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp384r1_sha512_range_sign) {
    using curve_type = algebra::curves::secp384r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "16563344750737000670434776486849190643381365404921930010598574414830758121888225911341090814368865334313953669"
        "606901");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("3648326057034240725905296396857424217716621473215872658571263"
                                                         "1828119159495940839921940964175207106857761724864608009")),
            scalar_field_value_type(scalar_integral_type("1249382570107161924342944835487064840305646318615387754415937"
                                                         "6515107999164422338578569115433694251040196116689190357"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(base_integral_type("3635877940847328403756764361634383055766588899140286943911938440120190"
                                                "2483390415587565061429479316052157240268864531"),
                             base_integral_type("1971414017733384243053684747272771180085510427954580662948483704369153"
                                                "2359487887290875737957629202174335950650754848")),
        std::make_pair(
            scalar_field_value_type(scalar_integral_type("2475480502783676609590189131533371467278884211930133383581879"
                                                         "5916804263853808414653711300069000630379796271658414711")),
            scalar_field_value_type(scalar_integral_type("2330446803106044632463722825076450590286933718615871834264831"
                                                         "2944628792536135915034375879114025367939346772744849206"))));
}

// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.7
BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp521r1_sha1_range_sign) {
    using curve_type = algebra::curves::secp521r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "33628682625689431580674590939246714484372411275921093887420533149752103196943334385963611019190358345393458392"
        "03587202634055892988122978419130552329975641400");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "7003187545602406611828540991574863703474522327482456086704142649068223197985616886088362067"
                           "61342381911642759418923272829253883612398326354675294936996632413")),
                       scalar_field_value_type(scalar_integral_type(
                           "3106468648790925890212450993317386775269678872472278040495731294486532953174479931261182619"
                           "132934276158682925345288096042223442129255014470816621583929269526"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "4232552805756188941408121987684474354346133454676861847854453428592651169390572523575931336"
                           "486979524466237348972825859537229327945263617768469168980494189415")),
                       scalar_field_value_type(scalar_integral_type(
                           "6566238658318847188595275485990268509551303382607772457578419391817946260444022726412629242"
                           "594941260404290440824025857881970515555896228963849508257561810943"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp521r1_sha224_range_sign) {
    using curve_type = algebra::curves::secp521r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "33628682625689431580674590939246714484372411275921093887420533149752103196943334385963611019190358345393458392"
        "03587202634055892988122978419130552329975641400");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "5033123215280814000018978756177795875968908873513817311883846519150033609011395730532352710"
                           "334392598165856859706421714535427698981073211974001234372435569966")),
                       scalar_field_value_type(scalar_integral_type(
                           "1083273464137123531791785049113918952649776101533465658223540548389454417296258178394119298"
                           "233568364704184483933114295441456685220661728333368971980021478431"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "6112994802643158324373430751327074054632954076382461894863349692507530717425253429485094425"
                           "488309544263639735377225187038767756874262043813572369810604300283")),
                       scalar_field_value_type(scalar_integral_type(
                           "5030620022782239671905730349873382768137737628772695430130907867846365290757391027324054133"
                           "404810838819080861586249590977868668915416266435097439489095965092"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp521r1_sha256_range_sign) {
    using curve_type = algebra::curves::secp521r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "33628682625689431580674590939246714484372411275921093887420533149752103196943334385963611019190358345393458392"
        "03587202634055892988122978419130552329975641400");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "4519882374164933457174231899322760109606620662659329652194746632261743842143075846323441382"
                           "799580678909675179121834327693340745249196987893555130566275883431")),
                       scalar_field_value_type(scalar_integral_type(
                           "9933859266062660246414014396563435943104248437620937983623405914662363669645031832421064516"
                           "88030426950624705418827430221617650927925516057453489348736969980"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "1947856223696987797122918706175027491495138095526254011145221824453369654805815577058243472"
                           "18372143916835871101204704437942560153324888983611062449741327016")),
                       scalar_field_value_type(scalar_integral_type(
                           "2752940254669594762115606708826156881580899834837352041771289401567189996571133410798064828"
                           "846617995861761264165401613356552270925859258470301205228002299526"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp521r1_sha384_range_sign) {
    using curve_type = algebra::curves::secp521r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "33628682625689431580674590939246714484372411275921093887420533149752103196943334385963611019190358345393458392"
        "03587202634055892988122978419130552329975641400");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "6576747890548813377717652726972700878873206507719309310890685678963951305624961527559501052"
                           "274741828737825547651960794202046786603046346930530446716499817553")),
                       scalar_field_value_type(scalar_integral_type(
                           "6678462545041046511325837460897963189979616124713408793341763435148367710687657196910979496"
                           "279328624551514353985130510671286319919247103198579427935912353121"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "4450456376715244046722483547729942388604114650310668163267199165454514631924044909977671106"
                           "192578405217476930632815556268163383363980603381885448734685616012")),
                       scalar_field_value_type(scalar_integral_type(
                           "4118869839240294429231946528447709919360947574782912894986076883518279904923560166008039663"
                           "317909344251184359951692938386377766027721739700502604884588476793"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp521r1_sha512_range_sign) {
    using curve_type = algebra::curves::secp521r1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using base_field_type = typename curve_type::base_field_type;
    using base_integral_type = typename base_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(
        "33628682625689431580674590939246714484372411275921093887420533149752103196943334385963611019190358345393458392"
        "03587202634055892988122978419130552329975641400");

    rfc6979_test<policy_type>(
        x,
        std::string("sample"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "2616668865037847359764487575100438577325942475514124480719493918855393095132132939138306228"
                           "439666967838913768987139826338892905255219889531004924840722528250")),
                       scalar_field_value_type(scalar_integral_type(
                           "1307094020936265499909856128231496113828887875252684744662287059401922448998079760457277792"
                           "799191920615129128596654866022976991839693773920569768689002653306"))));

    rfc6979_test<policy_type>(
        x,
        std::string("test"),
        g1_affine_value_type(
            base_integral_type("527289887325416183352038603263212582040805099042785233403262577107383712647937075458553"
                               "3841949303898691579347587217756566381748347606781708996710934768526244"),
            base_integral_type("981336682650441434433392812988969377633861760505881551958985841807005894970975628490028"
                               "680616384008883562991808313344385252341730921374456475975352693161205")),
        std::make_pair(scalar_field_value_type(scalar_integral_type(
                           "4271696599692765118998818751535411151554887569851842219557645590522680577076054588544755820"
                           "629030529801123305080906866937724047783052337678044170729172758125")),
                       scalar_field_value_type(scalar_integral_type(
                           "6808652717283396281165522952348291500534484668871402145262894150892031409108493536052527825"
                           "277568626101230857924285609597213277851581046658400441778640837859"))));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256k1_sha1_range_sign) {
    using curve_type = algebra::curves::secp256k1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using hash_type = hashes::sha1;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721_cppui256);

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("sample"),
        std::make_pair(scalar_field_value_type(
                           0x432D36AD7C15F289D193D233332B4192EC52182354661263962826D8D53BC7E8_cppui256),
                       scalar_field_value_type(
                           0xEB08245738BC9F49419A4EE58EBEB045A7824A61C7CDCE7007EC2C490ECFB34B_cppui256)));

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("test"),
        std::make_pair(scalar_field_value_type(
                           0x5A218C384E45F833F32D8B1DB49B4300B786D6C39DA00C59427287A72D186935_cppui256),
                       scalar_field_value_type(
                           0xF7722F896A737B0B4397A5074C67F6154B063D58B58E4628322716E974CEAF40_cppui256)));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256k1_sha224_range_sign) {
    using curve_type = algebra::curves::secp256k1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using hash_type = hashes::sha2<224>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721_cppui256);

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("sample"),
        std::make_pair(scalar_field_value_type(
                           0xEFE22812AEE54594AD645AC904F792A7B78DE889CDB203D45B0AD38E91877EA0_cppui256),
                       scalar_field_value_type(
                           0xE66176D972070CF93CFFFF669DAF62F72E4F169CAFCAE3152677C523D1C1EF39_cppui256)));

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("test"),
        std::make_pair(scalar_field_value_type(
                           0x242670EB1D4D272FEC08D78B2F817CB38E2DEE1F721C338D2A71D1E2921F4DC2_cppui256),
                       scalar_field_value_type(
                           0x84CDF656B5F7F8E6F93E83B325C556D2F49EBFA9ACAF4A6C8CE338B5E3E0449C_cppui256)));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256k1_sha256_range_sign) {
    using curve_type = algebra::curves::secp256k1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using hash_type = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721_cppui256);

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("sample"),
        std::make_pair(scalar_field_value_type(
                           0x432310E32CB80EB6503A26CE83CC165C783B870845FB8AAD6D970889FCD7A6C8_cppui256),
                       scalar_field_value_type(
                           0x530128B6B81C548874A6305D93ED071CA6E05074D85863D4056CE89B02BFAB69_cppui256)));

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("test"),
        std::make_pair(scalar_field_value_type(
                           0xF2ADCEA7139057BE6409855EE96D008E0E5B5F532333EC17448E26A36F47BCB2_cppui256),
                       scalar_field_value_type(
                           0x570C9D342779B40F513C0D75CBF93E3F3DE7B01F6593F17BFC2EE87151414D64_cppui256)));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256k1_sha384_range_sign) {
    using curve_type = algebra::curves::secp256k1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using hash_type = hashes::sha2<384>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721_cppui256);

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("sample"),
        std::make_pair(scalar_field_value_type(
                           0x16217648FC2AB9E82F4BC6304D6F7AE0E3C5728F75786BA13F258CF02D971D44_cppui256),
                       scalar_field_value_type(
                           0x899372870C08982344E4392ED218220E0B01E96F18425A2A4F2F74B0F6F57ABC_cppui256)));

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("test"),
        std::make_pair(scalar_field_value_type(
                           0xCA8D3ACA176FFA260E78ADA8736EC9EDD2A49D1A1C6686358120812145A7020F_cppui256),
                       scalar_field_value_type(
                           0xB6CE10567BDD40BDEB48EBCF87B1F82EE3A0EA15FAA7513FB815AD7403873A7E_cppui256)));
}

BOOST_AUTO_TEST_CASE(ecdsa_rfc6979_secp256k1_sha512_range_sign) {
    using curve_type = algebra::curves::secp256k1;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using scalar_integral_type = typename scalar_field_type::integral_type;
    using hash_type = hashes::sha2<512>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>;
    using policy_type = pubkey::ecdsa<curve_type, padding_policy, generator_type>;

    using g1_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using g1_affine_value_type = typename g1_affine_type::value_type;

    scalar_integral_type x(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721_cppui256);

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("sample"),
        std::make_pair(scalar_field_value_type(
                           0x12AF6086A07A3347920DDB0C997918077FA90EC44AD7939E051D9C76F010B0EF_cppui256),
                       scalar_field_value_type(
                           0x00559F7289748A2C6EBE6501F2BEF64E5CE94FF89C90B0DB22F5E3E01F88CC04_cppui256)));

    rfc6979_test_wo_pk_check<policy_type>(
        x,
        std::string("test"),
        std::make_pair(scalar_field_value_type(
                           0x2AAED0E23C13F46ADFF7820B5C61F2692645AA9FADCEB3D05297A2D33790DD5A_cppui256),
                       scalar_field_value_type(
                           0x9B24785EEAFFEF0B188A3D0B65B6322495B0311FCC90FEF5331AEB5B10AAA6E4_cppui256)));
}


BOOST_AUTO_TEST_SUITE_END()
