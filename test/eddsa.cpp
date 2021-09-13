//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE eddsa_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>

// #include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>

#include <nil/crypto3/pkpad/emsa/emsa1.hpp>

#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::marshalling;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename CurveGroupElement>
void print_fp_projective_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.Z.data << " )" << std::endl;
}

template<typename CurveGroupElement>
void print_fp_extended_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " : " << e.T.data << " : " << e.Z.data << " )"
       << std::endl;
}

template<typename CurveGroupElement>
void print_fp_affine_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "( " << e.X.data << " : " << e.Y.data << " )" << std::endl;
}

template<typename CurveGroupElement>
void print_fp2_projective_curve_group_element(std::ostream &os, const CurveGroupElement &e) {
    os << std::hex << "(" << e.X.data[0].data << " , " << e.X.data[1].data << ") : (" << e.Y.data[0].data << " , "
       << e.Y.data[1].data << ") : (" << e.Z.data[0].data << " , " << e.Z.data[1].data << ")" << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::twisted_edwards,
                                                                 curves::coordinates::extended_with_a_minus_1>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::twisted_edwards,
                                                              curves::coordinates::extended_with_a_minus_1> const &p) {
                    print_fp_extended_curve_group_element(os, p);
                }
            };

            template<typename CurveParams>
            struct print_log_value<curves::detail::curve_element<CurveParams,
                                                                 curves::forms::twisted_edwards,
                                                                 curves::coordinates::affine>> {
                void operator()(std::ostream &os,
                                curves::detail::curve_element<CurveParams,
                                                              curves::forms::twisted_edwards,
                                                              curves::coordinates::affine> const &p) {
                    print_fp_affine_curve_group_element(os, p);
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

BOOST_AUTO_TEST_SUITE(eddsa_manual_test_suite)

BOOST_AUTO_TEST_CASE(eddsa_conformity_test) {
    using curve_type = algebra::curves::curve25519;
    using group_type = typename curve_type::g1_type<>;
    using group_affine_type = typename curve_type::g1_type<curves::coordinates::affine>;
    using group_value_type = typename group_type::value_type;
    using group_affine_value_type = typename group_affine_type::value_type;
    using group_marshalling_type = group_element_serializer<group_type>;
    using base_field_type = typename group_type::params_type::base_field_type;
    using base_field_value_type = typename base_field_type::value_type;
    using base_integral_type = typename base_field_type::integral_type;

    auto encoded_point = group_marshalling_type::encode(group_value_type::one());

    for (auto c : encoded_point) {
        std::cout << c;
    } std::cout << std::endl;

    auto decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(group_value_type::one(), decoded_point);

    auto etalon_p0 = group_affine_value_type(base_integral_type("55143357684131188911077184997315609937704070614065852119589407129175795184871"),base_integral_type("279690604211431380350300621839030451597928240890723285720074998306105318895")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc0 = {
        239 ,221 ,137 ,198 ,167 ,211 ,247 ,81 ,190 ,82 ,3 ,159 ,87 ,80 ,160 ,185 ,237 ,143 ,225 ,242 ,231 ,236 ,222 ,80 ,32 ,99 ,36 ,24 ,157 ,76 ,158 ,128 ,};
    encoded_point = group_marshalling_type::encode(etalon_p0);
    BOOST_CHECK(etalon_p_enc0 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p0, decoded_point);

    auto etalon_p1 = group_affine_value_type(base_integral_type("11548370060999914546752838820613118927380875969607902678064652086070939840280"),base_integral_type("25080318020127322474660258407325510186473053591971807465547223221049410369752")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc1 = {
        216 ,184 ,202 ,230 ,42 ,167 ,213 ,212 ,159 ,70 ,19 ,25 ,5 ,171 ,160 ,177 ,144 ,238 ,236 ,173 ,178 ,50 ,2 ,124 ,233 ,186 ,81 ,157 ,250 ,244 ,114 ,55 ,};
    encoded_point = group_marshalling_type::encode(etalon_p1);
    BOOST_CHECK(etalon_p_enc1 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p1, decoded_point);

    auto etalon_p2 = group_affine_value_type(base_integral_type("55947610214747294403331267218170697915180877928897917514775980308425583661877"),base_integral_type("56387249255332090520934037859617767414109336800266065371460292887929494934542")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc2 = {
        14 ,148 ,27 ,127 ,46 ,70 ,243 ,188 ,87 ,48 ,29 ,67 ,143 ,109 ,24 ,19 ,221 ,213 ,170 ,58 ,118 ,38 ,56 ,176 ,130 ,180 ,12 ,149 ,85 ,13 ,170 ,252 ,};
    encoded_point = group_marshalling_type::encode(etalon_p2);
    BOOST_CHECK(etalon_p_enc2 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p2, decoded_point);

    auto etalon_p3 = group_affine_value_type(base_integral_type("39206714666651466055479712817663497205024663580712435901658531807242435231557"),base_integral_type("20887695811637204528997916437856580725875316769599170209444686404546930332326")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc3 = {
        166 ,210 ,14 ,140 ,239 ,188 ,64 ,163 ,117 ,56 ,38 ,230 ,130 ,55 ,143 ,111 ,41 ,186 ,216 ,136 ,21 ,48 ,202 ,100 ,107 ,106 ,57 ,200 ,81 ,4 ,46 ,174 ,};
    encoded_point = group_marshalling_type::encode(etalon_p3);
    BOOST_CHECK(etalon_p_enc3 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p3, decoded_point);

    auto etalon_p4 = group_affine_value_type(base_integral_type("19088796276937121954595745886271719449604380833409493733958359261084016340880"),base_integral_type("51386466478073825788015524081832509241666663755956722328794212271077074956246")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc4 = {
        214 ,111 ,76 ,28 ,169 ,78 ,222 ,185 ,13 ,25 ,22 ,132 ,107 ,52 ,186 ,127 ,225 ,181 ,29 ,75 ,92 ,227 ,80 ,184 ,73 ,211 ,195 ,57 ,151 ,181 ,155 ,113 ,};
    encoded_point = group_marshalling_type::encode(etalon_p4);
    BOOST_CHECK(etalon_p_enc4 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p4, decoded_point);

    auto etalon_p5 = group_affine_value_type(base_integral_type("49558956527115544728673414829529650295748384084102261501394433460787208387479"),base_integral_type("22271664850629264704459436750128974789208844582649476509109576182200733696974")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc5 = {
        206 ,131 ,86 ,150 ,215 ,200 ,118 ,139 ,133 ,28 ,103 ,6 ,114 ,172 ,200 ,145 ,72 ,59 ,200 ,118 ,213 ,41 ,255 ,82 ,174 ,233 ,1 ,128 ,202 ,80 ,61 ,177 ,};
    encoded_point = group_marshalling_type::encode(etalon_p5);
    BOOST_CHECK(etalon_p_enc5 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p5, decoded_point);

    auto etalon_p6 = group_affine_value_type(base_integral_type("11504516691809330554663548860830952622900343387149852666614538102882844360805"),base_integral_type("4989046253565769627862437272509341680100268176271483447363605323193251107035")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc6 = {
        219 ,144 ,53 ,35 ,15 ,6 ,72 ,208 ,14 ,4 ,36 ,144 ,55 ,165 ,199 ,166 ,208 ,63 ,172 ,32 ,242 ,241 ,97 ,182 ,151 ,127 ,118 ,127 ,58 ,179 ,7 ,139 ,};
    encoded_point = group_marshalling_type::encode(etalon_p6);
    BOOST_CHECK(etalon_p_enc6 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p6, decoded_point);

    auto etalon_p7 = group_affine_value_type(base_integral_type("50236832234614375899340890281691414709644138768640891508605003830598024319020"),base_integral_type("37174760652758728142265802921260240760940631446630805640629572183332247071909")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc7 = {
        165 ,108 ,176 ,22 ,108 ,31 ,214 ,213 ,124 ,119 ,124 ,210 ,34 ,99 ,170 ,53 ,108 ,103 ,166 ,235 ,163 ,11 ,144 ,116 ,109 ,31 ,173 ,162 ,60 ,43 ,48 ,82 ,};
    encoded_point = group_marshalling_type::encode(etalon_p7);
    BOOST_CHECK(etalon_p_enc7 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p7, decoded_point);

    auto etalon_p8 = group_affine_value_type(base_integral_type("25460672800405340374615259510316593615596685754459369809707344943856751523077"),base_integral_type("30241165004921947024834567953194130900171132423211980884565933619917557113242")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc8 = {
        154 ,161 ,108 ,209 ,234 ,204 ,185 ,96 ,132 ,220 ,234 ,161 ,42 ,154 ,170 ,157 ,186 ,241 ,213 ,41 ,100 ,189 ,124 ,167 ,127 ,210 ,239 ,102 ,144 ,228 ,219 ,194 ,};
    encoded_point = group_marshalling_type::encode(etalon_p8);
    BOOST_CHECK(etalon_p_enc8 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p8, decoded_point);

    auto etalon_p9 = group_affine_value_type(base_integral_type("12759720185415946975898435177791892140537559034877889193497368757802412157922"),base_integral_type("41899732108645672677751688394229437645236799595047376256984805517656060772171")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc9 = {
        75 ,191 ,46 ,46 ,144 ,89 ,29 ,131 ,140 ,206 ,119 ,5 ,23 ,241 ,31 ,238 ,47 ,153 ,162 ,143 ,47 ,93 ,234 ,70 ,43 ,1 ,213 ,126 ,112 ,104 ,162 ,92 ,};
    encoded_point = group_marshalling_type::encode(etalon_p9);
    BOOST_CHECK(etalon_p_enc9 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p9, decoded_point);

    auto etalon_p10 = group_affine_value_type(base_integral_type("19373691719464504846895828888971673720856288437177269768877492440627421525528"),base_integral_type("7757314792468670381141794510487304586378496397217074546335588862031714912114")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc10 = {
        114 ,7 ,49 ,45 ,153 ,10 ,101 ,134 ,46 ,62 ,222 ,222 ,114 ,68 ,83 ,50 ,181 ,70 ,113 ,97 ,125 ,76 ,44 ,77 ,195 ,36 ,18 ,105 ,13 ,124 ,38 ,17 ,};
    encoded_point = group_marshalling_type::encode(etalon_p10);
    BOOST_CHECK(etalon_p_enc10 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p10, decoded_point);

    auto etalon_p11 = group_affine_value_type(base_integral_type("8398929898501443569978677660843852828407029394799561137284461146663688242661"),base_integral_type("30489424304182467931104386630206218092853749912178154109148122898896155293005")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc11 = {
        77 ,181 ,143 ,210 ,99 ,155 ,183 ,240 ,140 ,219 ,202 ,236 ,227 ,198 ,244 ,5 ,85 ,238 ,137 ,121 ,5 ,139 ,68 ,88 ,200 ,118 ,148 ,153 ,17 ,103 ,104 ,195 ,};
    encoded_point = group_marshalling_type::encode(etalon_p11);
    BOOST_CHECK(etalon_p_enc11 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p11, decoded_point);

    auto etalon_p12 = group_affine_value_type(base_integral_type("34655773085900112115894596893054151604916269457181836612616824820869399642803"),base_integral_type("27775390656605663889680963798608895781490515804426397153851078012995930033408")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc12 = {
        0 ,13 ,82 ,74 ,171 ,90 ,185 ,197 ,104 ,44 ,66 ,101 ,253 ,3 ,127 ,17 ,175 ,141 ,198 ,110 ,211 ,95 ,26 ,186 ,119 ,41 ,190 ,156 ,98 ,80 ,104 ,189 ,};
    encoded_point = group_marshalling_type::encode(etalon_p12);
    BOOST_CHECK(etalon_p_enc12 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p12, decoded_point);

    auto etalon_p13 = group_affine_value_type(base_integral_type("42674832485763503504314735556365906100392370681327501690039904700918960640287"),base_integral_type("52986822020107985811348187035613183891587017802683726901151350006369670886619")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc13 = {
        219 ,116 ,119 ,168 ,108 ,107 ,63 ,226 ,111 ,42 ,90 ,19 ,249 ,105 ,89 ,1 ,202 ,188 ,142 ,94 ,88 ,45 ,54 ,42 ,237 ,211 ,115 ,108 ,125 ,122 ,37 ,245 ,};
    encoded_point = group_marshalling_type::encode(etalon_p13);
    BOOST_CHECK(etalon_p_enc13 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p13, decoded_point);

    auto etalon_p14 = group_affine_value_type(base_integral_type("30164109159819525862171009078871429513183351860043828289627561292344200087256"),base_integral_type("27734203217199925713086168272956549739400561095498546560662356418664318922790")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc14 = {
        38 ,112 ,164 ,82 ,241 ,218 ,18 ,233 ,107 ,80 ,135 ,59 ,161 ,108 ,187 ,147 ,252 ,107 ,249 ,151 ,38 ,156 ,17 ,26 ,153 ,92 ,151 ,147 ,179 ,0 ,81 ,61 ,};
    encoded_point = group_marshalling_type::encode(etalon_p14);
    BOOST_CHECK(etalon_p_enc14 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p14, decoded_point);

    auto etalon_p15 = group_affine_value_type(base_integral_type("11195397773697346911275560820271824076730929415339555092859006042936907812051"),base_integral_type("55548196080284222982127640051824452960310173380627780576088595253703441539884")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc15 = {
        44 ,99 ,62 ,31 ,25 ,67 ,186 ,78 ,202 ,49 ,154 ,102 ,68 ,252 ,155 ,1 ,220 ,23 ,107 ,208 ,20 ,192 ,92 ,241 ,166 ,118 ,22 ,155 ,49 ,42 ,207 ,250 ,};
    encoded_point = group_marshalling_type::encode(etalon_p15);
    BOOST_CHECK(etalon_p_enc15 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p15, decoded_point);

    auto etalon_p16 = group_affine_value_type(base_integral_type("3823299981975897870814625664631599083353205722347082738609047897438042502952"),base_integral_type("51543880973030102434938184443372684137330737551114844303281570569282660247396")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc16 = {
        100 ,167 ,218 ,108 ,202 ,52 ,47 ,156 ,29 ,8 ,240 ,45 ,47 ,29 ,19 ,158 ,40 ,162 ,174 ,231 ,55 ,32 ,218 ,9 ,207 ,109 ,201 ,90 ,131 ,205 ,244 ,113 ,};
    encoded_point = group_marshalling_type::encode(etalon_p16);
    BOOST_CHECK(etalon_p_enc16 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p16, decoded_point);

    auto etalon_p17 = group_affine_value_type(base_integral_type("16684653444477894846178914738360775312098433595923683606808126559517838318199"),base_integral_type("54039233942743235521185298155804713627245819766717102093898672820832649608564")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc17 = {
        116 ,253 ,119 ,2 ,12 ,233 ,133 ,235 ,128 ,212 ,166 ,166 ,201 ,32 ,140 ,229 ,134 ,80 ,96 ,38 ,235 ,224 ,140 ,86 ,156 ,225 ,71 ,48 ,93 ,31 ,121 ,247 ,};
    encoded_point = group_marshalling_type::encode(etalon_p17);
    BOOST_CHECK(etalon_p_enc17 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p17, decoded_point);

    auto etalon_p18 = group_affine_value_type(base_integral_type("52717939082107420210843151732703295625395422065296886978536076856420054693060"),base_integral_type("54032395725994807898034024451713873550217506395918611123204270285038081730315")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc18 = {
        11 ,231 ,134 ,176 ,94 ,35 ,159 ,165 ,143 ,160 ,15 ,178 ,96 ,0 ,158 ,181 ,218 ,147 ,76 ,104 ,63 ,239 ,80 ,194 ,129 ,202 ,226 ,161 ,145 ,64 ,117 ,119 ,};
    encoded_point = group_marshalling_type::encode(etalon_p18);
    BOOST_CHECK(etalon_p_enc18 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p18, decoded_point);

    auto etalon_p19 = group_affine_value_type(base_integral_type("37747011096658897845878877095191910257806665130888228632775404680810881169685"),base_integral_type("36983331054487147972556455634736141199493396693190852730168791005692654351295")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc19 = {
        191 ,115 ,217 ,127 ,150 ,217 ,117 ,74 ,106 ,216 ,175 ,93 ,126 ,255 ,0 ,248 ,229 ,200 ,17 ,96 ,153 ,65 ,199 ,225 ,1 ,177 ,190 ,51 ,214 ,210 ,195 ,209 ,};
    encoded_point = group_marshalling_type::encode(etalon_p19);
    BOOST_CHECK(etalon_p_enc19 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p19, decoded_point);

    auto etalon_p20 = group_affine_value_type(base_integral_type("19934769211783768259674437353701860121384340662869719512929924416461750171413"),base_integral_type("7619839763397220596267554598424446329793845568605117327176303285364600700303")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc20 = {
        143 ,125 ,185 ,246 ,11 ,67 ,82 ,242 ,0 ,160 ,158 ,215 ,91 ,235 ,131 ,9 ,64 ,30 ,78 ,176 ,234 ,180 ,197 ,231 ,25 ,49 ,44 ,45 ,45 ,173 ,216 ,144 ,};
    encoded_point = group_marshalling_type::encode(etalon_p20);
    BOOST_CHECK(etalon_p_enc20 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p20, decoded_point);

    auto etalon_p21 = group_affine_value_type(base_integral_type("53089103139003605563331092398524872604365970730130482921443924854160862514528"),base_integral_type("55022667531971805108459695147993839493385601644031769521030016767120541916012")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc21 = {
        108 ,155 ,38 ,226 ,222 ,162 ,195 ,205 ,1 ,200 ,43 ,89 ,34 ,42 ,151 ,222 ,181 ,1 ,155 ,208 ,46 ,197 ,232 ,29 ,76 ,162 ,65 ,94 ,232 ,185 ,165 ,121 ,};
    encoded_point = group_marshalling_type::encode(etalon_p21);
    BOOST_CHECK(etalon_p_enc21 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p21, decoded_point);

    auto etalon_p22 = group_affine_value_type(base_integral_type("52154728765153785983017196421168424015324992574386814544552480901403286904613"),base_integral_type("3134726546419235467036611486373376172815782392711414891970307697782084077068")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc22 = {
        12 ,6 ,20 ,117 ,135 ,184 ,74 ,73 ,237 ,156 ,24 ,42 ,70 ,53 ,147 ,151 ,82 ,141 ,75 ,248 ,64 ,69 ,173 ,160 ,146 ,155 ,244 ,221 ,61 ,49 ,238 ,134 ,};
    encoded_point = group_marshalling_type::encode(etalon_p22);
    BOOST_CHECK(etalon_p_enc22 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p22, decoded_point);

    auto etalon_p23 = group_affine_value_type(base_integral_type("11622488888619288613031019661031099278029829238582393770315829246728645538231"),base_integral_type("4569687899158677450312834041069302693244297806306248061184892940551544140532")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc23 = {
        244 ,114 ,84 ,128 ,218 ,110 ,253 ,72 ,188 ,41 ,126 ,163 ,26 ,104 ,196 ,107 ,124 ,139 ,58 ,210 ,51 ,126 ,31 ,233 ,103 ,163 ,112 ,159 ,8 ,90 ,26 ,138 ,};
    encoded_point = group_marshalling_type::encode(etalon_p23);
    BOOST_CHECK(etalon_p_enc23 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p23, decoded_point);

    auto etalon_p24 = group_affine_value_type(base_integral_type("55051316064537203361128309614721839030181480841500242054382095792807194182157"),base_integral_type("22237117243651084718566547145648604730726190684353054681931212158850571144287")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc24 = {
        95 ,140 ,139 ,146 ,219 ,109 ,232 ,249 ,247 ,55 ,212 ,147 ,144 ,144 ,231 ,160 ,101 ,128 ,75 ,121 ,12 ,50 ,25 ,128 ,14 ,6 ,126 ,137 ,40 ,195 ,41 ,177 ,};
    encoded_point = group_marshalling_type::encode(etalon_p24);
    BOOST_CHECK(etalon_p_enc24 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p24, decoded_point);

    auto etalon_p25 = group_affine_value_type(base_integral_type("27888019544144847542598115397925431679078005285939305581788671123336561449555"),base_integral_type("36415796522444871975441182732100554119484421658668695383819170566905381714837")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc25 = {
        149 ,251 ,2 ,235 ,210 ,128 ,50 ,187 ,129 ,2 ,142 ,206 ,184 ,202 ,162 ,235 ,1 ,4 ,4 ,253 ,191 ,93 ,35 ,172 ,73 ,235 ,173 ,110 ,68 ,156 ,130 ,208 ,};
    encoded_point = group_marshalling_type::encode(etalon_p25);
    BOOST_CHECK(etalon_p_enc25 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p25, decoded_point);

    auto etalon_p26 = group_affine_value_type(base_integral_type("25886510352497528412309956952929324512296048319539657423016283476206045090492"),base_integral_type("41812597710036278027399358997092481894103240638606977729122822012882604631994")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc26 = {
        186 ,167 ,185 ,104 ,29 ,47 ,198 ,142 ,25 ,222 ,244 ,61 ,165 ,132 ,128 ,237 ,42 ,71 ,7 ,162 ,231 ,209 ,231 ,183 ,157 ,186 ,217 ,5 ,118 ,23 ,113 ,92 ,};
    encoded_point = group_marshalling_type::encode(etalon_p26);
    BOOST_CHECK(etalon_p_enc26 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p26, decoded_point);

    auto etalon_p27 = group_affine_value_type(base_integral_type("9502132550989194861085912610626707007979840370732130876557533727721552472262"),base_integral_type("43914241115992923795970739987510625310219149772384640021654373164852421952995")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc27 = {
        227 ,133 ,221 ,43 ,255 ,21 ,223 ,62 ,143 ,188 ,185 ,143 ,103 ,239 ,49 ,86 ,29 ,211 ,241 ,70 ,224 ,66 ,171 ,61 ,214 ,139 ,138 ,128 ,100 ,148 ,22 ,97 ,};
    encoded_point = group_marshalling_type::encode(etalon_p27);
    BOOST_CHECK(etalon_p_enc27 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p27, decoded_point);

    auto etalon_p28 = group_affine_value_type(base_integral_type("51386205990651444443569467969414911753752630362115754364911711770449894950591"),base_integral_type("28401300196157755407997818103903958941286086357062418443522500933797382431652")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc28 = {
        164 ,163 ,191 ,91 ,134 ,52 ,141 ,87 ,236 ,199 ,157 ,204 ,84 ,209 ,120 ,48 ,50 ,62 ,100 ,221 ,90 ,41 ,43 ,50 ,70 ,235 ,70 ,192 ,245 ,144 ,202 ,190 ,};
    encoded_point = group_marshalling_type::encode(etalon_p28);
    BOOST_CHECK(etalon_p_enc28 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p28, decoded_point);

    auto etalon_p29 = group_affine_value_type(base_integral_type("57570219014487711980916600214067531181174137094070947197041514595837846226256"),base_integral_type("8907930884321255872188646780206523563782005100003782365754947774080041301390")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc29 = {
        142 ,53 ,215 ,12 ,110 ,235 ,131 ,41 ,95 ,212 ,76 ,105 ,113 ,61 ,44 ,147 ,206 ,45 ,0 ,105 ,43 ,236 ,123 ,117 ,150 ,84 ,158 ,66 ,208 ,181 ,177 ,19 ,};
    encoded_point = group_marshalling_type::encode(etalon_p29);
    BOOST_CHECK(etalon_p_enc29 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p29, decoded_point);

    auto etalon_p30 = group_affine_value_type(base_integral_type("3366147587089124158729579029566479620532565958599100739053494065941688946599"),base_integral_type("37470858122109458229153002430993901992209530609920066264949543593148240536992")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc30 = {
        160 ,165 ,234 ,51 ,75 ,252 ,121 ,28 ,35 ,161 ,240 ,221 ,206 ,227 ,50 ,60 ,17 ,15 ,20 ,110 ,126 ,224 ,15 ,50 ,224 ,128 ,62 ,46 ,14 ,193 ,215 ,210 ,};
    encoded_point = group_marshalling_type::encode(etalon_p30);
    BOOST_CHECK(etalon_p_enc30 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p30, decoded_point);

    auto etalon_p31 = group_affine_value_type(base_integral_type("19348054028973758008638931427677933577191262739840017146791450008332569503829"),base_integral_type("12290257452194873777349411034545312247918004928709925491705486759805260121790")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc31 = {
        190 ,198 ,187 ,255 ,53 ,150 ,139 ,201 ,150 ,111 ,86 ,247 ,119 ,219 ,61 ,114 ,180 ,27 ,39 ,91 ,5 ,185 ,127 ,132 ,255 ,72 ,37 ,90 ,9 ,10 ,44 ,155 ,};
    encoded_point = group_marshalling_type::encode(etalon_p31);
    BOOST_CHECK(etalon_p_enc31 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p31, decoded_point);

    auto etalon_p32 = group_affine_value_type(base_integral_type("19913656950996572210130878368510482925545726101042400326967061578027260591301"),base_integral_type("42579826378237747346728727909546469050628257274476163089319788426287750022884")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc32 = {
        228 ,134 ,39 ,107 ,191 ,35 ,170 ,215 ,72 ,45 ,116 ,44 ,130 ,127 ,63 ,44 ,109 ,46 ,148 ,170 ,186 ,85 ,4 ,57 ,165 ,34 ,63 ,249 ,226 ,83 ,35 ,222 ,};
    encoded_point = group_marshalling_type::encode(etalon_p32);
    BOOST_CHECK(etalon_p_enc32 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p32, decoded_point);

    auto etalon_p33 = group_affine_value_type(base_integral_type("33164128417239844863383348117922262153320731538090487430130333004600949200666"),base_integral_type("22832323696362039234474625570019397087207300463488873284894958465131191532549")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc33 = {
        5 ,252 ,252 ,251 ,32 ,178 ,54 ,156 ,99 ,236 ,187 ,140 ,49 ,44 ,34 ,182 ,74 ,45 ,236 ,190 ,199 ,70 ,244 ,136 ,145 ,42 ,236 ,227 ,34 ,163 ,122 ,50 ,};
    encoded_point = group_marshalling_type::encode(etalon_p33);
    BOOST_CHECK(etalon_p_enc33 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p33, decoded_point);

    auto etalon_p34 = group_affine_value_type(base_integral_type("17971765709625172913273956299871631600569804998592570670730676017516718777954"),base_integral_type("1057380055739717162026705603368991140671013535994040130428438629099219875195")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc34 = {
        123 ,117 ,150 ,31 ,74 ,160 ,166 ,3 ,209 ,223 ,84 ,87 ,123 ,228 ,84 ,241 ,86 ,10 ,221 ,217 ,128 ,186 ,255 ,212 ,140 ,176 ,74 ,16 ,182 ,116 ,86 ,2 ,};
    encoded_point = group_marshalling_type::encode(etalon_p34);
    BOOST_CHECK(etalon_p_enc34 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p34, decoded_point);

    auto etalon_p35 = group_affine_value_type(base_integral_type("20551201203641986689390102459009100970027009889993278079172212354880833802548"),base_integral_type("4895379866854050383222605664865249444336929509610727265190107260407760624109")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc35 = {
        237 ,25 ,225 ,189 ,239 ,172 ,155 ,20 ,152 ,212 ,169 ,106 ,115 ,59 ,244 ,204 ,223 ,184 ,97 ,201 ,12 ,235 ,164 ,86 ,185 ,243 ,240 ,30 ,211 ,175 ,210 ,10 ,};
    encoded_point = group_marshalling_type::encode(etalon_p35);
    BOOST_CHECK(etalon_p_enc35 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p35, decoded_point);

    auto etalon_p36 = group_affine_value_type(base_integral_type("25811766636285494688143678422931792083197589926804943368670070722069096681421"),base_integral_type("1800878332464757936299966844999391050715044373981233297139808301477867753980")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc36 = {
        252 ,17 ,167 ,87 ,104 ,116 ,105 ,30 ,105 ,254 ,233 ,154 ,241 ,65 ,164 ,86 ,205 ,26 ,9 ,247 ,144 ,131 ,254 ,170 ,131 ,64 ,202 ,223 ,209 ,66 ,251 ,131 ,};
    encoded_point = group_marshalling_type::encode(etalon_p36);
    BOOST_CHECK(etalon_p_enc36 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p36, decoded_point);

    auto etalon_p37 = group_affine_value_type(base_integral_type("42132051533214669641819664076607112406328237240211095707634490015655299282389"),base_integral_type("38003257035018595469334560918042645798606493691374292070643021826159134235111")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc37 = {
        231 ,217 ,237 ,81 ,146 ,108 ,251 ,127 ,154 ,198 ,244 ,141 ,57 ,100 ,93 ,116 ,215 ,89 ,45 ,207 ,30 ,49 ,218 ,142 ,82 ,175 ,138 ,103 ,203 ,20 ,5 ,212 ,};
    encoded_point = group_marshalling_type::encode(etalon_p37);
    BOOST_CHECK(etalon_p_enc37 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p37, decoded_point);

    auto etalon_p38 = group_affine_value_type(base_integral_type("24306828754206841080914933957240024950475094368163562035160047483716174899299"),base_integral_type("415241823029793235503292958127227666203224583678819124834977536204730176081")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc38 = {
        81 ,146 ,78 ,42 ,143 ,182 ,53 ,94 ,101 ,132 ,142 ,244 ,170 ,73 ,216 ,12 ,29 ,203 ,113 ,55 ,151 ,118 ,203 ,11 ,148 ,195 ,115 ,61 ,191 ,4 ,235 ,128 ,};
    encoded_point = group_marshalling_type::encode(etalon_p38);
    BOOST_CHECK(etalon_p_enc38 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p38, decoded_point);

    auto etalon_p39 = group_affine_value_type(base_integral_type("45650677719294588486233328945106656733378823134505470476317576180481642604875"),base_integral_type("55220914211055206916761462378327266792474234889592184183937601571983749958530")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc39 = {
        130 ,75 ,162 ,119 ,106 ,207 ,171 ,78 ,221 ,12 ,237 ,67 ,21 ,147 ,3 ,6 ,250 ,200 ,134 ,228 ,120 ,111 ,26 ,10 ,186 ,94 ,221 ,97 ,10 ,238 ,21 ,250 ,};
    encoded_point = group_marshalling_type::encode(etalon_p39);
    BOOST_CHECK(etalon_p_enc39 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p39, decoded_point);

    auto etalon_p40 = group_affine_value_type(base_integral_type("49089596841472601731206983055589126660114256585550963647864018166082704255808"),base_integral_type("3940879141837686680055619081300514536989371865693490823989008286401236127893")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc40 = {
        149 ,80 ,217 ,245 ,34 ,8 ,214 ,185 ,6 ,215 ,24 ,216 ,123 ,184 ,162 ,150 ,31 ,5 ,91 ,127 ,230 ,215 ,254 ,19 ,242 ,230 ,43 ,133 ,99 ,117 ,182 ,8 ,};
    encoded_point = group_marshalling_type::encode(etalon_p40);
    BOOST_CHECK(etalon_p_enc40 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p40, decoded_point);

    auto etalon_p41 = group_affine_value_type(base_integral_type("46423234342100305938324001016457507723257190579400044728119836692862503936743"),base_integral_type("20675256311987808362698823314974551444168173470357281666713110864985991100926")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc41 = {
        254 ,57 ,203 ,46 ,89 ,202 ,88 ,190 ,207 ,186 ,70 ,196 ,192 ,172 ,28 ,90 ,187 ,103 ,104 ,152 ,84 ,96 ,192 ,253 ,132 ,153 ,109 ,203 ,198 ,199 ,181 ,173 ,};
    encoded_point = group_marshalling_type::encode(etalon_p41);
    BOOST_CHECK(etalon_p_enc41 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p41, decoded_point);

    auto etalon_p42 = group_affine_value_type(base_integral_type("43641818060330578916899916736025144837759271494428353561986107920499560066961"),base_integral_type("25959743075354802923517911612094731071622034637460196172273401123634070884507")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc42 = {
        155 ,16 ,243 ,96 ,78 ,87 ,74 ,199 ,138 ,72 ,150 ,131 ,174 ,175 ,252 ,155 ,117 ,35 ,237 ,63 ,134 ,236 ,24 ,99 ,211 ,227 ,140 ,218 ,162 ,177 ,100 ,185 ,};
    encoded_point = group_marshalling_type::encode(etalon_p42);
    BOOST_CHECK(etalon_p_enc42 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p42, decoded_point);

    auto etalon_p43 = group_affine_value_type(base_integral_type("39683492891665071338707459381391625290195680959043444799473649453196133687798"),base_integral_type("3365282734333937394621306888060764351459711127985364888227687859272992015258")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc43 = {
        154 ,195 ,209 ,66 ,108 ,243 ,160 ,36 ,67 ,92 ,140 ,162 ,146 ,171 ,188 ,173 ,15 ,16 ,113 ,123 ,140 ,153 ,76 ,183 ,3 ,241 ,128 ,43 ,186 ,174 ,112 ,7 ,};
    encoded_point = group_marshalling_type::encode(etalon_p43);
    BOOST_CHECK(etalon_p_enc43 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p43, decoded_point);

    auto etalon_p44 = group_affine_value_type(base_integral_type("14772999761830390624342481034249527649407401563916652201351750412529219916664"),base_integral_type("9945157310953396768316651429755140759781283501962599339420369275484808685955")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc44 = {
        131 ,41 ,56 ,5 ,142 ,183 ,40 ,68 ,123 ,24 ,146 ,224 ,100 ,30 ,181 ,160 ,0 ,84 ,96 ,140 ,156 ,172 ,30 ,21 ,186 ,117 ,101 ,172 ,114 ,194 ,252 ,21 ,};
    encoded_point = group_marshalling_type::encode(etalon_p44);
    BOOST_CHECK(etalon_p_enc44 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p44, decoded_point);

    auto etalon_p45 = group_affine_value_type(base_integral_type("41816198775011528362670871546914457175038417940274872253708474642218529180783"),base_integral_type("47040238284613662438734315047506748402178826823225460681212746859629233424349")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc45 = {
        221 ,199 ,249 ,251 ,0 ,90 ,73 ,9 ,104 ,174 ,48 ,213 ,89 ,171 ,7 ,193 ,231 ,27 ,82 ,74 ,178 ,83 ,170 ,102 ,166 ,148 ,59 ,192 ,211 ,212 ,255 ,231 ,};
    encoded_point = group_marshalling_type::encode(etalon_p45);
    BOOST_CHECK(etalon_p_enc45 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p45, decoded_point);

    auto etalon_p46 = group_affine_value_type(base_integral_type("25842317648612885371235615728075076734880931062546689751455012111235411524969"),base_integral_type("56373390979189825369659575214716985009340688698543833723489161977031212032099")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc46 = {
        99 ,96 ,14 ,100 ,250 ,117 ,19 ,97 ,242 ,204 ,23 ,178 ,165 ,182 ,50 ,31 ,20 ,253 ,76 ,74 ,16 ,25 ,223 ,228 ,12 ,239 ,25 ,141 ,101 ,53 ,162 ,252 ,};
    encoded_point = group_marshalling_type::encode(etalon_p46);
    BOOST_CHECK(etalon_p_enc46 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p46, decoded_point);

    auto etalon_p47 = group_affine_value_type(base_integral_type("23573056835913764620339241086683800409914789959987184676996058691513573552795"),base_integral_type("19946773309885206258890902702558413431915814629527552419561084317357977823419")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc47 = {
        187 ,232 ,174 ,236 ,141 ,252 ,2 ,149 ,30 ,106 ,130 ,169 ,207 ,135 ,204 ,106 ,177 ,231 ,58 ,247 ,79 ,130 ,76 ,99 ,53 ,17 ,84 ,121 ,62 ,121 ,25 ,172 ,};
    encoded_point = group_marshalling_type::encode(etalon_p47);
    BOOST_CHECK(etalon_p_enc47 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p47, decoded_point);

    auto etalon_p48 = group_affine_value_type(base_integral_type("42325547899996061282837199935370380776778868059476334770581679573697897454629"),base_integral_type("54509231429004418436147768838265343539112564378143404142989687391815171090826")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc48 = {
        138 ,169 ,220 ,26 ,120 ,12 ,194 ,123 ,243 ,191 ,78 ,121 ,147 ,49 ,118 ,71 ,11 ,137 ,116 ,241 ,51 ,37 ,65 ,147 ,241 ,32 ,105 ,219 ,180 ,33 ,131 ,248 ,};
    encoded_point = group_marshalling_type::encode(etalon_p48);
    BOOST_CHECK(etalon_p_enc48 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p48, decoded_point);

    auto etalon_p49 = group_affine_value_type(base_integral_type("37798336293351900183741254756872599774155040732532865306756581465840839246788"),base_integral_type("13025379802055838536966871047642824291919286214852657245567503718786702559003")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc49 = {
        27 ,199 ,180 ,242 ,82 ,77 ,186 ,196 ,98 ,19 ,206 ,167 ,83 ,12 ,85 ,23 ,177 ,204 ,17 ,223 ,101 ,122 ,80 ,192 ,179 ,45 ,172 ,196 ,140 ,26 ,204 ,28 ,};
    encoded_point = group_marshalling_type::encode(etalon_p49);
    BOOST_CHECK(etalon_p_enc49 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p49, decoded_point);

    auto etalon_p50 = group_affine_value_type(base_integral_type("43405993338977058742607802746861307428223379144682899790754535212317233170239"),base_integral_type("46363528144087533759592092054783812372314902698574888754321042584832131346667")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc50 = {
        235 ,48 ,166 ,159 ,33 ,101 ,107 ,35 ,158 ,211 ,125 ,117 ,172 ,196 ,89 ,92 ,113 ,43 ,135 ,59 ,88 ,97 ,86 ,54 ,194 ,206 ,159 ,152 ,181 ,211 ,128 ,230 ,};
    encoded_point = group_marshalling_type::encode(etalon_p50);
    BOOST_CHECK(etalon_p_enc50 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p50, decoded_point);

    auto etalon_p51 = group_affine_value_type(base_integral_type("14174586445347810343286924210360822022315450815674737719990676573542896427399"),base_integral_type("52522032931854937510442989067780840481395956246164930066898640773528295933492")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc51 = {
        52 ,134 ,149 ,155 ,62 ,246 ,187 ,131 ,50 ,206 ,221 ,225 ,102 ,141 ,29 ,178 ,52 ,67 ,92 ,146 ,139 ,226 ,67 ,238 ,234 ,168 ,116 ,249 ,203 ,106 ,30 ,244 ,};
    encoded_point = group_marshalling_type::encode(etalon_p51);
    BOOST_CHECK(etalon_p_enc51 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p51, decoded_point);

    auto etalon_p52 = group_affine_value_type(base_integral_type("7679393674357900858845936921951193333627127226881276929341768323356282635650"),base_integral_type("36626445039686379378565004456439532214274665602719032994740707125495656207232")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc52 = {
        128 ,211 ,133 ,202 ,54 ,141 ,160 ,111 ,154 ,203 ,192 ,187 ,80 ,53 ,186 ,28 ,11 ,87 ,137 ,51 ,237 ,142 ,32 ,252 ,244 ,160 ,176 ,48 ,80 ,213 ,249 ,80 ,};
    encoded_point = group_marshalling_type::encode(etalon_p52);
    BOOST_CHECK(etalon_p_enc52 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p52, decoded_point);

    auto etalon_p53 = group_affine_value_type(base_integral_type("38790305047993709842818146602399171880483295852424230800961993846664567259884"),base_integral_type("31544172204402221364130914892375459550509385809279466794982281812075809286559")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc53 = {
        159 ,41 ,223 ,191 ,125 ,211 ,40 ,82 ,141 ,239 ,65 ,118 ,115 ,58 ,189 ,95 ,228 ,216 ,85 ,247 ,129 ,14 ,248 ,27 ,64 ,131 ,208 ,150 ,103 ,94 ,189 ,69 ,};
    encoded_point = group_marshalling_type::encode(etalon_p53);
    BOOST_CHECK(etalon_p_enc53 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p53, decoded_point);

    auto etalon_p54 = group_affine_value_type(base_integral_type("1948306167980412199678309793033269958337977346002764945444233958020643302774"),base_integral_type("10086007747544243592808064898690099798353338112445599430042723164907461466244")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc54 = {
        132 ,216 ,108 ,69 ,31 ,38 ,46 ,10 ,89 ,167 ,9 ,184 ,45 ,243 ,152 ,36 ,202 ,58 ,91 ,66 ,3 ,80 ,255 ,117 ,231 ,134 ,16 ,187 ,99 ,122 ,76 ,22 ,};
    encoded_point = group_marshalling_type::encode(etalon_p54);
    BOOST_CHECK(etalon_p_enc54 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p54, decoded_point);

    auto etalon_p55 = group_affine_value_type(base_integral_type("19344804650657426946180080041566716715100569384573406436047143746534001953813"),base_integral_type("10487279313435892879844276237928278975522762900957783606828571896721512017552")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc55 = {
        144 ,46 ,31 ,227 ,107 ,6 ,79 ,130 ,249 ,20 ,204 ,243 ,244 ,166 ,85 ,171 ,14 ,68 ,210 ,242 ,161 ,187 ,109 ,226 ,162 ,146 ,111 ,85 ,249 ,150 ,47 ,151 ,};
    encoded_point = group_marshalling_type::encode(etalon_p55);
    BOOST_CHECK(etalon_p_enc55 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p55, decoded_point);

    auto etalon_p56 = group_affine_value_type(base_integral_type("14280529640441277099179174132440534161046904365806357411286342813348998810210"),base_integral_type("17719310056238872720272328660122165947986297711064662297866345660188352136378")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc56 = {
        186 ,68 ,161 ,193 ,113 ,227 ,207 ,73 ,193 ,224 ,113 ,74 ,198 ,21 ,116 ,246 ,245 ,88 ,144 ,151 ,17 ,38 ,26 ,224 ,25 ,155 ,35 ,119 ,42 ,198 ,44 ,39 ,};
    encoded_point = group_marshalling_type::encode(etalon_p56);
    BOOST_CHECK(etalon_p_enc56 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p56, decoded_point);

    auto etalon_p57 = group_affine_value_type(base_integral_type("43253629432883455496485334257710094522223024946918670854120620852924243705329"),base_integral_type("21921896587924606413938007601725401567806804434173188349751302374389722133414")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc57 = {
        166 ,51 ,12 ,219 ,195 ,47 ,246 ,159 ,91 ,99 ,149 ,144 ,250 ,22 ,108 ,120 ,168 ,36 ,157 ,9 ,162 ,137 ,153 ,147 ,227 ,189 ,45 ,150 ,144 ,90 ,119 ,176 ,};
    encoded_point = group_marshalling_type::encode(etalon_p57);
    BOOST_CHECK(etalon_p_enc57 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p57, decoded_point);

    auto etalon_p58 = group_affine_value_type(base_integral_type("57713332922266375373531686848215120466040299590015283900503232826124048810807"),base_integral_type("10746129553556161217315113679344697810078831555030687188768070881187665969048")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc58 = {
        152 ,127 ,150 ,52 ,91 ,191 ,202 ,242 ,112 ,99 ,17 ,225 ,197 ,174 ,154 ,158 ,185 ,172 ,29 ,105 ,193 ,5 ,49 ,208 ,32 ,8 ,129 ,92 ,2 ,24 ,194 ,151 ,};
    encoded_point = group_marshalling_type::encode(etalon_p58);
    BOOST_CHECK(etalon_p_enc58 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p58, decoded_point);

    auto etalon_p59 = group_affine_value_type(base_integral_type("41497257885077433626133258880557575198854898066289096944418891621602496722285"),base_integral_type("40303961466161492557979824944167143193100330348326843228589549010652426896352")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc59 = {
        224 ,131 ,99 ,150 ,253 ,147 ,97 ,241 ,115 ,19 ,8 ,133 ,148 ,139 ,210 ,101 ,219 ,219 ,201 ,93 ,78 ,243 ,2 ,84 ,228 ,202 ,109 ,172 ,217 ,59 ,27 ,217 ,};
    encoded_point = group_marshalling_type::encode(etalon_p59);
    BOOST_CHECK(etalon_p_enc59 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p59, decoded_point);

    auto etalon_p60 = group_affine_value_type(base_integral_type("50753377927693988688173488534941478251661079244864035570539240574836915030626"),base_integral_type("17241792209033596985922508255621428008952727912570930381079366627790732900976")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc60 = {
        112 ,186 ,103 ,237 ,62 ,41 ,10 ,130 ,114 ,51 ,16 ,19 ,119 ,90 ,196 ,37 ,249 ,123 ,119 ,62 ,239 ,158 ,128 ,93 ,200 ,39 ,49 ,27 ,49 ,130 ,30 ,38 ,};
    encoded_point = group_marshalling_type::encode(etalon_p60);
    BOOST_CHECK(etalon_p_enc60 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p60, decoded_point);

    auto etalon_p61 = group_affine_value_type(base_integral_type("15442970548364064741253309753093229125608357827672307954893920659724050608080"),base_integral_type("3769536083688642379967278753264163409438011203623882963156266985540653948666")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc61 = {
        250 ,30 ,168 ,197 ,185 ,191 ,213 ,9 ,201 ,55 ,112 ,51 ,226 ,200 ,94 ,159 ,236 ,244 ,54 ,105 ,86 ,183 ,141 ,146 ,173 ,103 ,192 ,68 ,88 ,123 ,85 ,8 ,};
    encoded_point = group_marshalling_type::encode(etalon_p61);
    BOOST_CHECK(etalon_p_enc61 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p61, decoded_point);

    auto etalon_p62 = group_affine_value_type(base_integral_type("9447973775078041660509050448821831766455778438060496275472605826542293582431"),base_integral_type("40806590118907540415378779603749428909250426221901595333802646977561657019293")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc62 = {
        157 ,11 ,159 ,20 ,134 ,62 ,82 ,192 ,142 ,250 ,104 ,94 ,37 ,202 ,235 ,29 ,41 ,147 ,108 ,37 ,236 ,174 ,251 ,42 ,185 ,248 ,137 ,147 ,38 ,182 ,55 ,218 ,};
    encoded_point = group_marshalling_type::encode(etalon_p62);
    BOOST_CHECK(etalon_p_enc62 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p62, decoded_point);

    auto etalon_p63 = group_affine_value_type(base_integral_type("54344180039694954572813279515690196821681059471283540225464512294904542550763"),base_integral_type("18237528919469161844165120899264607067447957637867746391828364538357169574703")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc63 = {
        47 ,211 ,232 ,229 ,108 ,59 ,155 ,201 ,95 ,225 ,69 ,36 ,46 ,98 ,45 ,140 ,29 ,27 ,203 ,38 ,202 ,201 ,183 ,16 ,94 ,171 ,18 ,106 ,88 ,19 ,82 ,168 ,};
    encoded_point = group_marshalling_type::encode(etalon_p63);
    BOOST_CHECK(etalon_p_enc63 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p63, decoded_point);

    auto etalon_p64 = group_affine_value_type(base_integral_type("22906337404769490852582360723182853706454956090815011485177498613707226384918"),base_integral_type("33354357331097528988856195784383016917026549925554731140112507417625277813156")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc64 = {
        164 ,209 ,180 ,81 ,199 ,222 ,102 ,102 ,138 ,192 ,66 ,108 ,21 ,221 ,21 ,90 ,183 ,172 ,38 ,147 ,121 ,211 ,72 ,40 ,212 ,113 ,183 ,165 ,177 ,229 ,189 ,73 ,};
    encoded_point = group_marshalling_type::encode(etalon_p64);
    BOOST_CHECK(etalon_p_enc64 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p64, decoded_point);

    auto etalon_p65 = group_affine_value_type(base_integral_type("39322213881456826773202590767663480267988906145460828254834818642979460594404"),base_integral_type("20480511195483085785429608475425207209899677397434360979577562349292179055900")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc65 = {
        28 ,101 ,74 ,70 ,37 ,175 ,82 ,216 ,55 ,69 ,101 ,194 ,42 ,168 ,44 ,143 ,222 ,125 ,149 ,131 ,201 ,63 ,228 ,118 ,220 ,107 ,128 ,244 ,252 ,142 ,71 ,45 ,};
    encoded_point = group_marshalling_type::encode(etalon_p65);
    BOOST_CHECK(etalon_p_enc65 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p65, decoded_point);

    auto etalon_p66 = group_affine_value_type(base_integral_type("48008845262590571269587437493689563714228771736199476503335070258259996072769"),base_integral_type("44724145304871631964215463292078963826340089222723810223392098711226883099840")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc66 = {
        192 ,204 ,53 ,222 ,139 ,37 ,8 ,38 ,251 ,34 ,35 ,123 ,65 ,27 ,61 ,67 ,141 ,183 ,5 ,145 ,142 ,57 ,167 ,239 ,129 ,21 ,157 ,125 ,28 ,248 ,224 ,226 ,};
    encoded_point = group_marshalling_type::encode(etalon_p66);
    BOOST_CHECK(etalon_p_enc66 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p66, decoded_point);

    auto etalon_p67 = group_affine_value_type(base_integral_type("16898043230158609373672171062630176344252430589295823096512610302339326979047"),base_integral_type("19226460001329965978984021842036461036968769408429768245153466285868319635867")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc67 = {
        155 ,249 ,221 ,186 ,23 ,28 ,6 ,210 ,28 ,170 ,226 ,132 ,31 ,212 ,36 ,84 ,86 ,234 ,69 ,253 ,17 ,203 ,199 ,240 ,132 ,12 ,197 ,237 ,108 ,202 ,129 ,170 ,};
    encoded_point = group_marshalling_type::encode(etalon_p67);
    BOOST_CHECK(etalon_p_enc67 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p67, decoded_point);

    auto etalon_p68 = group_affine_value_type(base_integral_type("9392057019809427632094564691767361561061039888191512587224326144173136617588"),base_integral_type("51999342568692571726040419193321853150842692512438989499230415450759588344085")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc68 = {
        21 ,241 ,165 ,5 ,193 ,11 ,55 ,63 ,209 ,113 ,54 ,218 ,234 ,235 ,112 ,44 ,188 ,234 ,233 ,196 ,96 ,111 ,31 ,250 ,214 ,221 ,253 ,223 ,188 ,149 ,246 ,114 ,};
    encoded_point = group_marshalling_type::encode(etalon_p68);
    BOOST_CHECK(etalon_p_enc68 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p68, decoded_point);

    auto etalon_p69 = group_affine_value_type(base_integral_type("13778543827969408283560524037326429625873967327866879401243124440410346256495"),base_integral_type("14961820372201521176555932621523096653326832628055817400441129145107812159362")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc69 = {
        130 ,143 ,227 ,113 ,235 ,182 ,85 ,160 ,18 ,229 ,176 ,30 ,158 ,106 ,91 ,148 ,145 ,89 ,126 ,195 ,29 ,249 ,147 ,129 ,254 ,237 ,32 ,128 ,25 ,23 ,20 ,161 ,};
    encoded_point = group_marshalling_type::encode(etalon_p69);
    BOOST_CHECK(etalon_p_enc69 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p69, decoded_point);

    auto etalon_p70 = group_affine_value_type(base_integral_type("46601433237052385291201536237083487334635183566524258811692854696842559607966"),base_integral_type("32603306969691634238643291068952701028331056066578338904246079580460109846886")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc70 = {
        102 ,217 ,0 ,161 ,229 ,188 ,117 ,180 ,58 ,206 ,214 ,123 ,158 ,16 ,35 ,147 ,107 ,85 ,83 ,162 ,221 ,146 ,17 ,173 ,83 ,112 ,130 ,114 ,91 ,209 ,20 ,72 ,};
    encoded_point = group_marshalling_type::encode(etalon_p70);
    BOOST_CHECK(etalon_p_enc70 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p70, decoded_point);

    auto etalon_p71 = group_affine_value_type(base_integral_type("11502534063287058749380372333160823606150385061910987811052591528173549061721"),base_integral_type("25877068024329889050333965646531300145235433971875619414575899214650821117233")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc71 = {
        49 ,5 ,97 ,242 ,212 ,82 ,97 ,25 ,230 ,235 ,121 ,51 ,94 ,236 ,43 ,147 ,205 ,108 ,86 ,35 ,167 ,82 ,68 ,109 ,250 ,188 ,168 ,198 ,198 ,230 ,53 ,185 ,};
    encoded_point = group_marshalling_type::encode(etalon_p71);
    BOOST_CHECK(etalon_p_enc71 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p71, decoded_point);

    auto etalon_p72 = group_affine_value_type(base_integral_type("43955534665231726634351195255296915398430657512871977576531002784046638418605"),base_integral_type("18811701502659570233044290341652550983626720814843200093197569109560650252657")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc72 = {
        113 ,65 ,234 ,64 ,16 ,251 ,151 ,243 ,82 ,141 ,9 ,66 ,186 ,50 ,168 ,6 ,75 ,214 ,205 ,74 ,245 ,46 ,164 ,97 ,62 ,238 ,131 ,47 ,181 ,11 ,151 ,169 ,};
    encoded_point = group_marshalling_type::encode(etalon_p72);
    BOOST_CHECK(etalon_p_enc72 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p72, decoded_point);

    auto etalon_p73 = group_affine_value_type(base_integral_type("20758266634368572897330401504746919292871474526761553557306271045636924117253"),base_integral_type("32420649856172048210346171513935417917763502285803109567983139142452554805338")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc73 = {
        90 ,176 ,16 ,36 ,57 ,87 ,94 ,246 ,186 ,80 ,211 ,93 ,87 ,8 ,155 ,65 ,38 ,78 ,119 ,128 ,197 ,240 ,232 ,112 ,64 ,224 ,214 ,142 ,2 ,112 ,173 ,199 ,};
    encoded_point = group_marshalling_type::encode(etalon_p73);
    BOOST_CHECK(etalon_p_enc73 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p73, decoded_point);

    auto etalon_p74 = group_affine_value_type(base_integral_type("43369991253492618680654995560853195093598298276445311000437450308033854990617"),base_integral_type("20709446845819341955010929824340059227358306532065118425506230404122226468360")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc74 = {
        8 ,38 ,96 ,165 ,139 ,157 ,253 ,240 ,118 ,39 ,1 ,253 ,200 ,68 ,255 ,30 ,20 ,97 ,115 ,167 ,6 ,86 ,43 ,169 ,178 ,107 ,176 ,45 ,172 ,33 ,201 ,173 ,};
    encoded_point = group_marshalling_type::encode(etalon_p74);
    BOOST_CHECK(etalon_p_enc74 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p74, decoded_point);

    auto etalon_p75 = group_affine_value_type(base_integral_type("40913200456727106491509286144509488958783184183460516233574015396359209065932"),base_integral_type("33998963858780750866077269424510243463689627673134982633098309800269969687781")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc75 = {
        229 ,4 ,197 ,22 ,7 ,158 ,174 ,168 ,156 ,224 ,83 ,217 ,215 ,22 ,39 ,83 ,27 ,91 ,0 ,140 ,55 ,28 ,124 ,178 ,230 ,12 ,177 ,158 ,74 ,187 ,42 ,75 ,};
    encoded_point = group_marshalling_type::encode(etalon_p75);
    BOOST_CHECK(etalon_p_enc75 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p75, decoded_point);

    auto etalon_p76 = group_affine_value_type(base_integral_type("37903740790247966898988334724469635780707848946904312806446916978666887062757"),base_integral_type("15389980338780763954562263252500672748307499218467517683889823876998890037863")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc76 = {
        103 ,162 ,152 ,13 ,183 ,107 ,132 ,245 ,75 ,132 ,37 ,133 ,134 ,125 ,207 ,112 ,177 ,75 ,170 ,13 ,146 ,57 ,127 ,197 ,91 ,216 ,205 ,80 ,145 ,107 ,6 ,162 ,};
    encoded_point = group_marshalling_type::encode(etalon_p76);
    BOOST_CHECK(etalon_p_enc76 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p76, decoded_point);

    auto etalon_p77 = group_affine_value_type(base_integral_type("6900216982663199723404333619243770315289578354136471980291868467780552637324"),base_integral_type("18320422154862746865459093708016654361939362425158801406800196559543775467346")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc77 = {
        82 ,23 ,51 ,115 ,107 ,204 ,248 ,201 ,104 ,193 ,128 ,47 ,164 ,40 ,60 ,58 ,129 ,229 ,19 ,159 ,1 ,34 ,236 ,182 ,81 ,253 ,106 ,102 ,209 ,253 ,128 ,40 ,};
    encoded_point = group_marshalling_type::encode(etalon_p77);
    BOOST_CHECK(etalon_p_enc77 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p77, decoded_point);

    auto etalon_p78 = group_affine_value_type(base_integral_type("32961015675073100189683329582971058780265380362196508599420203311329249123822"),base_integral_type("37597074017476185529746122635903176965505932097573686882908909493787530998909")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc78 = {
        125 ,180 ,37 ,163 ,9 ,159 ,251 ,23 ,254 ,0 ,117 ,132 ,128 ,11 ,207 ,168 ,130 ,72 ,214 ,67 ,3 ,180 ,200 ,148 ,154 ,103 ,74 ,239 ,149 ,48 ,31 ,83 ,};
    encoded_point = group_marshalling_type::encode(etalon_p78);
    BOOST_CHECK(etalon_p_enc78 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p78, decoded_point);

    auto etalon_p79 = group_affine_value_type(base_integral_type("14123145134671113558077969450408038739756450815668034775013334641947600226509"),base_integral_type("17179056412991364940956115322130196363073541252521906689535817041575973234143")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc79 = {
        223 ,37 ,56 ,247 ,179 ,224 ,82 ,74 ,127 ,238 ,49 ,48 ,37 ,210 ,105 ,11 ,228 ,31 ,15 ,169 ,69 ,164 ,127 ,240 ,185 ,240 ,201 ,25 ,89 ,0 ,251 ,165 ,};
    encoded_point = group_marshalling_type::encode(etalon_p79);
    BOOST_CHECK(etalon_p_enc79 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p79, decoded_point);

    auto etalon_p80 = group_affine_value_type(base_integral_type("1635406309842543553670387610996642114242089406152609826827534479881841486225"),base_integral_type("24854969696573849168640612875409761014778579331061728282838094936463574572559")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc80 = {
        15 ,30 ,48 ,249 ,166 ,33 ,134 ,88 ,156 ,221 ,249 ,97 ,203 ,50 ,168 ,103 ,27 ,50 ,56 ,199 ,104 ,228 ,39 ,166 ,229 ,180 ,159 ,188 ,16 ,106 ,243 ,182 ,};
    encoded_point = group_marshalling_type::encode(etalon_p80);
    BOOST_CHECK(etalon_p_enc80 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p80, decoded_point);

    auto etalon_p81 = group_affine_value_type(base_integral_type("14327640891089694761080472917764230989446531184351852215398088663750634846316"),base_integral_type("12851761187339558978338589191103640364993979326664550363838056403850420347432")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc81 = {
        40 ,226 ,124 ,144 ,198 ,57 ,161 ,119 ,15 ,0 ,66 ,137 ,158 ,174 ,194 ,101 ,197 ,102 ,107 ,127 ,101 ,138 ,231 ,45 ,53 ,140 ,181 ,110 ,204 ,214 ,105 ,28 ,};
    encoded_point = group_marshalling_type::encode(etalon_p81);
    BOOST_CHECK(etalon_p_enc81 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p81, decoded_point);

    auto etalon_p82 = group_affine_value_type(base_integral_type("19299700114946755359750864322696854434210107548467086019627229219931629604879"),base_integral_type("6685016297147017385018892389600443586204475046206858020218065765809001998646")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc82 = {
        54 ,41 ,150 ,93 ,239 ,204 ,195 ,128 ,40 ,152 ,117 ,63 ,163 ,85 ,9 ,34 ,135 ,120 ,102 ,108 ,15 ,160 ,47 ,112 ,180 ,92 ,17 ,171 ,203 ,149 ,199 ,142 ,};
    encoded_point = group_marshalling_type::encode(etalon_p82);
    BOOST_CHECK(etalon_p_enc82 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p82, decoded_point);

    auto etalon_p83 = group_affine_value_type(base_integral_type("40633478416526797461957320249480865908768553471170843493747485155068029248089"),base_integral_type("51661350115215930410515263505701562301978192014116773533480719990743712858189")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc83 = {
        77 ,0 ,51 ,108 ,166 ,128 ,19 ,16 ,169 ,194 ,105 ,252 ,23 ,197 ,72 ,127 ,90 ,34 ,166 ,70 ,251 ,123 ,107 ,63 ,213 ,218 ,114 ,0 ,184 ,73 ,55 ,242 ,};
    encoded_point = group_marshalling_type::encode(etalon_p83);
    BOOST_CHECK(etalon_p_enc83 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p83, decoded_point);

    auto etalon_p84 = group_affine_value_type(base_integral_type("14708010638346631283444386911841137933843152461976353070007600990089940471793"),base_integral_type("3022099357665339706287137082798709428731892556214195547534060149176375264808")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc84 = {
        40 ,70 ,217 ,224 ,27 ,90 ,121 ,156 ,43 ,80 ,151 ,237 ,39 ,16 ,216 ,79 ,55 ,139 ,225 ,192 ,85 ,129 ,147 ,63 ,47 ,223 ,32 ,65 ,151 ,114 ,174 ,134 ,};
    encoded_point = group_marshalling_type::encode(etalon_p84);
    BOOST_CHECK(etalon_p_enc84 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p84, decoded_point);

    auto etalon_p85 = group_affine_value_type(base_integral_type("11414233989554484640565462596542283575316224427424179033991078140467469975790"),base_integral_type("14438593630023391298188000916843441926626488233665273477208274972839302556431")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc85 = {
        15 ,107 ,226 ,147 ,2 ,91 ,194 ,220 ,84 ,246 ,250 ,132 ,159 ,181 ,6 ,117 ,170 ,148 ,69 ,142 ,74 ,88 ,218 ,33 ,130 ,12 ,98 ,255 ,82 ,244 ,235 ,31 ,};
    encoded_point = group_marshalling_type::encode(etalon_p85);
    BOOST_CHECK(etalon_p_enc85 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p85, decoded_point);

    auto etalon_p86 = group_affine_value_type(base_integral_type("14913088512413970929691310625029813924328166487465152897141046244732257566619"),base_integral_type("1668599198328589618462715924626144849781157726424055290411678449854367107890")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc86 = {
        50 ,139 ,67 ,141 ,209 ,28 ,176 ,43 ,253 ,212 ,17 ,26 ,66 ,216 ,83 ,149 ,79 ,123 ,76 ,248 ,12 ,181 ,167 ,114 ,164 ,230 ,63 ,24 ,200 ,100 ,176 ,131 ,};
    encoded_point = group_marshalling_type::encode(etalon_p86);
    BOOST_CHECK(etalon_p_enc86 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p86, decoded_point);

    auto etalon_p87 = group_affine_value_type(base_integral_type("24186909417956818638911274041399560447042147254376438236688322337453903204704"),base_integral_type("41440426452373658770279326479721745963764452562108395662496795864596730327638")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc87 = {
        86 ,178 ,235 ,31 ,230 ,101 ,103 ,245 ,86 ,29 ,159 ,30 ,141 ,98 ,174 ,212 ,71 ,151 ,66 ,253 ,125 ,133 ,106 ,27 ,26 ,195 ,176 ,215 ,62 ,115 ,158 ,91 ,};
    encoded_point = group_marshalling_type::encode(etalon_p87);
    BOOST_CHECK(etalon_p_enc87 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p87, decoded_point);

    auto etalon_p88 = group_affine_value_type(base_integral_type("25386842686015828647182670588269137138255021175747712833671262272078951652251"),base_integral_type("24716311807671491233097907235704859659972664160618031806505842507090682480266")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc88 = {
        138 ,134 ,228 ,227 ,130 ,149 ,36 ,81 ,218 ,223 ,92 ,105 ,97 ,101 ,18 ,36 ,164 ,207 ,168 ,136 ,119 ,242 ,102 ,190 ,68 ,70 ,17 ,203 ,205 ,239 ,164 ,182 ,};
    encoded_point = group_marshalling_type::encode(etalon_p88);
    BOOST_CHECK(etalon_p_enc88 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p88, decoded_point);

    auto etalon_p89 = group_affine_value_type(base_integral_type("31426977516511168415050665921575786967242687556935924953407268658057938487761"),base_integral_type("41706190569543357030675430992177110708481107488661568864471571852511139073662")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc89 = {
        126 ,14 ,88 ,211 ,116 ,80 ,44 ,75 ,100 ,104 ,46 ,30 ,119 ,234 ,253 ,169 ,128 ,71 ,185 ,206 ,211 ,197 ,39 ,166 ,47 ,218 ,170 ,210 ,9 ,222 ,52 ,220 ,};
    encoded_point = group_marshalling_type::encode(etalon_p89);
    BOOST_CHECK(etalon_p_enc89 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p89, decoded_point);

    auto etalon_p90 = group_affine_value_type(base_integral_type("46601979527539566144998946835794332656328861464491041727721699669562684577754"),base_integral_type("10462947380242787088159262553330886787105385890383246823286834929237812027871")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc90 = {
        223 ,161 ,119 ,220 ,127 ,90 ,217 ,152 ,133 ,221 ,228 ,179 ,146 ,170 ,153 ,117 ,73 ,20 ,160 ,139 ,221 ,132 ,107 ,30 ,61 ,87 ,106 ,197 ,127 ,209 ,33 ,23 ,};
    encoded_point = group_marshalling_type::encode(etalon_p90);
    BOOST_CHECK(etalon_p_enc90 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p90, decoded_point);

    auto etalon_p91 = group_affine_value_type(base_integral_type("50514876642607425246940430635395340062830216161145477776164625524936198068835"),base_integral_type("27703999522232810580966762649323745194330510966819529296729927600700303386989")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc91 = {
        109 ,169 ,192 ,152 ,170 ,135 ,173 ,177 ,52 ,91 ,19 ,136 ,69 ,32 ,20 ,24 ,95 ,152 ,150 ,221 ,113 ,56 ,107 ,124 ,21 ,215 ,219 ,67 ,118 ,232 ,63 ,189 ,};
    encoded_point = group_marshalling_type::encode(etalon_p91);
    BOOST_CHECK(etalon_p_enc91 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p91, decoded_point);

    auto etalon_p92 = group_affine_value_type(base_integral_type("53537406521746807502254995025819202918656264367304094038143352151892196037244"),base_integral_type("34212711882026037224981791780927330596568952476664319253277485165966642451286")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc92 = {
        86 ,19 ,41 ,205 ,37 ,145 ,64 ,201 ,115 ,223 ,37 ,61 ,190 ,100 ,28 ,114 ,82 ,218 ,21 ,60 ,106 ,71 ,60 ,169 ,114 ,128 ,240 ,113 ,109 ,181 ,163 ,75 ,};
    encoded_point = group_marshalling_type::encode(etalon_p92);
    BOOST_CHECK(etalon_p_enc92 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p92, decoded_point);

    auto etalon_p93 = group_affine_value_type(base_integral_type("46795724829451952030298175846384232750924888104173564908639268801191673897657"),base_integral_type("26722815456018928636599543357337155897913174636219326679199356683602348511429")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc93 = {
        197 ,144 ,76 ,206 ,89 ,199 ,243 ,191 ,157 ,76 ,247 ,199 ,106 ,147 ,240 ,143 ,13 ,108 ,96 ,146 ,173 ,21 ,104 ,246 ,138 ,148 ,16 ,136 ,218 ,147 ,20 ,187 ,};
    encoded_point = group_marshalling_type::encode(etalon_p93);
    BOOST_CHECK(etalon_p_enc93 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p93, decoded_point);

    auto etalon_p94 = group_affine_value_type(base_integral_type("29287851416530607061876182583692875659651961963143990479379888347399600779861"),base_integral_type("16271964020590115117047193082049267036264554624366822085090662788710160662216")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc94 = {
        200 ,254 ,139 ,104 ,228 ,135 ,81 ,148 ,38 ,245 ,198 ,199 ,49 ,26 ,152 ,46 ,243 ,44 ,168 ,49 ,96 ,84 ,30 ,148 ,148 ,85 ,20 ,74 ,242 ,154 ,249 ,163 ,};
    encoded_point = group_marshalling_type::encode(etalon_p94);
    BOOST_CHECK(etalon_p_enc94 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p94, decoded_point);

    auto etalon_p95 = group_affine_value_type(base_integral_type("48637994354115049892139756998989796633446197700088900312197485738335160088153"),base_integral_type("32852581962474567195042768408437702451111205240943862604719182435633099104191")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc95 = {
        191 ,223 ,154 ,250 ,54 ,84 ,86 ,43 ,235 ,168 ,221 ,187 ,92 ,73 ,19 ,165 ,245 ,181 ,58 ,52 ,161 ,122 ,184 ,226 ,22 ,188 ,205 ,207 ,6 ,231 ,161 ,200 ,};
    encoded_point = group_marshalling_type::encode(etalon_p95);
    BOOST_CHECK(etalon_p_enc95 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p95, decoded_point);

    auto etalon_p96 = group_affine_value_type(base_integral_type("11517497618525654622704493389287144708552411909455757452243920998366320485422"),base_integral_type("57871210034854632441974080158844209243870023516768731871375126070248644720173")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc96 = {
        45 ,182 ,18 ,132 ,205 ,172 ,132 ,116 ,73 ,125 ,75 ,195 ,224 ,81 ,191 ,159 ,212 ,221 ,182 ,7 ,242 ,236 ,162 ,197 ,70 ,115 ,14 ,23 ,178 ,241 ,241 ,127 ,};
    encoded_point = group_marshalling_type::encode(etalon_p96);
    BOOST_CHECK(etalon_p_enc96 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p96, decoded_point);

    auto etalon_p97 = group_affine_value_type(base_integral_type("53887295796918698934051404228550365133012670462148643953382606419344052991735"),base_integral_type("15051601490390377572725770958312826777247291741546792106017824459703333760081")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc97 = {
        81 ,44 ,185 ,216 ,1 ,119 ,174 ,139 ,193 ,146 ,166 ,222 ,217 ,98 ,107 ,102 ,73 ,25 ,200 ,4 ,173 ,245 ,44 ,94 ,3 ,85 ,46 ,66 ,144 ,231 ,70 ,161 ,};
    encoded_point = group_marshalling_type::encode(etalon_p97);
    BOOST_CHECK(etalon_p_enc97 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p97, decoded_point);

    auto etalon_p98 = group_affine_value_type(base_integral_type("52177767179915817920986220822280774021828951148832354741982335106696858348430"),base_integral_type("52893251453227407653179070211102928994678010564170172528362930409322779765608")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc98 = {
        104 ,235 ,103 ,149 ,114 ,44 ,93 ,89 ,75 ,0 ,45 ,179 ,112 ,252 ,139 ,28 ,61 ,172 ,76 ,238 ,127 ,244 ,162 ,5 ,93 ,247 ,160 ,51 ,248 ,132 ,240 ,116 ,};
    encoded_point = group_marshalling_type::encode(etalon_p98);
    BOOST_CHECK(etalon_p_enc98 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p98, decoded_point);

    auto etalon_p99 = group_affine_value_type(base_integral_type("12100541331595492187316033195115965134118481413671462588321647603410407488802"),base_integral_type("56895307147047028426026777511440305898795978191166973449931454853576535490124")).to_extended_with_a_minus_1();
    std::array<std::uint8_t, 32> etalon_p_enc99 = {
        76 ,190 ,130 ,82 ,165 ,142 ,52 ,17 ,238 ,157 ,231 ,39 ,131 ,225 ,31 ,127 ,5 ,246 ,169 ,141 ,176 ,187 ,240 ,152 ,134 ,194 ,152 ,38 ,72 ,154 ,201 ,125 ,};
    encoded_point = group_marshalling_type::encode(etalon_p99);
    BOOST_CHECK(etalon_p_enc99 == encoded_point);
    decoded_point = group_marshalling_type::decode(encoded_point);
    BOOST_CHECK_EQUAL(etalon_p99, decoded_point);
}

BOOST_AUTO_TEST_SUITE_END()
