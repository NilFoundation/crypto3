//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE inverse_multiprecision_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include "test.hpp"

#if !defined(TEST_CPP_INT)
#define TEST_CPP_INT
#endif

#ifdef TEST_CPP_INT
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#endif

#include <nil/crypto3/multiprecision/inverse.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(585);

using namespace nil::crypto3::multiprecision;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream&, P<K, V> const&) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

template<typename T>
void test_cpp_int() {
    // test for monty_inverse
    BOOST_CHECK_EQUAL(monty_inverse(T(12), T(5), T(5)), T(1823));
    BOOST_CHECK_EQUAL(monty_inverse(T(10), T(37), T(1)), T(26));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(2), T(3)), T(3));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(4), T(2)), T(11));
    BOOST_CHECK_EQUAL(monty_inverse(T(4), T(7), T(2)), T(37));
    BOOST_CHECK_EQUAL(monty_inverse(T(32), T(247), T(1)), T(193));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(7), T(7)), T(549029));
    BOOST_CHECK_EQUAL(monty_inverse(T(5317589), T(23), T(8)), T(32104978469));

    // test for inverse with extended euclidean algorithm
    BOOST_CHECK_EQUAL(monty_inverse(T(12), T(5), T(5)), T(1823));
    BOOST_CHECK_EQUAL(monty_inverse(T(10), T(37), T(1)), T(26));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(2), T(3)), T(3));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(4), T(2)), T(11));
    BOOST_CHECK_EQUAL(monty_inverse(T(4), T(7), T(2)), T(37));
    BOOST_CHECK_EQUAL(monty_inverse(T(32), T(247), T(1)), T(193));
    BOOST_CHECK_EQUAL(monty_inverse(T(3), T(7), T(7)), T(549029));
    BOOST_CHECK_EQUAL(monty_inverse(T(5317589), T(23), T(8)), T(32104978469));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(5), T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x33333333333333333333333333333333"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(333), T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x17d4f2ee517d4f2ee517d4f2ee517d4f"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T("0x435b21e35ccd62dbdbafa1368cf742f0"),
                                                           T("0x7fffffffffffffffffffffffffffffff")),
                      T("0x604ddb74e5a55e559a7320e45b06eaf6"));
    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(T(2),
                                             T("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
        T("0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(8)), T(3));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(46), T(207)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(2), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(0), T(2)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(46), T(46)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(1), T(7)), T(1));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(35), T(118)), T(27));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(37), T(37)), T(0));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(32), T(247)), T(193));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(232)), T(155));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(
                          T("256992387993922882115519242002267204163958280694902854777438773165028812741820300742384101"
                            "620467227297951260702776745365693102268609333941403372929142489383748076291"),
                          T("310556067329850632847208938574658589632291100674077275160516075249922714838542485036214015"
                            "8165019680645739648726058090243814223511639161631852729287604717869259565828")),
                      T("2322484593360248972803085811686365806060063797313230509497970163285203519904646342173323688226"
                        "147654544918783691327115436052292182385106099615339567513136063879840431"));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(
                          T("657900513264442578215729259525804042708991731028255426638688946278845827095715186772097484"
                            "16019817305674876843604308670298295897660589296995641401495105646770364032950"),
                          T("146059874272782860583686068115674600616627249438711269370889274434354805551497286303947620"
                            "1659720247220048664250204314648520085411164461712526657028588699682983099362771")),
                      T("3701344688092353558099310214964185602579277616517826314317231208222417072861266226192312282752"
                        "10678415132318220494260963802381448709723310690465171935975287188943190781"));

    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(3), T(0x10)), T(11));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(T(43000466091), T(0x10000000000)), T(140404367363));

    BOOST_CHECK_EQUAL(
        inverse_extended_euclidean_algorithm(
            T("33292237061710524632068664083551908521453088535512228553742065532915836412003628111698671675220667324272"
              "59441069045458590915570173077273266668323626418910290729833115917608762612451607036836604560196526748133"
              "29522948231543216086195698566172041500850281737658912236916916850305170057553436136073435791550700526779"
              "12660561648431971151735424574091783976824121860178440448784777337066736659493124795020814172868481356070"
              "66940796741261651879705761216547813649105594986990007847567220787224253724912309650653332895570458720843"
              "32248506568118976869729175214974857589323352085671183814040169149453233350227887942508765678216349436356"
              "75846338481947840708222456495574685784973687231575617245307467847417686461029368632606300888825458750471"
              "73194357829837349405264332156553159"),
            T("51596692759022688970196837706341298598491314420895122094662553697486478852950434581004530951396375324897"
              "32379349334183998359005271540851438475735390060160055101459757369025094548935216928274885474920588457238"
              "93219921282613284811298303020722872923035014307024521461503233009837360681685755548737891159735617529596"
              "32962090241009808888741741043849264397734093528558956831628004860618936254613392484195923653331976713963"
              "90223849652458316548872173632032072142493359961192701645150390051578875246900773560274606831152842526302"
              "32119770327075242249607931076080422885968273410466133336708808535463570182780841768637479016464266039055"
              "79252439838082169284212200948381030179583349742050406608587079632257161952224606791379941232782765846637"
              "12976241848458904056941218720227786752")),
        T("161697650868559861271540461553971172959149630383872727836174576845991274476610311080533553178926047190203266"
          "855682387778179711917736974467565503622769386238790133592938052615852533561719117119940626105914149272955096"
          "438337875559227137733092417869557531785548219841868720728411947243663889165526728787046894739482800359519447"
          "645962037395419461841363898495986577864710230228655859268881063366400726401157990917652680450814220027329982"
          "285259267693662973801338310334464263818845826026848198196523975624137438165546650367370131035732951388159175"
          "971890099247228360312965057735541872892978783707133028552644759681714224704381891573964406129272600659255700"
          "500824412025869294370532513154961039220948194823131817745018177622290430615352105032422136121552433314291445"
          "5291939319"));
    BOOST_CHECK_EQUAL(inverse_extended_euclidean_algorithm(
                          T(65279),
                          T("0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                            "00000000000000000000000000000000000000000000000000000000000")),
                      T("2136191453734241471355287191702994357470910407859959447816962783332820558450714636705703817069"
                        "8710253677755075362127788711957331760388539866898398399344480664991941861081743615"));
}

template<typename T>
void test_cpp_int_backend() {

    using namespace nil::crypto3::multiprecision;
    number<T> res;

    number<backends::modular_adaptor<T>> modular;

    modular = number<backends::modular_adaptor<T>>(10, 37);
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(26));

    modular = number<backends::modular_adaptor<T>>(3, 8);
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(3));

    modular = number<backends::modular_adaptor<T>>(3, 16);
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(11));

    modular = number<backends::modular_adaptor<T>>(
        65279,
        "0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000");
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(
        cpp_int(res.backend()),
        cpp_int("213619145373424147135528719170299435747091040785995944781696278333282055845071463670570381706987102536"
                "77755075362127788711957331760388539866898398399344480664991941861081743615"));

    modular = number<backends::modular_adaptor<T>>(
        "33292237061710524632068664083551908521453088535512228553742065532915836412003628111698671675220667324272594410"
        "69045458590915570173077273266668323626418910290729833115917608762612451607036836604560196526748133295229482315"
        "43216086195698566172041500850281737658912236916916850305170057553436136073435791550700526779126605616484319711"
        "51735424574091783976824121860178440448784777337066736659493124795020814172868481356070669407967412616518797057"
        "61216547813649105594986990007847567220787224253724912309650653332895570458720843322485065681189768697291752149"
        "74857589323352085671183814040169149453233350227887942508765678216349436356758463384819478407082224564955746857"
        "8497368723157561724530746784741768646102936863260630088882545875047173194357829837349405264332156553159",
        "51596692759022688970196837706341298598491314420895122094662553697486478852950434581004530951396375324897323793"
        "49334183998359005271540851438475735390060160055101459757369025094548935216928274885474920588457238932199212826"
        "13284811298303020722872923035014307024521461503233009837360681685755548737891159735617529596329620902410098088"
        "88741741043849264397734093528558956831628004860618936254613392484195923653331976713963902238496524583165488721"
        "73632032072142493359961192701645150390051578875246900773560274606831152842526302321197703270752422496079310760"
        "80422885968273410466133336708808535463570182780841768637479016464266039055792524398380821692842122009483810301"
        "7958334974205040660858707963225716195222460679137994123278276584663712976241848458904056941218720227786752");
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(
        cpp_int(res.backend()),
        cpp_int("161697650868559861271540461553971172959149630383872727836174576845991274476610311080533553178926047190"
                "203266855682387778179711917736974467565503622769386238790133592938052615852533561719117119940626105914"
                "149272955096438337875559227137733092417869557531785548219841868720728411947243663889165526728787046894"
                "739482800359519447645962037395419461841363898495986577864710230228655859268881063366400726401157990917"
                "652680450814220027329982285259267693662973801338310334464263818845826026848198196523975624137438165546"
                "650367370131035732951388159175971890099247228360312965057735541872892978783707133028552644759681714224"
                "704381891573964406129272600659255700500824412025869294370532513154961039220948194823131817745018177622"
                "2904306153521050324221361215524333142914455291939319"));

    modular = number<backends::modular_adaptor<T>>(43000466091, 0x10000000000);
    modular.backend().mod_data().adjust_regular(res.backend(),
                                                inverse_extended_euclidean_algorithm(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(140404367363));
}

BOOST_AUTO_TEST_SUITE(runtime_tests)

BOOST_AUTO_TEST_CASE(cpp_int_test) {
#ifdef TEST_CPP_INT
    test_cpp_int<nil::crypto3::multiprecision::cpp_int>();
    test_cpp_int_backend<nil::crypto3::multiprecision::cpp_int_backend<>>();
#endif
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(cpp_int_fixed_test) {
    using Backend = cpp_int_backend<585, 585>;
    using Backend_modular = modular_adaptor<Backend>;
    using modular_number = number<Backend_modular>;

    constexpr auto mod =
        0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_cppui585;
    constexpr auto a = 0xfeff_cppui585;
    constexpr auto a_inv =
        0x565eb513c8dca58227a9d17b4cc814dcf1cec08f4fdf2f0e3d4b88d45d318ec04f0f5e6dcc3a06404686cd542175970ca3b05404585cb511c6d89f78178fa736de14f307fb02fe00ff_cppui585;
    static_assert(a_inv == inverse_extended_euclidean_algorithm(a, mod), "inverse error");

    constexpr modular_number a_m(a, mod);
    constexpr modular_number a_inv_m(a_inv, mod);
    static_assert(a_inv_m == inverse_extended_euclidean_algorithm(a_m), "inverse error");

    using T = number<Backend>;

    static_assert(inverse_extended_euclidean_algorithm(T(3), T(8)) == T(3));
    static_assert(inverse_extended_euclidean_algorithm(T(46), T(207)) == T(0));
    static_assert(inverse_extended_euclidean_algorithm(T(2), T(2)) == T(0));
    static_assert(inverse_extended_euclidean_algorithm(T(0), T(2)) == T(0));
    static_assert(inverse_extended_euclidean_algorithm(T(46), T(46)) == T(0));
    static_assert(inverse_extended_euclidean_algorithm(T(1), T(7)) == T(1));
    static_assert(inverse_extended_euclidean_algorithm(T(35), T(118)) == T(27));
    static_assert(inverse_extended_euclidean_algorithm(T(37), T(37)) == T(0));
    static_assert(inverse_extended_euclidean_algorithm(T(32), T(247)) == T(193));
    static_assert(inverse_extended_euclidean_algorithm(T(3), T(232)) == T(155));

    static_assert(monty_inverse(T(12), T(5), T(5)) == T(1823));
    static_assert(monty_inverse(T(10), T(37), T(1)) == T(26));
    static_assert(monty_inverse(T(3), T(2), T(3)) == T(3));
    static_assert(monty_inverse(T(3), T(4), T(2)) == T(11));
    static_assert(monty_inverse(T(4), T(7), T(2)) == T(37));
    static_assert(monty_inverse(T(32), T(247), T(1)) == T(193));
    static_assert(monty_inverse(T(3), T(7), T(7)) == T(549029));
    static_assert(monty_inverse(T(5317589), T(23), T(8)) == T(32104978469));
}

BOOST_AUTO_TEST_SUITE_END()
