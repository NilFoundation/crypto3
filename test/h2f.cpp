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

#define BOOST_TEST_MODULE hash_h2f_test

#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <type_traits>
#include <tuple>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/h2f.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/type_traits.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    std::cout << e.data[0].data << ", " << e.data[1].data << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp2<FieldParams> const &e) {
                    print_field_element(os, e);
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

template<typename Hash>
typename std::enable_if<hashes::is_h2f<Hash>::value>::type
    check_hash_to_field_ro(const std::string &msg_str, const typename Hash::digest_type &result) {

    std::vector<std::uint8_t> msg(msg_str.begin(), msg_str.end());
    typename Hash::digest_type u = hash<Hash>(msg);
    for (std::size_t i = 0; i < Hash::count; i++) {
        BOOST_CHECK_EQUAL(u[i], result[i]);
    }
}

BOOST_AUTO_TEST_SUITE(hash_h2f_manual_tests)

BOOST_AUTO_TEST_CASE(hash_to_field_bls12_381_g1_h2c_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.9.1
    using curve_type = curves::bls12_381;
    using field_type = typename curve_type::base_field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;
    using hash_type = hashes::h2f<field_type>;

    using samples_type = std::vector<std::tuple<std::string, std::array<field_value_type, 2>>>;
    samples_type samples = {
        {"",
         {field_value_type(
              integral_type("1790030616568561980207134218344899338736900885118493183248255875682123737756800"
                            "213955590674957414534085508415116879")),
          field_value_type(
              integral_type("2474702583317621523708233292803940741700450584532633563728739973751669085848991"
                            "00434893060702108665825589810322121"))}},
        {"abc",
         {field_value_type(
              integral_type("2088728490498894818688784437928579501848367107744050576780266498473771518428420"
                            "173373487118890161663886009635645777")),
          field_value_type(
              integral_type("3213892493831086209316960640873433141017158792584421675273329354360198845384332"
                            "7878077294514665889481436558332217"))}},
        {"abcdef0123456789",
         {field_value_type(
              integral_type("9505970308164648217789710156734861296414103440788614747505275085378045493860586"
                            "12983484048401731236595379325781716")),
          field_value_type(
              integral_type("1979385000937648348925653198641340374887185657649818450486460034420643425685140"
                            "133042050299078521896600910613745210"))}},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         {field_value_type(
              integral_type("1565983848840546529547071507571383550794102107851138573768250148104411885455485"
                            "95465313883035731540725116276838022")),
          field_value_type(
              integral_type("1709027689043323463259398100486189187238532958310276339146988040422594808842792"
                            "053521671901476006506290292962489454"))}},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         {field_value_type(
              integral_type("1625704516324785166230868561544190006281306318060308039760768255839116494270087"
                            "378351796462565313509233883467016390")),
          field_value_type(
              integral_type("8973476190440398924261230730510508241136153370908604317306021021786458550458325"
                            "65883684732229117125155988066429111"))}}
        // {"", {field_value_type(integral_type("")), field_value_type(integral_type(""))}}
    };

    for (auto &s : samples) {
        check_hash_to_field_ro<hash_type>(std::get<0>(s), std::get<1>(s));
    }
}

BOOST_AUTO_TEST_CASE(hash_to_field_bls12_381_g2_h2c_sha256_test) {
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
    using curve_type = curves::bls12_381;
    using group_type = typename curve_type::g2_type<>;
    using field_type = typename group_type::field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;
    using hash_type = hashes::h2f<field_type>;

    using samples_type = std::vector<std::tuple<std::string, std::array<field_value_type, 2>>>;
    samples_type samples = {
        {"",
         {field_value_type(
              integral_type("5938684483100054485611722523870295163604099457864574398759743150316400213898356"
                            "49561235021338510064922970633805048"),
              integral_type("8673753094890675127974598608873659518770540387638184480573261903027016498888499"
                            "97836339069389536967202878289851290")),
          field_value_type(
              integral_type("4578897045199488434740260225626419694433157155954591591128744980829534319713238"
                            "09145630315884223143822925947137684"),
              integral_type("3132697209754082586339430915081913810572071485832539443682634025529375380328136"
                            "128542015469873094481703191673087029"))}},
        {"abc",
         {field_value_type(
              integral_type("3381151350286428005095780827831774583653641216459357823974407145557165174365389"
                            "989442078766443621078367363453769585"),
              integral_type("2741746953704442638534180707453397316404679193551841082537168795196953970699630"
                            "34977795744692362177212201505728989")),
          field_value_type(
              integral_type("3761918608077574755256083960277010506684793456226386707192711779006489497410866"
                            "269311252402421709839991039401264868"),
              integral_type("1342131492846344403298252211066711749849099599627623100864413228392326132610002"
                            "371925674088601653350525231531947366"))}},
        {"abcdef0123456789",
         {field_value_type(
              integral_type("4736756665618245326244300857865191860224326611904114213007749037224882541543738"
                            "95989233527517731907580580706354657"),
              integral_type("9520540557415691916362510867127307131683791692159959526594533787977337613244945"
                            "87640793580119096894387397115436943")),
          field_value_type(
              integral_type("3574336717567028224405133950386477048284620456829914449302272757384276784667241"
                            "972055005113408837488328262928878231"),
              integral_type("2365602345707797244937763470382803726723577073883311775921418854730692345417958"
                            "26215789679703490403053611203549557"))}},
        {"q128_"
         "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
         "qqqqqqqqqqqqqqqqqqq",
         {field_value_type(
              integral_type("3608131929677217503005188861991391449980483387988256142839334881042292007389752"
                            "19634991234987258997592645316502099"),
              integral_type("5009904385311786096049606538586133897401985944525938049981086917265658825017777"
                            "15476408413735192405455364595747963")),
          field_value_type(
              integral_type("1414201600433038156752401103621159164529164806638579329495300394501933973057103"
                            "319123042671630779248244072674138005"),
              integral_type("2580989994757912640015815541704972436791025324967858519264081257257405036397177"
                            "981572950833626047365407639272235247"))}},
        {"a512_"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         {field_value_type(
              integral_type("3854656460966118202185202795415969034444473478700041637108073179423449626727403"
                            "291696647010132509133525205314259253"),
              integral_type("2873494353363126311409085895530381085174075451844000378947122252646711114869905"
                            "923958066527312260237781765269081913")),
          field_value_type(
              integral_type("2218682278840147973132952196327912255143646871258838127959845658885016361690895"
                            "544274403462155614933990666846598837"),
              integral_type("2692054640040186323570630735219910885988179020142391687801930252786130591827501"
                            "100656577702624784849458500251540952"))}},

        // {"",
        //  {field_value_type(integral_type(""),
        //                    integral_type("")),
        //   field_value_type(integral_type(""),
        //                    integral_type(""))}},
    };

    for (auto &s : samples) {
        check_hash_to_field_ro<hash_type>(std::get<0>(s), std::get<1>(s));
    }
}

BOOST_AUTO_TEST_SUITE_END()
