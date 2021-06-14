//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_fields_test

#include <iostream>
#include <cstdint>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

// #include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
// #include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
// #include <nil/crypto3/algebra/fields/dsa_botan.hpp>
// #include <nil/crypto3/algebra/fields/dsa_jce.hpp>
// #include <nil/crypto3/algebra/fields/ed25519_fe.hpp>
// #include <nil/crypto3/algebra/fields/ffdhe_ietf.hpp>
// #include <nil/crypto3/algebra/fields/field.hpp>
// #include <nil/crypto3/algebra/fields/modp_ietf.hpp>
// #include <nil/crypto3/algebra/fields/modp_srp.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp4<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_3over2<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << ", ";
    print_field_element(os, e.data[2]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp6_2over3<FieldParams> &e) {
    os << "[";
    print_field_element(os, e.data[0]);
    os << ", ";
    print_field_element(os, e.data[1]);
    os << "]";
}

template<typename FieldParams>
void print_field_element(std::ostream &os, const fields::detail::element_fp12_2over3over2<FieldParams> &e) {
    os << "[[[" << e.data[0].data[0].data[0].data << "," << e.data[0].data[0].data[1].data << "],["
       << e.data[0].data[1].data[0].data << "," << e.data[0].data[1].data[1].data << "],["
       << e.data[0].data[2].data[0].data << "," << e.data[0].data[2].data[1].data << "]],"
       << "[[" << e.data[1].data[0].data[0].data << "," << e.data[1].data[0].data[1].data << "],["
       << e.data[1].data[1].data[0].data << "," << e.data[1].data[1].data[1].data << "],["
       << e.data[1].data[2].data[0].data << "," << e.data[1].data[2].data[1].data << "]]]";
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

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp3<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp3<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp4<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp4<FieldParams> const &e) {
                    print_field_element(os, e);
                    std::cout << std::endl;
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp6_3over2<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_3over2<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp6_2over3<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp6_2over3<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp12_2over3over2<FieldParams>> {
                void operator()(std::ostream &os,
                                typename fields::detail::element_fp12_2over3over2<FieldParams> const &e) {
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

typedef std::size_t constant_type;
enum field_operation_test_constants : std::size_t { C1, constants_set_size };

enum field_operation_test_elements : std::size_t {
    e1,
    e2,
    e1_plus_e2,
    e1_minus_e2,
    e1_mul_e2,
    e1_dbl,
    e2_inv,
    e1_pow_C1,
    e2_pow_2,
    e2_pow_2_sqrt,
    minus_e1,

    elements_set_size
};

// if target == check-algebra just data/fields.json
const char *test_data = "../../../../libs/algebra/test/data/fields.json";

boost::property_tree::ptree string_data(std::string test_name) {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data.get_child(test_name);
}

template<typename ElementType>
struct field_element_init;

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp<FieldParams>> {
    using element_type = fields::detail::element_fp<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        return element_type(typename element_type::modulus_type(element_data.second.data()));
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp2<FieldParams>> {
    using element_type = fields::detail::element_fp2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp3<FieldParams>> {
    using element_type = fields::detail::element_fp3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 3> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1], element_values[2]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp4<FieldParams>> {
    using element_type = fields::detail::element_fp4<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp2 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp6_2over3<FieldParams>> {
    using element_type = fields::detail::element_fp6_2over3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp6_3over2<FieldParams>> {
    using element_type = fields::detail::element_fp6_3over2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp2 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 3> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1], element_values[2]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp12_2over3over2<FieldParams>> {
    using element_type = fields::detail::element_fp12_2over3over2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp2 over element_fp
        using underlying_type_3over2 = typename element_type::underlying_type;
        // element_fp2 over element_fp
        using underlying_type = typename underlying_type_3over2::underlying_type;

        std::array<underlying_type_3over2, 2> element_values;
        std::array<underlying_type, 3> underlying_element_values;
        auto i = 0;
        for (auto &elem_3over2 : element_data.second) {
            auto j = 0;
            for (auto &elem_fp2 : elem_3over2.second) {
                underlying_element_values[j++] = field_element_init<underlying_type>::process(elem_fp2);
            }
            element_values[i++] = underlying_type_3over2(
                underlying_element_values[0], underlying_element_values[1], underlying_element_values[2]);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename element_type>
void check_field_operations(const std::vector<element_type> &elements, const std::vector<constant_type> &constants) {
    BOOST_CHECK_EQUAL(elements[e1] + elements[e2], elements[e1_plus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] - elements[e2], elements[e1_minus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] * elements[e2], elements[e1_mul_e2]);
    BOOST_CHECK_EQUAL(elements[e1].doubled(), elements[e1_dbl]);
    BOOST_CHECK_EQUAL(elements[e2].inversed(), elements[e2_inv]);
    BOOST_CHECK_EQUAL(elements[e1].pow(constants[C1]), elements[e1_pow_C1]);
    BOOST_CHECK_EQUAL(elements[e2].squared(), elements[e2_pow_2]);
    BOOST_CHECK_EQUAL((elements[e2].squared()).sqrt(), elements[e2_pow_2_sqrt]);
    BOOST_CHECK_EQUAL(-elements[e1], elements[minus_e1]);
}

template<typename element_type>
void check_field_operations_wo_sqrt(const std::vector<element_type> &elements,
                                    const std::vector<constant_type> &constants) {
    BOOST_CHECK_EQUAL(elements[e1] + elements[e2], elements[e1_plus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] - elements[e2], elements[e1_minus_e2]);
    BOOST_CHECK_EQUAL(elements[e1] * elements[e2], elements[e1_mul_e2]);
    BOOST_CHECK_EQUAL(elements[e1].doubled(), elements[e1_dbl]);
    BOOST_CHECK_EQUAL(elements[e2].inversed(), elements[e2_inv]);
    BOOST_CHECK_EQUAL(elements[e1].pow(constants[C1]), elements[e1_pow_C1]);
    BOOST_CHECK_EQUAL(elements[e2].squared(), elements[e2_pow_2]);
    // BOOST_CHECK_EQUAL((elements[e2].squared()).sqrt(), elements[e2_pow_2_sqrt]);
    BOOST_CHECK_EQUAL(-elements[e1], elements[minus_e1 - 1]);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp4<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp6_3over2<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp6_2over3<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
}

template<typename FieldParams>
void check_field_operations(const std::vector<fields::detail::element_fp12_2over3over2<FieldParams>> &elements,
                            const std::vector<constant_type> &constants) {
    check_field_operations_wo_sqrt(elements, constants);
}

template<typename ElementType, typename TestSet>
void field_test_init(std::vector<ElementType> &elements,
                     std::vector<constant_type> &constants,
                     const TestSet &test_set) {
    for (auto &element : test_set.second.get_child("elements_values")) {
        elements.emplace_back(field_element_init<ElementType>::process(element));
    }

    for (auto &constant : test_set.second.get_child("constants")) {
        constants.emplace_back(std::stoll(constant.second.data()));
    }
}

template<typename FieldType, typename TestSet>
void field_operation_test(const TestSet &test_set) {
    std::vector<typename FieldType::value_type> elements;
    std::vector<constant_type> constants;

    field_test_init(elements, constants, test_set);

    check_field_operations(elements, constants);
}

template<typename FieldType>
void field_not_square_test(const std::vector<const char *> &test_set) {
    typedef typename FieldType::value_type value_type;
    typedef typename value_type::modulus_type modulus_type;

    for (auto &not_square : test_set) {
        BOOST_CHECK_EQUAL(value_type(modulus_type(not_square)).is_square(), false);
        BOOST_CHECK_EQUAL(value_type(modulus_type(not_square)).pow(2).is_square(), true);
    }
}

template<typename FieldType>
void field_not_square_test(const std::vector<std::array<const char *, 2>> &test_set) {
    typedef typename FieldType::value_type value_type;
    typedef typename value_type::underlying_type::modulus_type modulus_type;

    for (auto &not_square : test_set) {
        BOOST_CHECK_EQUAL(value_type(modulus_type(not_square[0]), modulus_type(not_square[1])).is_square(), false);
        BOOST_CHECK_EQUAL(value_type(modulus_type(not_square[0]), modulus_type(not_square[1])).pow(2).is_square(),
                          true);
    }
}

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fr, string_data("field_operation_test_bls12_381_fr"), data_set) {
    using policy_type = fields::bls12_fr<381>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq, string_data("field_operation_test_bls12_381_fq"), data_set) {
    using policy_type = fields::bls12_fq<381>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq2, string_data("field_operation_test_bls12_381_fq2"), data_set) {
    using policy_type = fields::fp2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq6, string_data("field_operation_test_bls12_381_fq6"), data_set) {
    using policy_type = fields::fp6_3over2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_bls12_381_fq12,
                     string_data("field_operation_test_bls12_381_fq12"),
                     data_set) {
    using policy_type = fields::fp12_2over3over2<fields::bls12_fq<381>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq, string_data("field_operation_test_mnt4_fq"), data_set) {
    using policy_type = fields::mnt4<298>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq2, string_data("field_operation_test_mnt4_fq2"), data_set) {
    using policy_type = fields::fp2<fields::mnt4<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt4_fq4, string_data("field_operation_test_mnt4_fq4"), data_set) {
    using policy_type = fields::fp4<fields::mnt4<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq, string_data("field_operation_test_mnt6_fq"), data_set) {
    using policy_type = fields::mnt6<298>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq3, string_data("field_operation_test_mnt6_fq3"), data_set) {
    using policy_type = fields::fp3<fields::mnt6<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_DATA_TEST_CASE(field_operation_test_mnt6_fq6, string_data("field_operation_test_mnt6_fq6"), data_set) {
    using policy_type = fields::fp6_2over3<fields::mnt6<298>>;

    field_operation_test<policy_type>(data_set);
}

BOOST_AUTO_TEST_CASE(field_not_square_manual_test_bls12_381_fq) {
    using policy_type = fields::bls12_fq<381>;

    std::vector<const char *> not_squares = {
        "14798052293848972207340588924335040520510143374686419653187390510594321928734789695669598795436983261541493433"
        "33408",
        "39712079266920692346674819688532168566378257996103780706306612642709680993338218886910345858741543217074438543"
        "6176",
        "30437732637067352016646719732788310803313453035601842216590484834487185077552976291597795651136310493591745153"
        "83291",
        "33648813561238216214517870412076799902980786995820192981867235689485429146062658965521362040571488020775692114"
        "56496",
        "90453611832741537854770256822623373768287133316099138215773567220972778314373782679776769559310649835872302232"
        "417",
        "27499140387422537651563142938643876939300307618891103564173219539364250297925848265276700983799800704563567074"
        "42024",
        "30910040868303931509999323590363683169003531722367256064735587751063058385304731851142664580127975750560238420"
        "20856",
        "21454368578183607665821511409741305583580287802791308029601615384416008539016529284174898427932428574310489018"
        "79630",
        "13624728773090142490231352789880682438236301041479839832524232192682622460157337638373560830032777512320972294"
        "86539",
        "10132496315768143321266586309303007049223702187328866829238228935279280420784867713044566703991757215784020734"
        "21784",
        "24537345975872460052887434635018774244475291780135633079725569892329917000317471034559657557183776739291074879"
        "60733",
        "32145378024412093505717894468662097165288630561532979748376501237783182135412458465559708724608717358112615855"
        "91943",
        "31691357787900514525490454886074010803568186423378248427149060175917179861362566139693316924952897711454287314"
        "40142",
        "35620343168913580816752687437059807235778238249509505708491220041118601237404501730267091412299870578543406275"
        "83020",
        "31823709335802178818161946448730102227702587736742113773241773189460861850558162865483116287852948050192136609"
        "59978",
        "16423322200611540926190205996140291749718076790949387613430978575151214999852320549640131598568216358154749876"
        "09568",
        "23614422615435697867358056168922200095680950162124116240067280447084343168300219756432141436171800875640522240"
        "9124",
        "35439171908629835243813423869055378770432674774759888352989949403693791042560265514562893067269835484302325553"
        "82440",
        "15703788354521237496732554038962775983453673716285566435550173946561159749309385057845845259975370353345320323"
        "65197",
        "12049721758579366441064232790687393313755067468922937527962916933531372039011318003298942065523447784984711764"
        "4077",
        "66075261791471525289161157360640617433681853816126294954310279954169125240430421968813555918392864931207633445"
        "9610",
        "26829020805715772326743934098858302153721345692258457691619140569142299693259060198468591034503041922226052814"
        "5380",
        "98154544965790700944636956506080903946408386322481882487638471326645820997940997316668782370136245428320523525"
        "2408",
        "36385894980500032083680278885198164586870249615577424372452461210054927001906147396104120951540200143679011084"
        "86749",
        "31715638142966653787448022051157365152243464621995062823488705755192878132760297388586182273193289744164668390"
        "78835",
        "10134558297615026769843892670904505531998550201870653448049701062597299528558836929041980421236655327462458302"
        "17321",
        "21981440158110618118826195305107060915310115728763097696230599296166329572519234649480695351956320133383864905"
        "61341",
        "24891154809121912545017123060313874638213498038277282796893997603012159143657945836627072227936087834436936998"
        "47793",
        "29626735728531916663926238047381425087783351525729545465141333544400726606233503010197123867008639033115035679"
        "8061",
        "22339256052462318453109895372692575153747409797872079315372200149136572625782555066119514982329393794221499613"
        "06689",
        "34471495862377993571059269593584820354662606220858319831342764737924427720458721513973341981508099453664505169"
        "89392",
        "13267847232711516229525688916801264055512063258169620790344406060621291583679010250002568213539113303268276787"
        "84769",
        "71928479018445016789360257233564660912013612760874327636764802295463755455521586049864970466549523176740659801"
        "311",
        "26376395947688936973085655424540721203858768874776778542414622610039101962394451645088776047632608369299421792"
        "38317",
        "13352591174304364471465650372775907842681369218783732726372645737524257522641111055268548023234990524942481048"
        "96117",
        "16759019492954826220874952699145088811035664386812953583663134049471201515002273404004538876116832079880751954"
        "02850",
        "21439800070247168065922063029372747893790584032778838736817086766347778481223351475971843213419015343157777666"
        "33334",
        "15875413530963318575320496585796091624654803501945260615829637780347617199215292542498625937680769053629840921"
        "80319",
        "24527011568788073077126792161989601815795607675934579907988942517349342208301189589401985388777810671388254491"
        "42453",
        "82722464250301743316274190476489709733507394898523750183460303929192304929929134341958509129214308031336096121"
        "9416",
        "13469795168482875541158234801669731583427299397267334768031586816079365621010943061885664626369575927232259885"
        "53661",
        "20951512242903182567255166681225117533125160728251659943573365588360963858110548863022884477326239684900225852"
        "79390",
        "27119713105584512168374466285212293561622558319010508109190696173630594770704513511209729245253990274598955395"
        "39673",
        "32177072430820423777555335844179269007359202450213259400947973860004284315377684819073677618766182649603578639"
        "41941",
        "39160765124901259582141868453825559908990040242034413030271648239122647780270221273229411976176614707829187956"
        "1376",
        "36677069777369261429464931481787054424402242381657362657241073118094491296578599592647467186861731404876260956"
        "60134",
        "72621363886686492741388497004114052565012721241609057700879042888588752093330272581534534086977606070038822934"
        "0357",
        "26555740541885503624250947439684419053188827856090387114367383919132273182608483469058377457119691298216222040"
        "61716",
        "33363221345011483039044495359037658525515852605993370148042132133250267261425253515371358642797745548616749757"
        "43591",
        "61650830347044927981003560870707032253788196444921942304541669864000851918735836607175984283162576769881184841"
        "0577",
        "15523244470033665892820959583078581720774582725289016949309257786980270962209638044494723747649076773435436237"
        "24417",
        "36078781939548318881579092608237683722371088406502649508165923659646358598354236405603097017778870928571271061"
        "75699",
        "28581221026942882189566080426844593734313310843573893707963778525332002584561033843698399164053284815523192763"
        "11184",
        "17723406837671481508003272246677690806955189307590507783677530607210459653740582014845219888951811764094819654"
        "69230",
        "37365858861230478538375594948228190529436591495709699766233567607985428763461671870968244498748765057240656072"
        "1356",
        "23258557920092251126616910387596907054913072678640042312661833099145180843632392888883020425952818884694310689"
        "55962",
        "25477907744083704314937483316339606380387190863108691177262421960033993890005357966627121636757336538192532497"
        "48110",
        "20075395544450200732287510364060151406592230081912305368220539979505535837264300155791386887210587654001547168"
        "03640",
        "80598556922993390417423293642640712997537816015644342726065754864309750084056536770587488947663192041823199743"
        "9407",
        "10182723030942039774694009636608734117625600285984477892289789147935036183005038261245685429526567877171046677"
        "90324",
        "17827308036247345141963845447558817125392749874628471271441897440776402286764762617068579561100161312257108297"
        "36936",
        "26852938849137272493427827197694253704762746627554571423716841027053020382266873389981347299950692687386862201"
        "46790",
        "16472496190913092856477096759067994988839588060093007002132608246297714518329550498640178753906453962129466045"
        "28228",
        "75459312275448002588892844259588155729770277795022044903252933560923306870320083607625171176716916294163463366"
        "0620",
        "14432399010414699025883221245104789438494417863433088017279423592658672515762458425015133482194144754263918091"
        "50012",
        "69348224852776383394504706780524513549841914133684083297165769199941980935803265880837350183576783099216123723"
        "4186",
        "16415393153001248833481974142363798689294979399270971755274820122797706867803491103474866571039477852660185309"
        "12102",
        "18863599484052720325092009722004878384990955460702513859221613139835402660835899305362469988495754103419284723"
        "78431",
        "18410878244865700907597349835061292177879842897231383748167148634385948210383343594324095004429609644697270109"
        "57731",
        "27836480498774430186235695851398320851967621884113958964417044338894287966733238549340985092740186942816662603"
        "48478",
        "84206824650290446014071858522589547524916456670624266476022452107925968161582601159792296004691484237536582269"
        "2973",
        "22455219340709094075511454576785971858900736190045095418619402544078953188319907202690121553261200805634975293"
        "5244",
        "16455924956184322398689093119117685180028656537551277657127902104656270414957870999506653562632370685322963844"
        "29137",
        "12321965984594470489905968817477699027877303507358894302568497176933196308910193476344450462022278989373475258"
        "42",
        "16071244194833398594730367506937546296068587399028511414623550202616778299565410935577228949967560457686268420"
        "43563",
        "18251305470156838861271007631986528333114274224289373995355948574704490305620181473691105676460002404051883520"
        "00066",
        "12532600980590001986173943880328069694080300518606390192997435098258814090423443864933545941252603411196980353"
        "60754",
        "23133100632022785117739999630964322374142772536350467229249198243709793512004774820112822642265925571152712187"
        "75926",
        "36902421150344477411997780560920454127138360828948673997774022917892101695604020659469035808835164338116510387"
        "39438",
        "18950956523354228627169005871597488877997700417113515101101551174709898134561996635271664663649723383339998112"
        "82448",
        "31666212085390170538166454085128464657741478993303252005194784090716581505956876358558238899382568501105262326"
        "84343",
        "31437305917864443209363299630254311322887815312631634243039871803435072791017897702095711629000003640599060793"
        "3737",
        "11349682347919117454587816106523078357630690342841008334260257323397909893679994199811301296052039169561079159"
        "3264",
        "94006650907441761073256710828530919158549684920488262255270707902226670547458890042451973371086490984644842101"
        "8197",
        "27706421791962032129217094580339048105811561670658379473625204383409038326005249216204727362893203749270506918"
        "97641",
        "31481253073658569212200762369433572708232558628303414011714747540073499082032367071387968812429987896485991786"
        "36755",
        "11753410467094723625224893381677264028195941004109267217790184627383145371378839991661413160510867840329487120"
        "27268",
        "32038540544608759440658054923664836799586644961683597665908900451860074198844545031171898934306400116226327215"
        "85216",
        "36214919840128469649783618341976865862867485236755844221501488048291475740418619111056304485442767124069767944"
        "01196",
        "16444934353050239262899174054231173576290288609003927920419432314199930480512391707078890543066240795908432868"
        "40623",
        "27378436025031376123917208606867748541033130417681030857870313588146303546262690410187807151887255991037215417"
        "85108",
        "32019684434623159028356438771387203541627990573991429213469798378999871268417784733979152361445491944571342527"
        "64436",
        "24916153982712028318928014894482328801011095831785489292565188947665207246760530215959274815675415990928798086"
        "63373",
        "31795522904040423907808524754258211935475571746851232799302632323065868012741843862937938492146229113732071195"
        "31585",
        "14926590299009453260728869790739934009013592088722362707932360636480427731350913582878448930502490173993570320"
        "81352",
        "52357605669314242677183632131247688292169794671778203803161318907537394072753431320718563796152622312302363221"
        "0136",
        "23257448865669570089644679127871561158376868975258261702655584251083249226668577733538413468582661997538222684"
        "63314",
        "13526716600176256922805325617302685566280968984946756824573066896693486828993389432785108036725050139097546286"
        "83416",
        "15623356576392550217235925013503286265229363112446924792956727285996469224050337417645037895606188495669681380"
        "53334",
        "27972903749962434207475053636092052721043106173102435683666797493472467595675307953412140803338237401282911808"
        "99326"};

    field_not_square_test<policy_type>(not_squares);
}

BOOST_AUTO_TEST_CASE(field_not_square_manual_test_bls12_381_fq2) {
    using policy_type = fields::fp2<fields::bls12_fq<381>>;
    typedef typename policy_type::value_type value_type;
    typedef typename value_type::underlying_type::modulus_type modulus_type;

    std::vector<std::array<const char *, 2>> not_squares = {
        {"3524621578887081555995618340212814089553799753665493370168024281656572217651956527488772586862482092190213449"
         "990545",
         "2997139273125515018699684898762662382901843308368533912696429988471797207078446595394092635518883976094889122"
         "035858"},
        {"3564246808941678095635411463598246864388410716124994071489326707020269793370874405544231138239965901828674257"
         "013647",
         "2774579600304003539482221790352156607206391406374377664227692213787545556222115254152232143203100490442762620"
         "34787"},
        {"7759727850579331796135541092951204727486212635551706572283445218095385180768815765608629124267097225768995451"
         "1443",
         "2164894066515734677088447520576896486795681729999055719580899126833251125744148632196441755751293139467858042"
         "975787"},
        {"3674660641533102899280319520439457787130695406399408914486368205071400986529552541380451273592996674531390369"
         "765608",
         "2185202060649305799215022551786211995506473249650593152193889725638367966400675630901440656303783797320404894"
         "993242"},
        {"3036822800038422198568955507658098786558522649543461300487788921906619595929710719336622624278535634073320166"
         "883167",
         "2298745317833798074172701618875140973591070816299352401316326193298775638105228444145756073798773481353251663"
         "288987"},
        {"2742000460458143089020406777009068400023330500124476370493221145280899821579970072115391703105879376716935586"
         "886384",
         "2541518826947723870472255431986815775946776915735407390654200033315380977946195216475762028597597986717552754"
         "536843"},
        {"7588326004758775351462635148269899594015767865592793404760130432187234263705116826042600253530937590358742859"
         "05363",
         "8119349533231161668655914690352688184224084766464475504299559899296662636878155745649787203870346361482379137"
         "78940"},
        {"1952666677358004585217231086904530218591022288708809861646858081568761490109078296015975106012976833059437363"
         "014667",
         "1535532434594101719731250807486481643229054089297120974089667385800140384058672170704255677709414151219483868"
         "535131"},
        {"2650652255073423405756896495140772757351358479639348907254174569143287039310884545326891561193731722792728058"
         "853282",
         "2652879980091272244978074284649346814115478868930937728039995140317784424425367127777987075646235416883836997"
         "901518"},
        {"1107151598649570125978385225201152563185542513856261079587097056984811464759037976744598610335635074497658569"
         "75014",
         "3366582040926142210771642506402676314670377952363233648543463141914880049418305563525919217144219039687962401"
         "969057"},
        {"1444775858635512507935155873342029536608279323589262793412200091344886577511124081546241753053859737027507216"
         "47971",
         "1309831305768740282054650244417164397026893216519053641682972495634541384952114038919061775224155866446099713"
         "513805"},
        {"2931694391738261579713986424423765727595707462299975551435496963061918529409863771580288488091323576078609215"
         "351001",
         "1194086403992716412339675150567113478065088274321669262888162513527628395974007254418440716413676704915584539"
         "431098"},
        {"3509356302379743727050385219321201801288781515079131520441644944201276251013477134878327273470093188955442796"
         "923614",
         "2650196358613441383213820238146669046391580468364059157812215339976907805119694185980963990362764220372582771"
         "038560"},
        {"2443397566112686712138260371925130268104647696850991218559669198821175576222037442735719281760674558336774984"
         "168586",
         "1938449318465163832759082451699982907882227369713806127073561777862245120770858796629087314360522425440680553"
         "094980"},
        {"1233911381172260711291459750072396006023004908441736155422758614669239854649773334971610663217960113086581798"
         "158921",
         "2097017809718631194959498369186694019246373585275393033175286471126333152390175278673637519028641684200919958"
         "435910"},
        {"2323576286752901820643696956817719883360545885361887461930759859925896538135831293962526915796437566976245510"
         "116086",
         "6467579608040342059963910694198805017801879870175007907913286472815222782756535443361088911818046460641717505"
         "32896"},
        {"3788806276267829417527368179910100858736975573570382055329930201695609716613844166866547778203879356432380852"
         "385119",
         "1498771001633580255051246971617688727606721081459069294996507384481787744646662889991758005655311996101027995"
         "216005"},
        {"3467086697977455527442330975311437637708891370556483475086950470006239346869549867660613391944731557432095457"
         "118650",
         "5220493558271308427818990611559934663042286254229422083362210817165546408463359551873067248262117359740604586"
         "91116"},
        {"7342663167363440032873771690633486466229522617499206087093749304090413584787885684309800204885037244192666164"
         "69957",
         "1572733118152311114892634861199683399223663577769362648755336203822320409132259363952522531968718380492575768"
         "125954"},
        {"2218496956645252588600371392732629274103231450211326739470190322096601978008538684422634512635538245996319811"
         "980173",
         "3220373206147532892505183064611071678852567334919681260050383149831892222322327345297761610339610007872595503"
         "4594"},
        {"2757437369802124814318226712317773214211176646118226825533613092823115772217869912345417795449724416513445388"
         "753295",
         "1206426677797137548090870167834910936377839505379875369305314578462022212561540454724401903642732345652828357"
         "82306"},
        {"2285381698596846983570995504408855287036345699818983858976538537272957413029546922234599252088419094750071565"
         "77532",
         "3547331871757455233762868073134046654435282035468432019108888362092224899667777739242047212339819334292398005"
         "115114"},
        {"3083501401902636614302943812087363655352195778912541454765776658843245311628183359455176206831397294230370349"
         "183792",
         "3286030203760226708924994228693480604210788710062385664970715265530018866198093115572531866278402306912242859"
         "440352"},
        {"2977350762771168255789950541400723997605645144478261630602195860761162103691196517531938742515306130023814821"
         "758500",
         "2907575211337221026600862414335354661261167111468683701830547668405988117453493590621339430549979431870079535"
         "471118"},
        {"2182277779787677461434312303007296553910683385507101104008471651981978593342779822877071407238624738762507660"
         "126730",
         "2810394095184918683241100134995999855360877471175598008638572375618961063176553858871680626514569562950243456"
         "386199"},
        {"3677881760888432125385947311430098533229811096916720585651793681955936525940323570400651412234995493343642069"
         "010250",
         "1572774135484231903318907400511898391217873542288047718980237743150027608830935566785765227497819396444835169"
         "621106"},
        {"2371872609213487810571283246300659850417363047493058536097995373373726853847142530302347306279772650901346976"
         "203445",
         "3203094168299568345301435842006714781469656166635493009071902297401229716208893582937042082329374371813951494"
         "306716"},
        {"9829786825146434493208210403532779930912620355514795299209386802586574795262267238460809800163196193250244889"
         "88697",
         "5375094837906398874824593764549676243586948958853603494446070133921594225672475627202726381910681199345868123"
         "95145"},
        {"5103208238309811095638978253788176668571174020715165722241324446964947756463106546087477990269284473495559123"
         "34566",
         "1456483090829430439024003382099468059479130123745603366524073070130635600072121378473394134822818328353996720"
         "469470"},
        {"3922478709317270821047833773278439662708259569912459762818423201957590850558999651970498893711870137336354387"
         "993256",
         "5712683327619183210035264498048551080411326705309749971147246305290064657180973662353746110038628515870627528"
         "69348"},
        {"2443671995228042579279442424892431969114744315609492360961526591876408030624420697191408019255819775807614746"
         "537995",
         "3865242522264468314541362659193991677934245281136918400204493270895630816407850644892287026288093482841791795"
         "485306"},
        {"1631346268348927340593985788688734524791327161240274701412145824617982157119183144563090458928919356663159686"
         "506756",
         "4777146551323207377211680999935794547952515595654572762832076433983870555884794105113782686601176943244678319"
         "68102"},
        {"1934289272610377026714890582195967776295219556165073232873931438376550665777367705345908067786228574427053943"
         "006511",
         "2560432896194571055400327532565219616689250583900456151279175378601879562944870120170916296023102369732376447"
         "051034"},
        {"1807506478838978472208472540105760739989567723850150181865004172859735880436662546623286641423612284367981748"
         "516357",
         "3213108824056420823840521557467430043754818496558522741108608252988507935695800526752285071460110757189011615"
         "262626"},
        {"3646276628590556713040394934065215991099337997882900704565271241792737332574238021771713489132221172870498970"
         "294704",
         "1256105650291373953355984579832098363653424634841533561860096445221144570331034906983889448532702867309628577"
         "405660"},
        {"2296011666211783666846153688233669670743739794344352985285963173527499695049153760583042054244747921407658385"
         "179355",
         "3745744157480594867553128623703261295333716855548521134363895479482175936208385908263697641250313570158739818"
         "98839"},
        {"2284671070430950233878746998796515119777271632036028866557954031376465166979630553141119863188730842899088100"
         "032914",
         "2676069971043850192364857366095070318652943890403585339366464496459930398820919933725923940977464839625406484"
         "813982"},
        {"2593657995218521054926984314099988264259671732916630931942345138526655148763372584607789995844530396772195270"
         "953202",
         "2799604882543244875681415125311330699175081600118857507033631630515930822573386300685739245122090360441227485"
         "750060"},
        {"2518871760295746296591469754766752882984592225482943478802921372365892871748380615966511406722885873721455726"
         "678097",
         "1975222708845983598640172024970485884421170358716499700444406387106911798106550340432338619017700065641965600"
         "423212"},
        {"1651495879555023658689901386772259862854228566103168062299101002252019018486560305440315463298922797999270366"
         "72144",
         "2079561383242630447666366395575198998074876725973372217310163195422512328790137110735073268761276535961018226"
         "295163"},
        {"1098846469804320705680130443266433874810123856334045188313076451183936887031093362811107820362454759277754551"
         "942603",
         "2970096646469282957849782747241136098814452629893282391228200768521120537892626046397094762239187881629102874"
         "557117"},
        {"7210781818864753101497505076490191689692916186624670854155853247378103947623371513730890554071720944512905888"
         "25129",
         "8824564281320131794612766301595572153766909322192862567559177043915171139835133457720599039567903036245171258"
         "33141"},
        {"2395205032237597885481222076915298640541578853768551706782023493934939331129882687934897864958431820387030706"
         "41505",
         "5717554556379791063066574351108410477101825384572801988688304289342850423012618461224845391639388685408165827"
         "06294"},
        {"3212978526646705863115424864694760378501200909134629039808882642347406354620817621740231831700837600051955781"
         "922961",
         "3436539423781039276241449591218523583731717750753035513996426259559159538630075048506416800079786689681995840"
         "638923"},
        {"9564612818835064762913161048715426928822914044173197944395779003384591069788498131863090820308281085026530939"
         "49412",
         "2613881937128413644694972362667794327170791767185406733062897664805422910140708329733265364529569629565075396"
         "606612"},
        {"3056034126153780736410661320761057187688208239229649676872549207761238866554107258081890675233689179818915647"
         "150897",
         "1828707019700727368336907649442336602808914339695666434878438422728125360607634681381082857713986483293980377"
         "609189"},
        {"3487323257636816599165640350437341054318435938787891421212178942910347620599164937484451417558696085100347506"
         "828381",
         "1060915976455763715849738377937059868917776517551951226593589941601758901491223867868263573323835134649736259"
         "372149"},
        {"4334609349803680622689340533110278636369052327517115111588947328744826941256256431787900389426838690797875450"
         "46688",
         "1039247787489576235086191055755242789000406986051667827990237444336007410901228624998014556366524001619918025"
         "366721"},
        {"3617783597292364173076779690123543030217522155736651060134169396150468292730637577615291395924714082450619497"
         "851056",
         "1703885056985973175302966288562280058409752375166197708846424746667250785494510527964185892236783231296344348"
         "04692"},
        {"1096916472630315787436980584119528858127708300569982989180237327944374355497533188615396165687637610768585586"
         "455445",
         "2640176492834849883219946096033044590172299031367907480467006647068157735837078241634565704609193494909958475"
         "634303"}};

    field_not_square_test<policy_type>(not_squares);
}

BOOST_AUTO_TEST_SUITE_END()
