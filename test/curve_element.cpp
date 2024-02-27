//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_curve_element_test

#include <boost/test/included/unit_test.hpp>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/montgomery/element_g1_affine.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(*it);
    }
    std::cout << std::endl;
}

template<typename T>
void test_curve_element_big_endian(T val) {
    using namespace nil::crypto3::marshalling;

    using Endianness = nil::marshalling::option::big_endian;

    using unit_type = unsigned char;

    using curve_element_type = types::curve_element<nil::marshalling::field_type<Endianness>, typename T::group_type>;

    static_assert(nil::marshalling::is_curve_element<curve_element_type>::value);
    static_assert(nil::marshalling::is_compatible<T>::value);
    nil::marshalling::status_type status;

    std::vector<unit_type> cv = nil::marshalling::pack<Endianness>(val, status);

    BOOST_CHECK(status == nil::marshalling::status_type::success);

    T test_val = nil::marshalling::pack<Endianness>(cv, status);
    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<typename CurveGroup>
void test_curve_element() {
    std::cout << std::hex;
    std::cerr << std::hex;

    /* test infinity */
    typename CurveGroup::value_type val = typename CurveGroup::value_type();
    test_curve_element_big_endian(val);

    /* test 128 random points */
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        val = nil::crypto3::algebra::random_element<CurveGroup>();
        test_curve_element_big_endian(val);
        // test_curve_element_little_endian(val);
    }
}

BOOST_AUTO_TEST_SUITE(curve_element_test_suite)

BOOST_AUTO_TEST_CASE(curve_element_bn254_g1) {
    std::cout << "BN254 g1 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::alt_bn128_254::g1_type<>>();
    std::cout << "BN254 g1 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_bn254_g2) {
    std::cout << "BN254 g2 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::alt_bn128_254::g2_type<>>();
    std::cout << "BN254 g2 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_mnt4_g1) {
    std::cout << "MNT4 g1 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::mnt4_298::g1_type<>>();
    std::cout << "MNT4 g1 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_mnt4_g2) {
    std::cout << "MNT4 g2 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::mnt4_298::g2_type<>>();
    std::cout << "MNT4 g2 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_mnt6_g1) {
    std::cout << "MNT6 g1 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::mnt6_298::g1_type<>>();
    std::cout << "MNT6 g1 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_mnt6_g2) {
    std::cout << "MNT6 g2 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::mnt6_298::g2_type<>>();
    std::cout << "MNT6 g2 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_bls12_381_g1) {
    std::cout << "BLS12-381 g1 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::bls12<381>::g1_type<>>();
    std::cout << "BLS12-381 g1 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_bls12_381_g2) {
    std::cout << "BLS12-381 g2 group test started" << std::endl;
    test_curve_element<nil::crypto3::algebra::curves::bls12<381>::g2_type<>>();
    std::cout << "BLS12-381 g2 group test finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(curve_element_jubjub_g1) {
    using curve_type = nil::crypto3::algebra::curves::jubjub;
    using group_type = typename curve_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                             nil::crypto3::algebra::curves::forms::twisted_edwards>;
    using group_value_type = typename group_type::value_type;
    using field_type = typename group_value_type::field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;

    /// deserialization of correct blobs
    nil::marshalling::status_type status;
    std::vector<std::uint8_t> blob = {0x5f, 0x50, 0xa1, 0xdc, 0x87, 0xd9, 0x9b, 0x13, 0xb3, 0x60, 0x2a,
                                      0xe1, 0x25, 0xce, 0x0,  0x66, 0xe2, 0xab, 0x19, 0x8c, 0x92, 0x69,
                                      0x94, 0x13, 0x13, 0x60, 0x57, 0xa8, 0x1,  0x21, 0x2,  0x41};
    group_value_type expected = group_value_type(
        integral_type("34431432384332876907572759816814758423306059590054253468360681509944827160006"),
        integral_type("29404096654359671878917481308573927330727282437544669652502934947226949079135"));
    group_value_type point =
        nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(point == expected);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    blob = {0x8c, 0x59, 0x25, 0x37, 0x5a, 0x98, 0xc9, 0xd0, 0x5d, 0xe5, 0xb4, 0xf5, 0xc4, 0x7,  0xad, 0x7f,
            0x6c, 0xf0, 0xf7, 0x69, 0xbf, 0x80, 0xca, 0x2c, 0x91, 0x33, 0xcb, 0xc4, 0xd8, 0xa1, 0x3,  0x85};
    expected =
        group_value_type(integral_type("51845316313984588131191635700847278221892447412874386787531559514756013022179"),
                         integral_type("2267981809345781868602884763436767012634799368758626259799403354148032567692"));
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(point == expected);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    blob = {0xa4, 0x13, 0x70, 0xbc, 0x2e, 0x20, 0x40, 0x11, 0x57, 0x60, 0xd5, 0x53, 0x91, 0xcb, 0x8d, 0x6,
            0x23, 0x74, 0xc1, 0x4c, 0xca, 0xe2, 0xa5, 0xe,  0x5e, 0x66, 0x85, 0x24, 0x81, 0x4f, 0x7a, 0xbb};
    expected = group_value_type(
        integral_type("25651767798190354528910599415746062172834836761677597036046682114031745402655"),
        integral_type("26902562127956316343893262683171938435197568407043214449144600616790024786852"));
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(point == expected);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    blob = {0xfc, 0xc9, 0x8e, 0x93, 0xc,  0x7f, 0xc3, 0xfc, 0x89, 0xc4, 0x10, 0x66, 0x6,  0xd,  0x1,  0xeb,
            0xf8, 0xc7, 0x82, 0x19, 0x16, 0xfd, 0x12, 0x5b, 0x87, 0x55, 0x69, 0xc4, 0x81, 0xd2, 0xdf, 0x5c};
    expected = group_value_type(
        integral_type("40185837415754419626270588927415047095813982975230357263686068930519460729080"),
        integral_type("42008241830356574617713311689533669924455940847366394238316645523644983724540"));
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(point == expected);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    /// deserialization of incorrect blobs
    blob = {0x8f, 0xcb, 0xae, 0xbb, 0x2b, 0x32, 0xa6, 0x98, 0xcb, 0x6,  0xba, 0x7f, 0xa7, 0xb7, 0xd9, 0x4b,
            0x37, 0x60, 0x2a, 0x7e, 0xa6, 0x20, 0xdc, 0xe2, 0x92, 0xf8, 0x87, 0xca, 0x5,  0xf7, 0x73, 0x7a};
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(status != nil::marshalling::status_type::success);

    blob = {0x64, 0x43, 0x6c, 0xd4, 0x66, 0xa5, 0x8c, 0x71, 0x2f, 0x8c, 0x6b, 0xa7, 0x82, 0x5b, 0x55, 0xef,
            0xb,  0x9f, 0x4a, 0x1e, 0xdc, 0x26, 0xa5, 0x55, 0xf9, 0x35, 0x4e, 0x3e, 0x95, 0xd9, 0xe1, 0x8};
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(status != nil::marshalling::status_type::success);

    blob = {0x0,  0xde, 0xe0, 0x91, 0xab, 0x96, 0xb2, 0x2,  0x28, 0xc0, 0x11, 0x5c, 0x1d, 0x1d, 0x21, 0xef,
            0x9a, 0xfe, 0x63, 0x55, 0x3f, 0x2c, 0xad, 0xc3, 0xbd, 0x16, 0x4f, 0x8d, 0x92, 0x2f, 0x3,  0x20};
    point = nil::marshalling::pack<nil::marshalling::option::little_endian>(blob, status);
    BOOST_CHECK(status != nil::marshalling::status_type::success);

    /// serialization
    point = group_value_type(
        integral_type("3669431847238482802904025485408296241776002230868041345055738963615665974946"),
        integral_type("27924821127213629235056488929093463445821551452792195607066067950495472725010"));
    std::vector<bool> expected_bits = {
        0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1,
        0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
        1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0,
        1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    std::vector<std::uint8_t> cv =
        nil::marshalling::pack<nil::marshalling::option::little_endian>(point, status);
    for (auto i = 0; i < expected_bits.size(); ++i) {
        BOOST_CHECK(expected_bits[i] == ((cv[i / 8] >> (i % 8)) & 1));
    }

    /// serialization into bits
    std::vector<bool> cv_bits = nil::marshalling::pack<nil::marshalling::option::little_endian>(point, status);
    auto it1 = expected_bits.begin();
    auto it2 = cv_bits.begin();
    while (it1 != expected_bits.end() && it2 != cv_bits.end()) {
        BOOST_CHECK(*it1++ == *it2++);
    }
    BOOST_CHECK(cv_bits.size() == field_type::value_bits);
}

BOOST_AUTO_TEST_CASE(curve_element_ed25519_g1) {
    using curve_type = nil::crypto3::algebra::curves::ed25519;
    using group_type = typename curve_type::g1_type<>;
    using group_affine_type = typename curve_type::g1_type<nil::crypto3::algebra::curves::coordinates::affine>;
    using group_value_type = typename group_type::value_type;
    using group_affine_value_type = typename group_affine_type::value_type;
    using base_field_type = typename group_type::params_type::base_field_type;
    using base_field_value_type = typename base_field_type::value_type;
    using base_integral_type = typename base_field_type::integral_type;

    using curve_element_type = nil::crypto3::marshalling::types::
        curve_element<nil::marshalling::field_type<nil::marshalling::option::little_endian>, group_type>;

    curve_element_type test_val = curve_element_type(group_value_type::one());

    std::vector<std::uint8_t> encoded_point;
    encoded_point.resize(32);
    auto write_iter = encoded_point.begin();
    nil::marshalling::status_type status = test_val.write(write_iter, 32 * 8);

    for (auto c : encoded_point) {
        std::cout << c;
    }
    std::cout << std::endl;

    auto read_iter = encoded_point.begin();
    curve_element_type test_val_read;
    status = test_val_read.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(group_value_type::one() == test_val_read.value());

    auto etalon_p0 =
        group_affine_value_type(
            base_integral_type("34635077898116492310845069966122148616747722987106984453733372546503329107915"),
            base_integral_type("49338005294490284482104640895014307301516746361224773297235381488855003244760"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc0 = {
        216, 40,  169, 253, 155, 233, 200, 132, 232, 104, 10,  99, 28, 129, 26, 142,
        123, 141, 64,  187, 176, 139, 78,  47,  214, 245, 124, 2,  71, 82,  20, 237,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val0 = curve_element_type(etalon_p0);
    status = test_val0.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc0 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read0;
    status = test_val_read0.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p0 == test_val_read0.value());
    auto etalon_p1 =
        group_affine_value_type(
            base_integral_type("53750658631423664961088359631425146378091294078056269163982741665396402470352"),
            base_integral_type("18742885604507380591808793708388155177429163649743866867987384400688385953103"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc1 = {
        79,  13,  21,  67,  85, 9,   157, 85,  216, 73, 133, 67,  130, 167, 206, 25,
        107, 191, 177, 177, 72, 232, 167, 179, 255, 60, 160, 168, 233, 24,  112, 41,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val1 = curve_element_type(etalon_p1);
    status = test_val1.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc1 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read1;
    status = test_val_read1.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p1 == test_val_read1.value());
    auto etalon_p2 =
        group_affine_value_type(
            base_integral_type("56710780569822342653953753144839363683043653395627012162173362943076986182285"),
            base_integral_type("57147675224438120047033758766421383220066994289285694518281183388407044371371"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc2 = {
        171, 243, 81, 12,  195, 166, 252, 131, 187, 64,  172, 26,  188, 177, 20, 15,
        241, 210, 8,  206, 116, 178, 107, 188, 35,  187, 84,  102, 28,  112, 88, 254,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val2 = curve_element_type(etalon_p2);
    status = test_val2.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc2 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read2;
    status = test_val_read2.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p2 == test_val_read2.value());
    auto etalon_p3 =
        group_affine_value_type(
            base_integral_type("37822843536515135035073132411637802611245784869849549711381198770753002096282"),
            base_integral_type("8834718289175184141100104022374884107189934742756430468202895024557500972637"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc3 = {
        93,  190, 128, 238, 87,  232, 226, 77, 56,  201, 197, 127, 32,  183, 157, 4,
        112, 247, 10,  49,  157, 203, 168, 36, 231, 233, 144, 45,  250, 69,  136, 19,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val3 = curve_element_type(etalon_p3);
    status = test_val3.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc3 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read3;
    status = test_val_read3.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p3 == test_val_read3.value());
    auto etalon_p4 =
        group_affine_value_type(
            base_integral_type("40778999898687793233147246083845696915952873074268358930551643065536295678792"),
            base_integral_type("20399882465845624264449877379965476120335223996003137410054413413527327075232"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc4 = {
        160, 235, 3,   102, 30,  117, 254, 37,  112, 162, 243, 166, 21,  188, 181, 211,
        164, 107, 138, 156, 128, 1,   148, 106, 3,   126, 249, 39,  159, 236, 25,  45,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val4 = curve_element_type(etalon_p4);
    status = test_val4.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc4 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read4;
    status = test_val_read4.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p4 == test_val_read4.value());
    auto etalon_p5 =
        group_affine_value_type(
            base_integral_type("46919388651445060304380518997000698693889217136913068367844607267512215105100"),
            base_integral_type("7075951239608643707289219626610910672271731054172579880251468487752120068507"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc5 = {
        155, 233, 200, 198, 185, 214, 117, 123, 30,  191, 77,  68,  85,  156, 217, 48,
        35,  72,  115, 58,  221, 204, 161, 245, 102, 155, 101, 153, 178, 216, 164, 15,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val5 = curve_element_type(etalon_p5);
    status = test_val5.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc5 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read5;
    status = test_val_read5.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p5 == test_val_read5.value());
    auto etalon_p6 =
        group_affine_value_type(
            base_integral_type("4984976605133154297907307030204454486644075933092423511299806367163840832833"),
            base_integral_type("31959866948421171038040517810219071604753383592802145353380999082173967589418"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc6 = {
        42,  96,  211, 20,  151, 135, 76, 105, 116, 248, 245, 239, 95,  189, 15,  134,
        164, 234, 129, 134, 227, 220, 84, 69,  71,  229, 51,  154, 198, 164, 168, 198,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val6 = curve_element_type(etalon_p6);
    status = test_val6.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc6 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read6;
    status = test_val_read6.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p6 == test_val_read6.value());
    auto etalon_p7 =
        group_affine_value_type(
            base_integral_type("26341208934225446954563926149798813210990903063637730947388275266234278746803"),
            base_integral_type("22468880697766758387820844535988368041797978822288907466414910592017729173396"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc7 = {
        148, 183, 5,   118, 113, 55,  196, 158, 243, 179, 188, 107, 3,   127, 228, 141,
        56,  141, 131, 59,  61,  129, 199, 77,  192, 248, 9,   213, 144, 239, 172, 177,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val7 = curve_element_type(etalon_p7);
    status = test_val7.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc7 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read7;
    status = test_val_read7.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p7 == test_val_read7.value());
    auto etalon_p8 =
        group_affine_value_type(
            base_integral_type("3046485132837038317484485622601011458533082639722649652199202601075823193502"),
            base_integral_type("20211992840728070033727529918505858373606669024403965838145081698432228327258"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc8 = {
        90, 255, 16, 60, 220, 124, 25, 164, 94,  169, 164, 191, 115, 134, 201, 96,
        93, 176, 95, 17, 81,  129, 81, 164, 195, 7,   242, 159, 33,  149, 175, 44,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val8 = curve_element_type(etalon_p8);
    status = test_val8.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc8 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read8;
    status = test_val_read8.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p8 == test_val_read8.value());
    auto etalon_p9 =
        group_affine_value_type(
            base_integral_type("40142720555983903824642320528317807297855615234827027017412543553513985857533"),
            base_integral_type("48146496335445153382179277629167237269111151522137879733425061927553897320928"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc9 = {
        224, 209, 255, 7,  24, 74, 147, 64,  21, 246, 88, 191, 68,  55,  171, 31,
        129, 204, 124, 63, 65, 53, 38,  202, 54, 2,   50, 106, 131, 243, 113, 234,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val9 = curve_element_type(etalon_p9);
    status = test_val9.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc9 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read9;
    status = test_val_read9.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p9 == test_val_read9.value());
    auto etalon_p10 =
        group_affine_value_type(
            base_integral_type("3755756680767724892410768690708628968478974241109513325669341809745726968360"),
            base_integral_type("21208194046812906284356571278285053746775558087884910544957060133542932193865"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc10 = {
        73, 34, 99,  132, 16,  101, 173, 201, 186, 153, 159, 64, 79,  140, 16,  209,
        15, 34, 218, 59,  146, 47,  157, 132, 240, 74,  187, 8,  150, 105, 227, 46,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val10 = curve_element_type(etalon_p10);
    status = test_val10.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc10 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read10;
    status = test_val_read10.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p10 == test_val_read10.value());
    auto etalon_p11 =
        group_affine_value_type(
            base_integral_type("701725759041147694121363930579006846102497635008296645234331923948637571723"),
            base_integral_type("30925402949285708942516020116119233340186751799236526088353637166154300152878"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc11 = {
        46,  92,  218, 151, 118, 149, 216, 0,  32,  4,   49,  9,  164, 188, 186, 133,
        108, 136, 136, 236, 57,  165, 3,   74, 186, 193, 220, 81, 100, 40,  95,  196,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val11 = curve_element_type(etalon_p11);
    status = test_val11.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc11 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read11;
    status = test_val_read11.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p11 == test_val_read11.value());
    auto etalon_p12 =
        group_affine_value_type(
            base_integral_type("36930166537542724383546570407100156660862091647060961593670321691501168333783"),
            base_integral_type("14134729352235926155383985844248485089681789560677257220741332986493910654616"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc12 = {
        152, 30, 128, 179, 112, 55,  135, 37,  227, 110, 201, 214, 110, 197, 117, 125,
        49,  48, 255, 24,  140, 251, 109, 246, 192, 192, 34,  132, 42,  249, 63,  159,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val12 = curve_element_type(etalon_p12);
    status = test_val12.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc12 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read12;
    status = test_val_read12.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p12 == test_val_read12.value());
    auto etalon_p13 =
        group_affine_value_type(
            base_integral_type("40321115506036397748377945801887666512007847707106466566679799765585003716465"),
            base_integral_type("32389213242237665568623256986076219234715589223220807713616679358508945383085"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc13 = {
        173, 30,  20,  100, 136, 246, 71, 212, 241, 32, 83,  107, 193, 57,  239, 10,
        89,  187, 204, 32,  57,  190, 85, 51,  176, 51, 135, 189, 33,  165, 155, 199,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val13 = curve_element_type(etalon_p13);
    status = test_val13.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc13 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read13;
    status = test_val_read13.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p13 == test_val_read13.value());
    auto etalon_p14 =
        group_affine_value_type(
            base_integral_type("53589669757693029972514886289301043825137100747859541404843875054261473194092"),
            base_integral_type("37186534767929667942910563588949340590034677006038030393017125059722885572439"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc14 = {
        87, 167, 145, 117, 203, 0,  225, 155, 178, 227, 111, 90,  184, 186, 28, 214,
        92, 103, 58,  83,  22,  49, 198, 40,  238, 164, 237, 214, 50,  213, 54, 82,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val14 = curve_element_type(etalon_p14);
    status = test_val14.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc14 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read14;
    status = test_val_read14.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p14 == test_val_read14.value());
    auto etalon_p15 =
        group_affine_value_type(
            base_integral_type("52762257250561534521895834335884555498767056046423107778147867005714519818509"),
            base_integral_type("26428350299909892062388304159985932256381534147202890941552983936709504598498"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc15 = {
        226, 1,   61, 47, 77,  106, 180, 204, 151, 197, 24,  105, 114, 81,  204, 208,
        161, 146, 64, 91, 230, 154, 162, 225, 120, 54,  119, 217, 138, 234, 109, 186,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val15 = curve_element_type(etalon_p15);
    status = test_val15.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc15 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read15;
    status = test_val_read15.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p15 == test_val_read15.value());
    auto etalon_p16 =
        group_affine_value_type(
            base_integral_type("33433826792042461402669811565478833235433790387798956861712201322186578693852"),
            base_integral_type("13989314213684068045850252869040657904609124405906968286498621267686241551949"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc16 = {
        77, 70,  35, 180, 202, 239, 114, 216, 33,  101, 125, 249, 225, 189, 29,  129,
        71, 209, 65, 198, 77,  139, 94,  130, 251, 237, 193, 64,  215, 171, 237, 30,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val16 = curve_element_type(etalon_p16);
    status = test_val16.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc16 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read16;
    status = test_val_read16.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p16 == test_val_read16.value());
    auto etalon_p17 =
        group_affine_value_type(
            base_integral_type("44546179894019841983043628029151422281250862470895765838856095874104321246178"),
            base_integral_type("54837082691275039470860283812591711070732198611203491470121733278787125348776"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc17 = {
        168, 137, 243, 86,  255, 149, 237, 245, 201, 12,  111, 178, 234, 249, 86, 196,
        22,  204, 197, 230, 156, 90,  7,   136, 108, 142, 213, 10,  92,  176, 60, 121,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val17 = curve_element_type(etalon_p17);
    status = test_val17.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc17 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read17;
    status = test_val_read17.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p17 == test_val_read17.value());
    auto etalon_p18 =
        group_affine_value_type(
            base_integral_type("15541197961340072198001438440099828221069100334717389103948680218047715637421"),
            base_integral_type("19732430192077210568964078192613508926814571325362882307077831918132965124773"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc18 = {
        165, 170, 139, 178, 219, 155, 197, 45,  189, 174, 146, 149, 68,  176, 197, 94,
        66,  194, 191, 26,  253, 245, 237, 130, 111, 94,  88,  93,  226, 40,  160, 171,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val18 = curve_element_type(etalon_p18);
    status = test_val18.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc18 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read18;
    status = test_val_read18.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p18 == test_val_read18.value());
    auto etalon_p19 =
        group_affine_value_type(
            base_integral_type("6705097896766935885636219049288006924346728915909383897460578774731457700180"),
            base_integral_type("51306931639360615059093039057181446280434724113162460622882315485947960364733"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc19 = {
        189, 14,  22,  79,  220, 253, 199, 39,  48, 166, 255, 139, 220, 220, 255, 245,
        248, 131, 116, 118, 62,  153, 251, 143, 18, 150, 157, 24,  184, 177, 110, 113,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val19 = curve_element_type(etalon_p19);
    status = test_val19.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc19 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read19;
    status = test_val_read19.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p19 == test_val_read19.value());
    auto etalon_p20 =
        group_affine_value_type(
            base_integral_type("28404067076560618695197828757300857275841039942937616050466120050663332990803"),
            base_integral_type("9538990620601042965348064887310741423483138972181047145029966176838642957787"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc20 = {
        219, 253, 121, 223, 83,  28,  162, 59,  152, 61,  147, 217, 18,  208, 59, 62,
        167, 19,  114, 215, 205, 202, 150, 115, 101, 162, 21,  208, 154, 224, 22, 149,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val20 = curve_element_type(etalon_p20);
    status = test_val20.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc20 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read20;
    status = test_val_read20.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p20 == test_val_read20.value());
    auto etalon_p21 =
        group_affine_value_type(
            base_integral_type("52929442103130375153230932599927308127072638481510703835431522251142451046815"),
            base_integral_type("22023798333242434565580252032561305286905229330968571799719065878613018121007"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc21 = {
        47,  147, 121, 177, 48,  222, 94,  16,  248, 73, 218, 69,  74, 238, 80,  58,
        116, 1,   215, 91,  165, 210, 191, 164, 218, 89, 65,  100, 50, 7,   177, 176,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val21 = curve_element_type(etalon_p21);
    status = test_val21.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc21 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read21;
    status = test_val_read21.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p21 == test_val_read21.value());
    auto etalon_p22 =
        group_affine_value_type(
            base_integral_type("33684195358127916234818842072620197688804309982949402796551880547591763773748"),
            base_integral_type("20451562438351655637602030254985057471922551342607696062966132916738936576792"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc22 = {
        24,  155, 28,  191, 246, 31, 88, 30, 247, 129, 44, 173, 241, 7,  22, 211,
        160, 162, 167, 173, 227, 51, 18, 89, 182, 45,  1,  224, 147, 44, 55, 45,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val22 = curve_element_type(etalon_p22);
    status = test_val22.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc22 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read22;
    status = test_val_read22.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p22 == test_val_read22.value());
    auto etalon_p23 =
        group_affine_value_type(
            base_integral_type("8176901345190121968714986567342559640367520131816368123113171653974421675570"),
            base_integral_type("49910955165381205551314493723875354142463427641504609563775476080778667614075"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc23 = {
        123, 223, 123, 123, 87, 0,   166, 146, 209, 135, 186, 70,  231, 241, 137, 166,
        139, 208, 36,  113, 84, 211, 141, 142, 225, 10,  117, 220, 122, 153, 88,  110,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val23 = curve_element_type(etalon_p23);
    status = test_val23.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc23 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read23;
    status = test_val_read23.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p23 == test_val_read23.value());
    auto etalon_p24 =
        group_affine_value_type(
            base_integral_type("49379488174706634279731502079278985532761824213478004962320492137253340058621"),
            base_integral_type("19402079052793723162137335362896534736331571461956239305976394712346057803204"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc24 = {
        196, 133, 28,  240, 148, 135, 148, 124, 52,  226, 142, 204, 71, 162, 66,  205,
        64,  51,  241, 67,  48,  75,  196, 20,  211, 208, 99,  150, 5,  48,  229, 170,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val24 = curve_element_type(etalon_p24);
    status = test_val24.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc24 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read24;
    status = test_val_read24.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p24 == test_val_read24.value());
    auto etalon_p25 =
        group_affine_value_type(
            base_integral_type("24583367496645132924587932986510984756366319894708069402738881269037832385997"),
            base_integral_type("2798045839307977816117140716642603381249758683940861013576711340214695911720"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc25 = {
        40, 97, 134, 23, 236, 64,  173, 198, 236, 198, 139, 156, 252, 196, 0,  249,
        61, 49, 43,  82, 158, 169, 87,  237, 179, 230, 227, 94,  72,  163, 47, 134,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val25 = curve_element_type(etalon_p25);
    status = test_val25.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc25 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read25;
    status = test_val_read25.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p25 == test_val_read25.value());
    auto etalon_p26 =
        group_affine_value_type(
            base_integral_type("37394846850752284551524648151101217222122009316725355269710439983385868843793"),
            base_integral_type("23386562937134700711759439074546178608932510662537740376464089736143426502911"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc26 = {
        255, 64,  179, 244, 95,  117, 49,  67,  155, 40,  84, 247, 38, 204, 218, 173,
        197, 235, 210, 174, 210, 206, 215, 107, 201, 173, 9,  230, 86, 83,  180, 179,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val26 = curve_element_type(etalon_p26);
    status = test_val26.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc26 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read26;
    status = test_val_read26.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p26 == test_val_read26.value());
    auto etalon_p27 =
        group_affine_value_type(
            base_integral_type("39855076346417519948328036698272596102072930415806235084039790779604652008466"),
            base_integral_type("48980156117336911859106369871658982858806583273990724404394083793720680947970"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc27 = {
        2,  161, 0,   164, 61, 50,  22,  4,  26, 51, 235, 152, 242, 102, 157, 183,
        76, 149, 174, 216, 4,  144, 179, 36, 59, 90, 16,  82,  51,  201, 73,  108,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val27 = curve_element_type(etalon_p27);
    status = test_val27.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc27 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read27;
    status = test_val_read27.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p27 == test_val_read27.value());
    auto etalon_p28 =
        group_affine_value_type(
            base_integral_type("3464664173370347863993461823047441249905502318366699239969907589755003501749"),
            base_integral_type("13880998762542321476939096864120868069959477043384752930384197695737395386511"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc28 = {
        143, 152, 79,  80, 87, 220, 91, 41, 46,  129, 208, 75,  6,   39, 179, 34,
        149, 239, 136, 14, 96, 41,  87, 92, 227, 78,  135, 224, 235, 93, 176, 158,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val28 = curve_element_type(etalon_p28);
    status = test_val28.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc28 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read28;
    status = test_val_read28.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p28 == test_val_read28.value());
    auto etalon_p29 =
        group_affine_value_type(
            base_integral_type("8181613634230691139082629184124297473658911526451385011736447094316370901341"),
            base_integral_type("47639662560810372312194065113543849722266417311232133181991776312385592377402"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc29 = {
        58,  64, 52,  114, 128, 227, 48, 122, 61,  102, 49, 114, 197, 8,  144, 38,
        231, 42, 210, 156, 86,  244, 38, 218, 223, 198, 79, 223, 237, 23, 83,  233,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val29 = curve_element_type(etalon_p29);
    status = test_val29.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc29 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read29;
    status = test_val_read29.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p29 == test_val_read29.value());
    auto etalon_p30 =
        group_affine_value_type(
            base_integral_type("13133056913465472178189099625502632294202975539595956450981972191676111925291"),
            base_integral_type("27833212252556861740858484734361034731233347092810076852426670388686502618404"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc30 = {
        36, 229, 85, 181, 129, 59,  30,  134, 160, 231, 228, 28,  114, 137, 194, 64,
        60, 152, 78, 3,   113, 211, 186, 173, 72,  239, 67,  206, 52,  10,  137, 189,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val30 = curve_element_type(etalon_p30);
    status = test_val30.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc30 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read30;
    status = test_val_read30.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p30 == test_val_read30.value());
    auto etalon_p31 =
        group_affine_value_type(
            base_integral_type("13417403704396159162882969995063796307903332929662448692331475103217776678937"),
            base_integral_type("11088913466847596810338682007288595039486314950940229202921200153578453130447"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc31 = {
        207, 220, 60,  198, 183, 80, 188, 61,  204, 223, 56, 108, 187, 18, 16,  208,
        172, 71,  210, 97,  233, 94, 21,  174, 98,  203, 81, 91,  68,  26, 132, 152,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val31 = curve_element_type(etalon_p31);
    status = test_val31.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc31 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read31;
    status = test_val_read31.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p31 == test_val_read31.value());
    auto etalon_p32 =
        group_affine_value_type(
            base_integral_type("30109264399322067330494328065722840863160987802077534132926121057145408681546"),
            base_integral_type("29498990762097954592166536130625374850471965373617101906213273954218356523778"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc32 = {
        2,  67,  80,  19,  166, 156, 149, 107, 160, 109, 227, 135, 197, 186, 59, 209,
        93, 251, 135, 228, 101, 65,  36,  177, 134, 41,  11,  189, 75,  214, 55, 65,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val32 = curve_element_type(etalon_p32);
    status = test_val32.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc32 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read32;
    status = test_val_read32.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p32 == test_val_read32.value());
    auto etalon_p33 =
        group_affine_value_type(
            base_integral_type("15767600720791223007555659873258019325651633792945320685774484475705835780752"),
            base_integral_type("48548583986122007169734602901721528464949554371254727482023629193116939027198"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc33 = {
        254, 130, 129, 192, 48,  64, 113, 226, 206, 215, 223, 55, 159, 208, 178, 149,
        107, 127, 15,  129, 170, 70, 244, 170, 181, 73,  238, 72, 87,  134, 85,  107,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val33 = curve_element_type(etalon_p33);
    status = test_val33.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc33 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read33;
    status = test_val_read33.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p33 == test_val_read33.value());
    auto etalon_p34 =
        group_affine_value_type(
            base_integral_type("57682178935987503238937584780998972781064448204063349381104346615363519083432"),
            base_integral_type("55328689442420797086320996881975910813544969693441084289285487863714168206282"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc34 = {
        202, 115, 192, 254, 53,  41, 78,  163, 240, 189, 5,   42,  57,  181, 19, 123,
        98,  11,  48,  140, 239, 23, 104, 206, 107, 147, 156, 228, 175, 237, 82, 122,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val34 = curve_element_type(etalon_p34);
    status = test_val34.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc34 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read34;
    status = test_val_read34.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p34 == test_val_read34.value());
    auto etalon_p35 =
        group_affine_value_type(
            base_integral_type("24518132135807554327189806173906733186836978805987429698360080306426319999516"),
            base_integral_type("4196047293864987771783563841403666449392390772027054979278997736758269956078"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc35 = {
        238, 207, 127, 50,  71, 214, 83,  60,  251, 33,  221, 22, 40,  158, 22, 152,
        20,  194, 4,   140, 61, 87,  192, 100, 220, 155, 78,  79, 236, 224, 70, 9,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val35 = curve_element_type(etalon_p35);
    status = test_val35.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc35 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read35;
    status = test_val_read35.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p35 == test_val_read35.value());
    auto etalon_p36 =
        group_affine_value_type(
            base_integral_type("9751661049672021419636940398609123041710928551289992308758722633841344960155"),
            base_integral_type("46702980826019456810774446738915102906054056827796619035509770402440744593222"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc36 = {
        70,  231, 96,  211, 115, 46,  172, 5,   167, 79,  156, 170, 137, 217, 51, 66,
        188, 164, 215, 158, 95,  190, 129, 212, 88,  128, 99,  90,  77,  243, 64, 231,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val36 = curve_element_type(etalon_p36);
    status = test_val36.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc36 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read36;
    status = test_val_read36.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p36 == test_val_read36.value());
    auto etalon_p37 =
        group_affine_value_type(
            base_integral_type("34042660311469017860130713079882139986054882670660578499718854064649654334353"),
            base_integral_type("3321831045074939113150848531201510456151646995801644213433412365244827938543"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc37 = {
        239, 174, 243, 102, 255, 146, 208, 183, 44,  88, 186, 255, 117, 92, 232, 63,
        67,  9,   63,  231, 99,  6,   146, 148, 229, 38, 122, 112, 249, 22, 88,  135,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val37 = curve_element_type(etalon_p37);
    status = test_val37.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc37 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read37;
    status = test_val_read37.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p37 == test_val_read37.value());
    auto etalon_p38 =
        group_affine_value_type(
            base_integral_type("40068711478583254247147700647923298713402183273203099680030706013403019745988"),
            base_integral_type("44290418299406967674308798541234789246935602711927764628664879233079184114146"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc38 = {
        226, 193, 106, 95, 120, 168, 186, 243, 54,  224, 165, 121, 69, 135, 137, 99,
        65,  36,  215, 2,  26,  244, 108, 84,  161, 240, 14,  186, 7,  125, 235, 97,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val38 = curve_element_type(etalon_p38);
    status = test_val38.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc38 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read38;
    status = test_val_read38.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p38 == test_val_read38.value());
    auto etalon_p39 =
        group_affine_value_type(
            base_integral_type("26365190154379357256675253295150402501075718335456226898457521067406810996367"),
            base_integral_type("41952495364464663983439282314217290779952905620876132105733880863755750938064"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc39 = {
        208, 21, 1,   182, 23,  3,  254, 3,   43, 38,  92,  232, 170, 22, 11,  9,
        83,  58, 237, 241, 210, 50, 173, 138, 9,  185, 242, 108, 90,  69, 192, 220,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val39 = curve_element_type(etalon_p39);
    status = test_val39.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc39 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read39;
    status = test_val_read39.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p39 == test_val_read39.value());
    auto etalon_p40 =
        group_affine_value_type(
            base_integral_type("12373059242552348140720189663857611214394386212393997345342000223178913681406"),
            base_integral_type("17614838787854980500545136707578533245286805634955924900706487580577435470001"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc40 = {
        177, 200, 179, 13,  229, 252, 164, 1,  129, 176, 43,  76,  254, 149, 158, 92,
        242, 75,  203, 150, 63,  195, 201, 87, 206, 225, 182, 192, 59,  165, 241, 38,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val40 = curve_element_type(etalon_p40);
    status = test_val40.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc40 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read40;
    status = test_val_read40.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p40 == test_val_read40.value());
    auto etalon_p41 =
        group_affine_value_type(
            base_integral_type("6138165159294485469631375510281798805018844593882227197223666896717233346214"),
            base_integral_type("8473597335426995533298260762146887708492089479028055472362028582884922104382"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc41 = {
        62,  26,  216, 95,  23, 81,  37,  211, 195, 237, 66,  117, 165, 78,  226, 239,
        247, 133, 174, 247, 61, 169, 241, 174, 117, 53,  214, 140, 217, 226, 187, 18,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val41 = curve_element_type(etalon_p41);
    status = test_val41.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc41 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read41;
    status = test_val_read41.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p41 == test_val_read41.value());
    auto etalon_p42 =
        group_affine_value_type(
            base_integral_type("32659212585384848698176398910537753338099478183521954536003998306028725513051"),
            base_integral_type("33371834499308277657251564333186082182414927118449974290270067070181416183730"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc42 = {
        178, 39,  13,  53, 151, 196, 171, 108, 137, 154, 100, 145, 41,  100, 205, 77,
        17,  232, 122, 59, 173, 149, 217, 234, 161, 61,  119, 216, 249, 201, 199, 201,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val42 = curve_element_type(etalon_p42);
    status = test_val42.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc42 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read42;
    status = test_val_read42.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p42 == test_val_read42.value());
    auto etalon_p43 =
        group_affine_value_type(
            base_integral_type("46008027625793495333821084828092042947622044031598336204768770406807649952930"),
            base_integral_type("29693823722102950048503235751323232375001166754695004906783188865829355353514"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc43 = {
        170, 117, 11,  86,  72,  188, 6,  115, 147, 55,  120, 5,   132, 116, 213, 228,
        42,  60,  150, 150, 224, 115, 44, 184, 19,  193, 224, 223, 207, 27,  166, 65,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val43 = curve_element_type(etalon_p43);
    status = test_val43.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc43 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read43;
    status = test_val_read43.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p43 == test_val_read43.value());
    auto etalon_p44 =
        group_affine_value_type(
            base_integral_type("20080319709848455965477181653477690713897175829887498201318557912971958855778"),
            base_integral_type("872502764661068924666748865490310789092579731092410618868290778608497360611"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc44 = {
        227, 126, 20,  139, 163, 174, 202, 235, 86,  64,  189, 59, 235, 196, 106, 161,
        173, 56,  105, 7,   142, 26,  223, 214, 157, 175, 51,  54, 174, 209, 237, 1,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val44 = curve_element_type(etalon_p44);
    status = test_val44.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc44 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read44;
    status = test_val_read44.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p44 == test_val_read44.value());
    auto etalon_p45 =
        group_affine_value_type(
            base_integral_type("39305617783926685952195543686853901978226607315448305820813275869096027876197"),
            base_integral_type("2517322786731803005577790829817136976202339216882451017093445181414241201115"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc45 = {
        219, 235, 103, 195, 136, 178, 137, 12,  186, 32, 227, 206, 9,  43,  91,  214,
        122, 173, 95,  154, 242, 182, 158, 249, 118, 79, 91,  163, 19, 193, 144, 133,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val45 = curve_element_type(etalon_p45);
    status = test_val45.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc45 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read45;
    status = test_val_read45.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p45 == test_val_read45.value());
    auto etalon_p46 =
        group_affine_value_type(
            base_integral_type("35735531997372234472647286643350569183282530062193122486587151391162545736063"),
            base_integral_type("5182374213058556912931787268321191527785919121020270769697315785385484395678"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc46 = {
        158, 164, 242, 58,  55,  77,  78,  109, 90, 23,  85,  78, 19,  183, 124, 156,
        151, 72,  31,  116, 128, 235, 219, 57,  29, 229, 249, 15, 175, 30,  117, 139,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val46 = curve_element_type(etalon_p46);
    status = test_val46.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc46 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read46;
    status = test_val_read46.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p46 == test_val_read46.value());
    auto etalon_p47 =
        group_affine_value_type(
            base_integral_type("49005229472010168536018712073024690194907640941791437748117958804264127400996"),
            base_integral_type("31762368893876606573992651287272809802952164501924426410367966646519843124531"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc47 = {
        51,  245, 57,  117, 241, 67,  215, 70,  38,  0,   82,  56,  188, 6,   86, 175,
        122, 200, 104, 197, 117, 192, 242, 229, 128, 121, 158, 157, 28,  221, 56, 70,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val47 = curve_element_type(etalon_p47);
    status = test_val47.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc47 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read47;
    status = test_val_read47.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p47 == test_val_read47.value());
    auto etalon_p48 =
        group_affine_value_type(
            base_integral_type("47749586855701000474653037628609995108369338597158026693671491277664759774867"),
            base_integral_type("415060083034642852801851946203093351690737722008502905480016654677328589800"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc48 = {
        232, 243, 36,  147, 164, 5,   12,  71,  243, 217, 237, 75, 7,   47,  221, 131,
        99,  207, 230, 208, 30,  174, 169, 119, 167, 33,  4,   33, 106, 234, 234, 128,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val48 = curve_element_type(etalon_p48);
    status = test_val48.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc48 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read48;
    status = test_val_read48.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p48 == test_val_read48.value());
    auto etalon_p49 =
        group_affine_value_type(
            base_integral_type("12452153833909579280409871377251400681337611978044293957157835083139557189218"),
            base_integral_type("54828973230398160953637969267488889093444421337874571177191172595558595414782"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc49 = {
        254, 202, 31, 59, 158, 131, 84,  39,  74, 153, 252, 163, 216, 113, 207, 72,
        67,  93,  68, 27, 219, 165, 149, 154, 51, 59,  178, 107, 95,  25,  56,  121,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val49 = curve_element_type(etalon_p49);
    status = test_val49.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc49 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read49;
    status = test_val_read49.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p49 == test_val_read49.value());
    auto etalon_p50 =
        group_affine_value_type(
            base_integral_type("21923278323361101763983650895237578552290202251774059124265340228030397249571"),
            base_integral_type("6993332122239850039873491324294879256836179836294942644892316754339435808353"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc50 = {
        97,  134, 18,  228, 179, 147, 223, 79,  211, 61,  26, 215, 152, 148, 27,  210,
        113, 213, 237, 133, 155, 128, 6,   102, 210, 158, 83, 55,  241, 21,  118, 143,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val50 = curve_element_type(etalon_p50);
    status = test_val50.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc50 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read50;
    status = test_val_read50.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p50 == test_val_read50.value());
    auto etalon_p51 =
        group_affine_value_type(
            base_integral_type("41000817908171563192489557407967813217987068967579118639405168188006534778557"),
            base_integral_type("55234309684121645642184117604455804219089128858261957322736293205004841021502"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc51 = {
        62,  112, 170, 41,  95,  250, 62, 16, 16, 129, 48,  38, 154, 239, 151, 97,
        238, 16,  117, 179, 170, 250, 3,  9,  74, 133, 218, 23, 236, 130, 29,  250,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val51 = curve_element_type(etalon_p51);
    status = test_val51.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc51 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read51;
    status = test_val_read51.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p51 == test_val_read51.value());
    auto etalon_p52 =
        group_affine_value_type(
            base_integral_type("19236727376942611138250344890286957053614762190325404995312703606968629976259"),
            base_integral_type("38944018349114609818725094474598341792450888452444938622558310318398873958155"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc52 = {
        11, 119, 222, 154, 5,   186, 251, 55, 123, 44,  90, 178, 140, 144, 9,  212,
        0,  119, 113, 89,  112, 243, 216, 28, 122, 101, 33, 238, 131, 136, 25, 214,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val52 = curve_element_type(etalon_p52);
    status = test_val52.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc52 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read52;
    status = test_val_read52.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p52 == test_val_read52.value());
    auto etalon_p53 =
        group_affine_value_type(
            base_integral_type("15739539889353932766707591680601638119168294947706917470425986321675139391096"),
            base_integral_type("46582026851938992078042590913789808019950286332651374072805185056690076409752"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc53 = {
        152, 95,  196, 107, 138, 6,  124, 92, 135, 107, 99, 4,  116, 61,  206, 119,
        123, 227, 201, 200, 21,  10, 172, 4,  23,  133, 99, 27, 45,  126, 252, 102,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val53 = curve_element_type(etalon_p53);
    status = test_val53.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc53 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read53;
    status = test_val_read53.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p53 == test_val_read53.value());
    auto etalon_p54 =
        group_affine_value_type(
            base_integral_type("758552852132180889984636583587859673332031009946946789452791360652310183202"),
            base_integral_type("41564772641444352243214889657217986362269327378258006969271590605244285698317"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc54 = {
        13,  193, 157, 32,  233, 71, 96,  137, 230, 233, 251, 109, 51,  5,   188, 73,
        246, 44,  113, 101, 193, 68, 177, 149, 169, 52,  240, 85,  223, 211, 228, 91,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val54 = curve_element_type(etalon_p54);
    status = test_val54.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc54 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read54;
    status = test_val_read54.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p54 == test_val_read54.value());
    auto etalon_p55 =
        group_affine_value_type(
            base_integral_type("35043823827834297881382001012752604721556676988932887719792796515062079503180"),
            base_integral_type("11120193401552214865187672904821394563087777234421937653097569737416921804607"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc55 = {
        63,  111, 227, 26,  73, 170, 71, 124, 121, 25,  105, 152, 84,  247, 52,  33,
        147, 67,  142, 197, 54, 168, 71, 74,  24,  225, 99,  158, 113, 206, 149, 24,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val55 = curve_element_type(etalon_p55);
    status = test_val55.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc55 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read55;
    status = test_val_read55.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p55 == test_val_read55.value());
    auto etalon_p56 =
        group_affine_value_type(
            base_integral_type("40194320979996010278967611634303279245202268085515813855515207133198308795475"),
            base_integral_type("20404295955457622288468262268382530503006833268927735441981334383250085114539"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc56 = {
        171, 242, 253, 162, 138, 239, 160, 240, 10,  100, 93,  195, 252, 249, 66, 61,
        125, 88,  241, 12,  186, 73,  1,   39,  135, 156, 148, 149, 24,  108, 28, 173,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val56 = curve_element_type(etalon_p56);
    status = test_val56.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc56 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read56;
    status = test_val_read56.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p56 == test_val_read56.value());
    auto etalon_p57 =
        group_affine_value_type(
            base_integral_type("41829480725480694299243696415050808377660164020173916803914437204010076359885"),
            base_integral_type("14422253107679134622814477287960702267428901555018130140195449032778057970203"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc57 = {
        27, 242, 82,  207, 59,  36, 129, 95,  77,  140, 2,   221, 45,  175, 78,  45,
        77, 134, 208, 85,  166, 69, 43,  130, 113, 70,  118, 86,  187, 180, 226, 159,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val57 = curve_element_type(etalon_p57);
    status = test_val57.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc57 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read57;
    status = test_val_read57.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p57 == test_val_read57.value());
    auto etalon_p58 =
        group_affine_value_type(
            base_integral_type("22275014656550825845363171699183757656898925505737562960006032852731728142131"),
            base_integral_type("984142204116185825617407326154775873496663583354271607483443811186631026569"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc58 = {
        137, 167, 136, 236, 175, 249, 8,   115, 119, 47,  197, 198, 60, 134, 178, 12,
        157, 4,   60,  42,  190, 139, 198, 225, 65,  136, 165, 42,  55, 1,   45,  130,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val58 = curve_element_type(etalon_p58);
    status = test_val58.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc58 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read58;
    status = test_val_read58.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p58 == test_val_read58.value());
    auto etalon_p59 =
        group_affine_value_type(
            base_integral_type("5266322402942330320302942657188572430142082312964353882458322045929275872679"),
            base_integral_type("32732041461093218505644984463061809227040813251006395876240890479271964525531"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc59 = {
        219, 67, 139, 97,  52,  81, 159, 129, 219, 205, 66,  226, 222, 208, 218, 128,
        230, 2,  181, 151, 224, 96, 147, 41,  152, 70,  212, 30,  207, 173, 93,  200,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val59 = curve_element_type(etalon_p59);
    status = test_val59.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc59 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read59;
    status = test_val_read59.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p59 == test_val_read59.value());
    auto etalon_p60 =
        group_affine_value_type(
            base_integral_type("35078823285943228506486982440270286764197145269788521082002038490890292901195"),
            base_integral_type("12260276978698617078154504231722181165809368926556506684263336906267808469212"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc60 = {
        220, 144, 143, 148, 114, 209, 202, 223, 46, 67, 184, 3,   253, 98, 156, 233,
        252, 0,   132, 128, 23,  246, 89,  177, 89, 17, 3,   201, 35,  18, 27,  155,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val60 = curve_element_type(etalon_p60);
    status = test_val60.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc60 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read60;
    status = test_val_read60.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p60 == test_val_read60.value());
    auto etalon_p61 =
        group_affine_value_type(
            base_integral_type("47101704035249923113990997688597510948737550077670553452770059317688138253199"),
            base_integral_type("29606428629218916893999112184647032637682505967532289591632849952576666040668"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc61 = {
        92, 121, 91, 83,  54, 213, 86, 226, 114, 46, 168, 7,   66, 158, 225, 39,
        52, 175, 92, 176, 56, 89,  75, 221, 227, 41, 192, 182, 15, 165, 116, 193,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val61 = curve_element_type(etalon_p61);
    status = test_val61.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc61 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read61;
    status = test_val_read61.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p61 == test_val_read61.value());
    auto etalon_p62 =
        group_affine_value_type(
            base_integral_type("42073538532792005826758296273346446309275117267285660911154183742580774196482"),
            base_integral_type("19258483780127034987973214173983433694032971569334203718455526841726428808616"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc62 = {
        168, 133, 32,  199, 130, 35,  111, 1,  112, 175, 27,  231, 248, 123, 148, 152,
        102, 11,  106, 212, 126, 206, 57,  14, 34,  1,   208, 230, 96,  234, 147, 42,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val62 = curve_element_type(etalon_p62);
    status = test_val62.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc62 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read62;
    status = test_val_read62.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p62 == test_val_read62.value());
    auto etalon_p63 =
        group_affine_value_type(
            base_integral_type("55361909605270568267732955930119441653420302071698323612601356018130269080542"),
            base_integral_type("17252539940112288023644231714345136600347182562461375842359430899704746120707"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc63 = {
        3,   150, 178, 177, 142, 217, 14, 219, 132, 185, 214, 60,  226, 98,  20, 39,
        224, 62,  150, 50,  215, 204, 75, 45,  132, 79,  195, 155, 112, 151, 36, 38,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val63 = curve_element_type(etalon_p63);
    status = test_val63.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc63 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read63;
    status = test_val_read63.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p63 == test_val_read63.value());
    auto etalon_p64 =
        group_affine_value_type(
            base_integral_type("28642119958029088255841595984318309775612988389985856165637402310509633559957"),
            base_integral_type("24503278112362804675033532420085512949741099176445157150913197941790650503185"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc64 = {
        17, 144, 81, 248, 255, 50, 155, 203, 243, 52, 121, 107, 32, 157, 96, 95,
        38, 92,  17, 160, 5,   29, 132, 146, 20,  97, 34,  221, 42, 93,  44, 182,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val64 = curve_element_type(etalon_p64);
    status = test_val64.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc64 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read64;
    status = test_val_read64.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p64 == test_val_read64.value());
    auto etalon_p65 =
        group_affine_value_type(
            base_integral_type("19766272497126793314784431751334831980898599401202921869917486684140280605260"),
            base_integral_type("34515302279507403865245360058488273764994355305294758362557788745562129087876"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc65 = {
        132, 189, 178, 81,  58, 21, 235, 248, 49,  200, 56,  28, 142, 209, 81, 204,
        207, 111, 163, 103, 41, 94, 202, 40,  118, 174, 112, 20, 3,   248, 78, 76,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val65 = curve_element_type(etalon_p65);
    status = test_val65.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc65 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read65;
    status = test_val_read65.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p65 == test_val_read65.value());
    auto etalon_p66 =
        group_affine_value_type(
            base_integral_type("35318709825627451705272978068996020250680075597954108835140261877526163495315"),
            base_integral_type("44223633300892241046341468684374828551151746983392750129657147378796076799645"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc66 = {
        157, 22, 217, 103, 2,   211, 9,  95, 62,  71,  76, 29,  138, 186, 95,  34,
        34,  81, 133, 104, 214, 57,  57, 71, 226, 228, 66, 116, 126, 176, 197, 225,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val66 = curve_element_type(etalon_p66);
    status = test_val66.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc66 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read66;
    status = test_val_read66.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p66 == test_val_read66.value());
    auto etalon_p67 =
        group_affine_value_type(
            base_integral_type("9019651656406529649075165023927329556028399778613681785858720899668853500083"),
            base_integral_type("6974950575303655615301195579196338665294069270073995499748086532839003660231"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc67 = {
        199, 31,  72,  15, 95,  105, 213, 230, 61,  164, 23, 166, 82,  158, 46,  28,
        84,  115, 243, 36, 167, 174, 107, 136, 221, 68,  31, 191, 159, 174, 107, 143,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val67 = curve_element_type(etalon_p67);
    status = test_val67.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc67 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read67;
    status = test_val_read67.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p67 == test_val_read67.value());
    auto etalon_p68 =
        group_affine_value_type(
            base_integral_type("21259303519217719382803270113091255588750394976678359970182243976381685517981"),
            base_integral_type("56271359022443059191890329576555277246063652986242994464557567372325060017573"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc68 = {
        165, 253, 42, 75,  135, 43,  243, 57, 167, 98,  18,  127, 80,  56,  75,  66,
        62,  241, 52, 246, 107, 203, 155, 18, 189, 119, 148, 239, 229, 117, 104, 252,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val68 = curve_element_type(etalon_p68);
    status = test_val68.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc68 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read68;
    status = test_val_read68.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p68 == test_val_read68.value());
    auto etalon_p69 =
        group_affine_value_type(
            base_integral_type("44672172038330640390784902265213369351783379693446283677384874757353552208319"),
            base_integral_type("9343422933454564159981895261456564388138119637726177818298758809438156074493"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc69 = {
        253, 173, 41, 156, 185, 155, 85, 61, 36,  84, 65,  215, 244, 24, 192, 78,
        218, 33,  55, 41,  25,  170, 47, 53, 213, 79, 231, 33,  162, 48, 168, 148,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val69 = curve_element_type(etalon_p69);
    status = test_val69.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc69 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read69;
    status = test_val_read69.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p69 == test_val_read69.value());
    auto etalon_p70 =
        group_affine_value_type(
            base_integral_type("46358518378956506158274311015082398310778822406551125177504536843664861695863"),
            base_integral_type("17617257383585114369839207544699585262978940048588056667026325884057568270903"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc70 = {
        55, 218, 89, 4,  65,  113, 99, 125, 238, 179, 93, 166, 132, 100, 99,  172,
        88, 174, 34, 40, 212, 176, 88, 206, 21,  201, 81, 116, 170, 3,   243, 166,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val70 = curve_element_type(etalon_p70);
    status = test_val70.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc70 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read70;
    status = test_val_read70.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p70 == test_val_read70.value());
    auto etalon_p71 =
        group_affine_value_type(
            base_integral_type("7360682380550972953350693297711937905416940921534320048097307910226320528428"),
            base_integral_type("32404041678758531848807649521784138183888199873266999338498934593099527098384"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc71 = {
        16, 16,  160, 17,  103, 184, 135, 111, 31, 73, 164, 85, 42,  167, 144, 227,
        49, 197, 80,  165, 20,  238, 14,  150, 47, 98, 19,  5,  163, 9,   164, 71,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val71 = curve_element_type(etalon_p71);
    status = test_val71.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc71 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read71;
    status = test_val_read71.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p71 == test_val_read71.value());
    auto etalon_p72 =
        group_affine_value_type(
            base_integral_type("18176037342034827065102325122630731321618410690361195561029964842274578044245"),
            base_integral_type("16345634663196260408636225279046091539357836437284497309413378269801964942780"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc72 = {
        188, 181, 212, 107, 74,  169, 68,  211, 95,  143, 88,  165, 100, 199, 201, 131,
        42,  19,  95,  54,  142, 155, 154, 78,  151, 218, 209, 75,  38,  77,  35,  164,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val72 = curve_element_type(etalon_p72);
    status = test_val72.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc72 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read72;
    status = test_val_read72.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p72 == test_val_read72.value());
    auto etalon_p73 =
        group_affine_value_type(
            base_integral_type("40022727838880478684588535732952328960577183704865481782141600366499993957517"),
            base_integral_type("57767567311029536215386138391362702249988306395664290298682870050952950902563"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc73 = {
        35,  239, 200, 91,  123, 55, 208, 217, 130, 160, 173, 50,  220, 80, 226, 235,
        208, 4,   67,  210, 142, 58, 205, 142, 153, 195, 158, 205, 207, 72, 183, 255,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val73 = curve_element_type(etalon_p73);
    status = test_val73.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc73 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read73;
    status = test_val_read73.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p73 == test_val_read73.value());
    auto etalon_p74 =
        group_affine_value_type(
            base_integral_type("17931630300726692415491389605635632829551415883355519123494674322781932034204"),
            base_integral_type("2264975746940208877639346762200881908235830007852631382856284892283843762083"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc74 = {
        163, 215, 225, 113, 239, 99,  144, 131, 3,  153, 143, 209, 186, 66,  204, 159,
        90,  181, 163, 106, 231, 246, 26,  223, 23, 219, 146, 183, 75,  238, 1,   5,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val74 = curve_element_type(etalon_p74);
    status = test_val74.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc74 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read74;
    status = test_val_read74.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p74 == test_val_read74.value());
    auto etalon_p75 =
        group_affine_value_type(
            base_integral_type("57334844718720215580598911584589276265750027562263362055877751591695493798438"),
            base_integral_type("10485244075616787088894794981816685372407244118275141056351839486652740188722"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc75 = {
        50,  186, 94, 76,  133, 176, 245, 240, 129, 175, 188, 152, 34, 44,  91, 69,
        167, 82,  58, 177, 159, 122, 192, 3,   6,   133, 216, 42,  22, 112, 46, 23,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val75 = curve_element_type(etalon_p75);
    status = test_val75.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc75 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read75;
    status = test_val_read75.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p75 == test_val_read75.value());
    auto etalon_p76 =
        group_affine_value_type(
            base_integral_type("21146201061051110999767636941413714314564804156783070984379802585417850752439"),
            base_integral_type("13837145730855824094065740389748432871460316469836990613419210192036178405268"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc76 = {
        148, 167, 211, 158, 253, 197, 82,  220, 161, 140, 179, 92,  79, 150, 92,  94,
        88,  222, 139, 212, 190, 33,  220, 28,  177, 222, 74,  135, 4,  140, 151, 158,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val76 = curve_element_type(etalon_p76);
    status = test_val76.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc76 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read76;
    status = test_val_read76.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p76 == test_val_read76.value());
    auto etalon_p77 =
        group_affine_value_type(
            base_integral_type("51680177468659015617957166051576913592293043816267704449727388115344853385879"),
            base_integral_type("34113883779895369577769614576090888220767198932259527559473318063495817561270"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc77 = {
        182, 132, 93, 2,   92,  54,  121, 107, 19,  2,  165, 122, 6,  243, 132, 71,
        89,  19,  58, 151, 119, 142, 137, 144, 216, 11, 249, 102, 35, 198, 107, 203,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val77 = curve_element_type(etalon_p77);
    status = test_val77.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc77 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read77;
    status = test_val_read77.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p77 == test_val_read77.value());
    auto etalon_p78 =
        group_affine_value_type(
            base_integral_type("12859871507300075541318138213322340553594501912669912048137308448964953061947"),
            base_integral_type("20686298956458659742897712181765167483273607945784264824845592647081424627"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc78 = {
        243, 118, 216, 224, 177, 149, 4,   149, 236, 120, 163, 218, 121, 16,  231, 41,
        233, 24,  67,  140, 176, 173, 185, 241, 133, 108, 38,  121, 65,  181, 11,  128,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val78 = curve_element_type(etalon_p78);
    status = test_val78.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc78 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read78;
    status = test_val_read78.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p78 == test_val_read78.value());
    auto etalon_p79 =
        group_affine_value_type(
            base_integral_type("32505242079253046234868138481761769632196626604076097547498753311922074658431"),
            base_integral_type("10848927771305436383855431564092973481022336437928093474206316165855373876201"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc79 = {
        233, 219, 98, 63,  22, 55,  1,   136, 41,  39, 44, 58, 91,  38, 208, 254,
        107, 48,  73, 172, 45, 246, 244, 1,   180, 31, 73, 45, 136, 70, 252, 151,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val79 = curve_element_type(etalon_p79);
    status = test_val79.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc79 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read79;
    status = test_val_read79.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p79 == test_val_read79.value());
    auto etalon_p80 =
        group_affine_value_type(
            base_integral_type("8592482722822658780860075470098626027356524999533342443545294060012953692967"),
            base_integral_type("38267934627324372693362938728750808426333092157123069796513039556910519585090"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc80 = {
        66, 137, 210, 181, 112, 172, 160, 54,  77,  133, 103, 26,  35, 80,  224, 243,
        64, 243, 91,  94,  252, 173, 229, 243, 190, 218, 16,  240, 40, 226, 154, 212,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val80 = curve_element_type(etalon_p80);
    status = test_val80.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc80 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read80;
    status = test_val_read80.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p80 == test_val_read80.value());
    auto etalon_p81 =
        group_affine_value_type(
            base_integral_type("24636937454268087988693219497185818908641540415032839991941697209296458518485"),
            base_integral_type("21544418913762634656419840113740553315531078452144681435327004077164988592031"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc81 = {
        159, 239, 113, 214, 149, 153, 144, 196, 156, 42,  49,  234, 158, 68,  16,  65,
        244, 43,  74,  125, 131, 168, 29,  194, 222, 109, 169, 122, 127, 181, 161, 175,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val81 = curve_element_type(etalon_p81);
    status = test_val81.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc81 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read81;
    status = test_val_read81.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p81 == test_val_read81.value());
    auto etalon_p82 =
        group_affine_value_type(
            base_integral_type("54604878696273841133837915669446636832743989487036105834861359722834708337810"),
            base_integral_type("52387548451173022164303887988660689707914336949223742530436086837274655585836"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc82 = {
        44,  246, 171, 136, 152, 126, 187, 47, 83,  162, 191, 163, 254, 135, 50,  141,
        217, 201, 219, 9,   192, 178, 99,  43, 215, 34,  99,  88,  57,  77,  210, 115,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val82 = curve_element_type(etalon_p82);
    status = test_val82.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc82 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read82;
    status = test_val_read82.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p82 == test_val_read82.value());
    auto etalon_p83 =
        group_affine_value_type(
            base_integral_type("7707444747668165579846112990945714037374755965066379428710089818697688192182"),
            base_integral_type("46482582458182036176087959428883532655581945864470979908078732455642791908363"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc83 = {
        11, 148, 79,  5,  248, 96, 167, 165, 196, 200, 177, 104, 157, 237, 146, 117,
        51, 168, 107, 16, 141, 70, 241, 163, 132, 151, 136, 137, 151, 53,  196, 102,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val83 = curve_element_type(etalon_p83);
    status = test_val83.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc83 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read83;
    status = test_val_read83.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p83 == test_val_read83.value());
    auto etalon_p84 =
        group_affine_value_type(
            base_integral_type("11395993478643994644288001523983368860122729001557445062243460768566278614064"),
            base_integral_type("52863667619816314953500476046929048403693005306532202207790448279013978156630"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc84 = {
        86,  46,  102, 152, 222, 105, 143, 187, 89,  185, 184, 138, 128, 178, 212, 39,
        245, 136, 167, 44,  254, 179, 196, 168, 124, 98,  75,  213, 138, 198, 223, 116,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val84 = curve_element_type(etalon_p84);
    status = test_val84.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc84 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read84;
    status = test_val_read84.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p84 == test_val_read84.value());
    auto etalon_p85 =
        group_affine_value_type(
            base_integral_type("35526011595807541166245597509439112742780389911580328684476318322025522481879"),
            base_integral_type("8363582512716673581173084381687661836631967416965182475013923919971478465221"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc85 = {
        197, 234, 208, 53,  250, 85, 193, 117, 83,  245, 55,  51,  94,  76,  238, 195,
        166, 194, 94,  177, 156, 9,  4,   126, 158, 205, 192, 250, 180, 158, 125, 146,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val85 = curve_element_type(etalon_p85);
    status = test_val85.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc85 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read85;
    status = test_val_read85.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p85 == test_val_read85.value());
    auto etalon_p86 =
        group_affine_value_type(
            base_integral_type("6844407550458082222591701215080587079768193049554371979782649620855689513825"),
            base_integral_type("54219338937500167790440739181328676609318446615173427478684381323112815545680"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc86 = {
        80, 77,  244, 204, 226, 105, 74,  5,   63,  116, 227, 215, 108, 148, 57,  229,
        61, 151, 114, 100, 248, 194, 199, 239, 164, 78,  88,  187, 238, 14,  223, 247,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val86 = curve_element_type(etalon_p86);
    status = test_val86.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc86 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read86;
    status = test_val_read86.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p86 == test_val_read86.value());
    auto etalon_p87 =
        group_affine_value_type(
            base_integral_type("26765216885501846650935259651486928050022340032310350639874881311598698465045"),
            base_integral_type("14399030940482762085087603525124570069945221102225237207718584933448832651705"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc87 = {
        185, 17, 194, 85,  203, 123, 143, 248, 20, 186, 128, 94, 141, 11,  215, 51,
        45,  92, 193, 149, 179, 124, 212, 198, 58, 63,  165, 72, 13,  144, 213, 159,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val87 = curve_element_type(etalon_p87);
    status = test_val87.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc87 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read87;
    status = test_val_read87.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p87 == test_val_read87.value());
    auto etalon_p88 =
        group_affine_value_type(
            base_integral_type("7846565875908542570751458689856917075247577078148740461094838373369600692735"),
            base_integral_type("45397708517473612513807508065050110489751774364126242423900259892515076523859"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc88 = {
        83, 71, 219, 72,  196, 54,  66, 8,   1,  21,  174, 82,  93, 137, 167, 164,
        31, 31, 115, 211, 218, 238, 59, 172, 59, 101, 237, 153, 68, 49,  94,  228,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val88 = curve_element_type(etalon_p88);
    status = test_val88.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc88 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read88;
    status = test_val_read88.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p88 == test_val_read88.value());
    auto etalon_p89 =
        group_affine_value_type(
            base_integral_type("54238078543565260702083171565378784784318310321117225335278303973895001199634"),
            base_integral_type("45035882435525616641171446517680556717143711942718269990641708774732159026837"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc89 = {
        149, 134, 64, 133, 152, 41,  68,  12, 212, 137, 67,  225, 233, 61,  48,  171,
        138, 58,  70, 79,  179, 200, 190, 23, 168, 119, 155, 80,  249, 103, 145, 99,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val89 = curve_element_type(etalon_p89);
    status = test_val89.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc89 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read89;
    status = test_val_read89.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p89 == test_val_read89.value());
    auto etalon_p90 =
        group_affine_value_type(
            base_integral_type("18078871356236373095956817764680594686073103078253583421325636606252013211033"),
            base_integral_type("50522330377538406428955817763423929264960004241279897151102807628577585683796"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc90 = {
        84,  221, 170, 200, 228, 57, 136, 184, 111, 97,  40,  87,  21, 57,  189, 135,
        219, 113, 239, 24,  246, 78, 159, 79,  171, 252, 146, 213, 41, 160, 178, 239,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val90 = curve_element_type(etalon_p90);
    status = test_val90.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc90 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read90;
    status = test_val_read90.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p90 == test_val_read90.value());
    auto etalon_p91 =
        group_affine_value_type(
            base_integral_type("50670671174406071799425635757380407970869378609781286891861118816286389767451"),
            base_integral_type("36139062449272573707109838828498503316120491906578132559120334998073121326193"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc91 = {
        113, 68,  22,  231, 255, 158, 92,  127, 232, 156, 42, 18, 221, 207, 49,  55,
        72,  233, 248, 240, 163, 200, 230, 205, 195, 207, 79, 43, 7,   252, 229, 207,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val91 = curve_element_type(etalon_p91);
    status = test_val91.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc91 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read91;
    status = test_val_read91.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p91 == test_val_read91.value());
    auto etalon_p92 =
        group_affine_value_type(
            base_integral_type("19412935524867995708425470421600223308299651696112265537573557860327094577734"),
            base_integral_type("43596306911203624246997810936723550288021603601642145021597254089463250726351"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc92 = {
        207, 173, 142, 38,  90, 194, 42,  176, 10,  12, 177, 58,  233, 146, 18, 181,
        121, 251, 169, 129, 63, 10,  177, 56,  110, 39, 69,  108, 161, 162, 98, 96,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val92 = curve_element_type(etalon_p92);
    status = test_val92.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc92 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read92;
    status = test_val_read92.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p92 == test_val_read92.value());
    auto etalon_p93 =
        group_affine_value_type(
            base_integral_type("47459566212496329975026195840917491714931282081921965586191473772221531060441"),
            base_integral_type("740412998971425371786327608688183724578432785967190450703869484455855352864"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc93 = {
        32, 108, 215, 151, 103, 159, 239, 12,  168, 152, 136, 179, 100, 129, 196, 177,
        50, 224, 164, 142, 4,   21,  68,  194, 150, 8,   147, 127, 20,  15,  163, 129,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val93 = curve_element_type(etalon_p93);
    status = test_val93.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc93 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read93;
    status = test_val_read93.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p93 == test_val_read93.value());
    auto etalon_p94 =
        group_affine_value_type(
            base_integral_type("21073454116085703348189460463504950567752741107052261290962195370394077019118"),
            base_integral_type("19213905196973665487094298447634051066816153566001194083129649249622418879186"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc94 = {
        210, 114, 25,  108, 250, 53,  162, 105, 240, 5,  174, 164, 152, 20,  119, 52,
        75,  192, 182, 48,  6,   152, 135, 37,  246, 62, 120, 90,  89,  175, 122, 42,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val94 = curve_element_type(etalon_p94);
    status = test_val94.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc94 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read94;
    status = test_val_read94.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p94 == test_val_read94.value());
    auto etalon_p95 =
        group_affine_value_type(
            base_integral_type("27139590345168339343199097316462406991347904742038163762162564027651366746311"),
            base_integral_type("23949856279751982845076756323940890722823908929458648188706078914419166999373"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc95 = {
        77, 243, 98, 249, 114, 187, 61, 217, 107, 69,  125, 194, 212, 240, 18,  181,
        58, 216, 45, 46,  131, 6,   9,  140, 131, 127, 152, 53,  102, 35,  243, 180,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val95 = curve_element_type(etalon_p95);
    status = test_val95.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc95 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read95;
    status = test_val_read95.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p95 == test_val_read95.value());
    auto etalon_p96 =
        group_affine_value_type(
            base_integral_type("41113773222150103100728893645699941169501744678598800955223487853451405755479"),
            base_integral_type("28347842902547741784693640594533937714268363629616216641080602020226580332487"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc96 = {
        199, 191, 203, 238, 86,  143, 180, 179, 30,  220, 188, 177, 56,  208, 177, 163,
        217, 163, 244, 249, 136, 38,  45,  251, 234, 84,  76,  135, 124, 79,  172, 190,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val96 = curve_element_type(etalon_p96);
    status = test_val96.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc96 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read96;
    status = test_val_read96.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p96 == test_val_read96.value());
    auto etalon_p97 =
        group_affine_value_type(
            base_integral_type("41672458263152987112873941248563585221814622461127543020473221788680629218370"),
            base_integral_type("50686581227500512698528614498540675245867641388076261062891160621034013187865"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc97 = {
        25, 223, 155, 68, 75,  80,  208, 143, 175, 109, 254, 129, 34,  60,  131, 118,
        92, 66,  146, 84, 140, 233, 82,  173, 54,  31,  176, 118, 156, 150, 15,  112,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val97 = curve_element_type(etalon_p97);
    status = test_val97.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc97 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read97;
    status = test_val_read97.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p97 == test_val_read97.value());
    auto etalon_p98 =
        group_affine_value_type(
            base_integral_type("38470632132325133341113461424443203144954915785198762852503483917514928674786"),
            base_integral_type("2069700745715607826430212282468743206927122797587302631148600572746651231422"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc98 = {
        190, 100, 29, 210, 72, 79,  224, 97, 192, 75, 176, 189, 248, 27,  183, 201,
        240, 19,  71, 8,   75, 141, 148, 32, 139, 98, 100, 92,  187, 104, 147, 4,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val98 = curve_element_type(etalon_p98);
    status = test_val98.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc98 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read98;
    status = test_val_read98.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p98 == test_val_read98.value());
    auto etalon_p99 =
        group_affine_value_type(
            base_integral_type("25257171893629220161989580451943786770345773083656861546743129125824799064154"),
            base_integral_type("37547953173892429602407538473813142848386566240916344872669499962810972065363"))
            .to_extended_with_a_minus_1();
    std::vector<std::uint8_t> etalon_p_enc99 = {
        83,  78, 57,  78,  24,  26,  34, 87,  232, 150, 24, 210, 160, 121, 104, 158,
        217, 97, 239, 183, 112, 171, 86, 240, 139, 237, 79, 149, 108, 99,  3,   83,
    };
    write_iter = encoded_point.begin();
    curve_element_type test_val99 = curve_element_type(etalon_p99);
    status = test_val99.write(write_iter, 32 * 8);
    BOOST_CHECK(etalon_p_enc99 == encoded_point);
    read_iter = encoded_point.begin();
    curve_element_type test_val_read99;
    status = test_val_read99.read(read_iter, curve_element_type::bit_length());
    BOOST_CHECK(etalon_p99 == test_val_read99.value());
}

BOOST_AUTO_TEST_SUITE_END()
