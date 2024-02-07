//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_r1cs_gg_ppzksnark_primary_input_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(FpCurveGroupElement e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(Fp2CurveGroupElement e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << ") (" << e.Y.data[0].data << " "
              << e.Y.data[1].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data << ")" << std::endl;
}

template<typename SchemeType, typename Endianness>
void test_primary_input(typename SchemeType::primary_input_type val) {

    using namespace nil::crypto3::marshalling;

    using unit_type = unsigned char;
    using primary_input_type = types::r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<Endianness>,
            typename SchemeType::primary_input_type>;

    primary_input_type filled_val =
            types::fill_r1cs_gg_ppzksnark_primary_input<typename SchemeType::primary_input_type, Endianness>(val);

    typename SchemeType::primary_input_type constructed_val =
            types::make_r1cs_gg_ppzksnark_primary_input<typename SchemeType::primary_input_type, Endianness>(
                    filled_val);
    BOOST_CHECK(val == constructed_val);

    std::size_t unitblob_size = filled_val.length();

    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);

    auto write_iter = cv.begin();

    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    primary_input_type test_val_read;

    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    typename SchemeType::primary_input_type constructed_val_read =
            types::make_r1cs_gg_ppzksnark_primary_input<typename SchemeType::primary_input_type, Endianness>(
                    test_val_read);

    BOOST_CHECK(val == constructed_val_read);
}

template<typename SchemeType, typename Endianness, std::size_t TSize>
void test_primary_input() {
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128 * 16; ++i) {
        std::vector<typename SchemeType::primary_input_type::value_type> val_container;
        if (!(i % (16 * 16)) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        for (std::size_t i = 0; i < TSize; i++) {
            val_container.push_back(nil::crypto3::algebra::random_element<
                    typename SchemeType::primary_input_type::value_type::field_type>());
        }
        test_primary_input<SchemeType, Endianness>(val_container);
    }
}

BOOST_AUTO_TEST_SUITE(r1cs_gg_ppzksnark_primary_input_test_suite)

    BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_primary_input_bls12_381_be) {
        std::cout << "BLS12-381 r1cs_gg_ppzksnark primary input big-endian test started" << std::endl;
        test_primary_input<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<nil::crypto3::algebra::curves::bls12<381>>,
                nil::marshalling::option::big_endian,
                100>();
        std::cout << "BLS12-381 r1cs_gg_ppzksnark primary input big-endian test finished" << std::endl;
    }

    BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_primary_input_bls12_381_le) {
        std::cout << "BLS12-381 r1cs_gg_ppzksnark primary input little-endian test started" << std::endl;
        test_primary_input<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<nil::crypto3::algebra::curves::bls12<381>>,
                nil::marshalling::option::little_endian,
                100>();
        std::cout << "BLS12-381 r1cs_gg_ppzksnark primary input little-endian test finished" << std::endl;
    }

BOOST_AUTO_TEST_SUITE_END()
