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

#define BOOST_TEST_MODULE crypto3_marshalling_r1cs_gg_ppzksnark_verification_key_test

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

#include <nil/crypto3/container/sparse_vector.hpp>
#include <nil/crypto3/container/accumulation_vector.hpp>

#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/marshalling/pubkey/types/elgamal_verifiable.hpp>

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

template<typename Endianness, typename VerificationKeyMarshalling, typename VerificationKey,
        typename CurveType = typename VerificationKey::curve_type>
void test_verification_key(const VerificationKey &val) {

    using namespace nil::crypto3::marshalling;

    using unit_type = unsigned char;
    using verification_key_marshalling_type = VerificationKeyMarshalling;

    verification_key_marshalling_type filled_val =
            types::fill_r1cs_gg_ppzksnark_verification_key<VerificationKey, Endianness>(val);

    VerificationKey constructed_val =
            types::make_r1cs_gg_ppzksnark_verification_key<VerificationKey, Endianness>(filled_val);
    BOOST_CHECK(val == constructed_val);

    std::size_t unitblob_size = filled_val.length();

    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);

    auto write_iter = cv.begin();

    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    verification_key_marshalling_type test_val_read;

    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    VerificationKey constructed_val_read =
            types::make_r1cs_gg_ppzksnark_verification_key<VerificationKey, Endianness>(test_val_read);

    BOOST_CHECK(val == constructed_val_read);
}

// TODO: move to pubkey marshling
template<typename Endianness, typename KeyMarshalling, typename Key,
        typename CurveType = typename Key::scheme_type::curve_type>
void test_pubkey(const Key &val) {

    using namespace nil::crypto3::marshalling;

    using unit_type = unsigned char;
    using key_marshalling_type = KeyMarshalling;

    key_marshalling_type filled_val = types::fill_public_key<Key, Endianness>(val);

    Key constructed_val = types::make_public_key<Key, Endianness>(filled_val);
    BOOST_CHECK(val == constructed_val);

    std::size_t unitblob_size = filled_val.length();

    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);

    auto write_iter = cv.begin();

    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    key_marshalling_type test_val_read;

    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    Key constructed_val_read = types::make_public_key<Key, Endianness>(test_val_read);

    BOOST_CHECK(val == constructed_val_read);
}

template<typename VerificationKey, typename VerificationKeyMarshalling, typename Endianness, std::size_t TSize,
        typename CurveType = typename VerificationKey::curve_type>
typename std::enable_if<
        std::is_same<nil::crypto3::zk::snark::r1cs_gg_ppzksnark_verification_key<CurveType>, VerificationKey>::value>::type
test_verification_key() {
    using g1_type = typename CurveType::template g1_type<>;
    using g2_type = typename CurveType::template g2_type<>;
    using gt_type = typename CurveType::gt_type;

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        typename g1_type::value_type first = nil::crypto3::algebra::random_element<g1_type>();
        std::vector<typename g1_type::value_type> rest;
        for (std::size_t i = 0; i < TSize; i++) {
            rest.push_back(nil::crypto3::algebra::random_element<g1_type>());
        }
        test_verification_key<Endianness, VerificationKeyMarshalling>(VerificationKey(
                nil::crypto3::algebra::random_element<gt_type>(),
                nil::crypto3::algebra::random_element<g2_type>(),
                nil::crypto3::algebra::random_element<g2_type>(),
                std::move(nil::crypto3::container::accumulation_vector<g1_type>(std::move(first), std::move(rest)))));
    }
}

template<typename VerificationKey, typename VerificationKeyMarshalling, typename Endianness, std::size_t TSize,
        typename CurveType = typename VerificationKey::curve_type>
typename std::enable_if<std::is_same<nil::crypto3::zk::snark::r1cs_gg_ppzksnark_extended_verification_key<CurveType>,
        VerificationKey>::value>::type
test_verification_key() {
    using g1_type = typename CurveType::template g1_type<>;
    using g2_type = typename CurveType::template g2_type<>;
    using gt_type = typename CurveType::gt_type;

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        typename g1_type::value_type first = nil::crypto3::algebra::random_element<g1_type>();
        std::vector<typename g1_type::value_type> rest;
        for (std::size_t i = 0; i < TSize; i++) {
            rest.push_back(nil::crypto3::algebra::random_element<g1_type>());
        }
        test_verification_key<Endianness, VerificationKeyMarshalling>(VerificationKey(
                nil::crypto3::algebra::random_element<gt_type>(),
                nil::crypto3::algebra::random_element<g2_type>(),
                nil::crypto3::algebra::random_element<g2_type>(),
                nil::crypto3::algebra::random_element<g1_type>(),
                std::move(nil::crypto3::container::accumulation_vector<g1_type>(std::move(first), std::move(rest))),
                nil::crypto3::algebra::random_element<g1_type>()));
    }
}

// TODO: move to pubkey marshling
template<typename PublicKey, typename PublicKeyMarshalling, typename Endianness, std::size_t TSize,
        typename CurveType = typename PublicKey::scheme_type::curve_type>
typename std::enable_if<
        std::is_same<nil::crypto3::pubkey::public_key<nil::crypto3::pubkey::elgamal_verifiable<
                typename PublicKey::scheme_type::curve_type, PublicKey::scheme_type::block_bits>>,
                PublicKey>::value>::type
test_pubkey() {
    using g1_type = typename PublicKey::g1_type;
    using g2_type = typename PublicKey::g2_type;

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        std::vector<typename g1_type::value_type> delta_s_g1;
        std::vector<typename g1_type::value_type> t_g1;
        std::vector<typename g2_type::value_type> t_g2;
        for (std::size_t i = 0; i < TSize; i++) {
            delta_s_g1.push_back(nil::crypto3::algebra::random_element<g1_type>());
            t_g1.push_back(nil::crypto3::algebra::random_element<g1_type>());
            t_g2.push_back(nil::crypto3::algebra::random_element<g2_type>());
        }
        t_g2.push_back(nil::crypto3::algebra::random_element<g2_type>());
        test_pubkey<Endianness, PublicKeyMarshalling>(PublicKey(
                nil::crypto3::algebra::random_element<g1_type>(), std::move(delta_s_g1), std::move(t_g1),
                std::move(t_g2),
                nil::crypto3::algebra::random_element<g1_type>(), nil::crypto3::algebra::random_element<g1_type>()));
    }
}

BOOST_AUTO_TEST_SUITE(verification_key_test_suite)

    BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_verification_key_bls12_381_be) {
        using endianness = nil::marshalling::option::big_endian;
        using key_type =
                nil::crypto3::zk::snark::r1cs_gg_ppzksnark_verification_key<nil::crypto3::algebra::curves::bls12<381>>;
        using key_marshalling_type =
                nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<endianness>,
                        key_type>;
        std::cout << "BLS12-381 r1cs_gg_ppzksnark verification key big-endian test started" << std::endl;
        test_verification_key<key_type, key_marshalling_type, endianness, 5>();
        std::cout << "BLS12-381 r1cs_gg_ppzksnark verification key big-endian test finished" << std::endl;
    }

    BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_extended_verification_key_bls12_381_be) {
        using endianness = nil::marshalling::option::big_endian;
        using key_type =
                nil::crypto3::zk::snark::r1cs_gg_ppzksnark_extended_verification_key<nil::crypto3::algebra::curves::bls12<381>>;
        using key_marshalling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_extended_verification_key<
                nil::marshalling::field_type<endianness>, key_type>;
        std::cout << "BLS12-381 r1cs_gg_ppzksnark extended verification key big-endian test started" << std::endl;
        test_verification_key<key_type, key_marshalling_type, endianness, 5>();
        std::cout << "BLS12-381 r1cs_gg_ppzksnark extended verification key big-endian test finished" << std::endl;
    }

// TODO: move to pubkey marshling
    BOOST_AUTO_TEST_CASE(elgamal_verifiable_public_key_bls12_381_be) {
        using endianness = nil::marshalling::option::big_endian;
        using key_type = nil::crypto3::pubkey::public_key<
                nil::crypto3::pubkey::elgamal_verifiable<nil::crypto3::algebra::curves::bls12<381>>>;
        using key_marshalling_type =
                nil::crypto3::marshalling::types::elgamal_verifiable_public_key<nil::marshalling::field_type<endianness>,
                        key_type>;
        std::cout << "BLS12-381 r1cs_gg_ppzksnark extended verification key big-endian test started" << std::endl;
        test_pubkey<key_type, key_marshalling_type, endianness, 5>();
        std::cout << "BLS12-381 r1cs_gg_ppzksnark extended verification key big-endian test finished" << std::endl;
    }

    BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_extended_verification_key_bls12_381_be_error_length) {
        using endianness = nil::marshalling::option::big_endian;
        using curve_type = nil::crypto3::algebra::curves::bls12<381>;

        using g1_type = typename curve_type::template g1_type<>;
        using g2_type = typename curve_type::template g2_type<>;
        using gt_type = typename curve_type::gt_type;

        using gt_marshalling_type =
                nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<endianness>, typename gt_type::value_type>;
        using g2_marshalling_type =
                nil::crypto3::marshalling::types::curve_element<nil::marshalling::field_type<endianness>, g2_type>;
        using g1_marshalling_type =
                nil::crypto3::marshalling::types::curve_element<nil::marshalling::field_type<endianness>, g1_type>;
        using accumulation_vector_marshalling_type =
                nil::crypto3::marshalling::types::accumulation_vector<nil::marshalling::field_type<endianness>,
                        nil::crypto3::container::accumulation_vector<g1_type>>;
        gt_marshalling_type filled_gt(nil::crypto3::algebra::random_element<gt_type>());
        std::cout << "Ok only after initialization: " << filled_gt.length() << std::endl;

        g2_marshalling_type g2_marshalling;
        std::cout << "Ok: " << g2_marshalling.length() << std::endl;

        g1_marshalling_type g1_marshalling;
        std::cout << "Ok: " << g1_marshalling.length() << std::endl;

        accumulation_vector_marshalling_type accumulation_vector_marshalling;
        std::cout << "Seems ok, full information about size should be available after initialization: "
                  << accumulation_vector_marshalling.length() << std::endl;
        typename g1_type::value_type first = nil::crypto3::algebra::random_element<g1_type>();
        std::vector<typename g1_type::value_type> rest;
        for (std::size_t i = 0; i < 5; i++) {
            rest.push_back(nil::crypto3::algebra::random_element<g1_type>());
        }
        nil::crypto3::container::accumulation_vector<g1_type> acc_vec(std::move(first), std::move(rest));
        accumulation_vector_marshalling_type filled_acc_vec = nil::crypto3::marshalling::types::fill_accumulation_vector<
                nil::crypto3::container::accumulation_vector<g1_type>, endianness>(acc_vec);
        std::cout << "Ok: " << filled_acc_vec.length() << std::endl;

        // key_type key(nil::crypto3::algebra::random_element<gt_type>(),
        //              nil::crypto3::algebra::random_element<g2_type>(),
        //              nil::crypto3::algebra::random_element<g2_type>(),
        //              nil::crypto3::algebra::random_element<g1_type>(),
        //              std::move(zk::snark::accumulation_vector<g1_type>(std::move(first), std::move(rest))),
        //              nil::crypto3::algebra::random_element<g1_type>());
    }

// BOOST_AUTO_TEST_CASE(sparse_vector_bls12_381_le) {
//     std::cout << "BLS12-381 r1cs_gg_ppzksnark verification key little-endian test started" << std::endl;
//     test_verification_key<nil::crypto3::algebra::curves::bls12<381>, nil::marshalling::option::little_endian, 5>();
//     std::cout << "BLS12-381 r1cs_gg_ppzksnark verification key little-endian test finished" << std::endl;
// }

BOOST_AUTO_TEST_SUITE_END()
