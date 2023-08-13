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

#define BOOST_TEST_MODULE crypto3_marshalling_r1cs_gg_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <iostream>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

//#include <nil/crypto3/zk/blueprint/r1cs.hpp>
//#include <nil/crypto3/zk/blueprint/detail/r1cs/blueprint_variable.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/algorithms/generate.hpp>
#include <nil/crypto3/zk/algorithms/verify.hpp>
#include <nil/crypto3/zk/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>

#include "detail/r1cs_examples.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;

template<typename CurveType, typename Endianness>
bool test_r1cs_gg_ppzksnark() {

    std::size_t num_constraints = 1000, input_size = 100;

    typedef CurveType curve_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

    std::cout << "R1CS generation started." << std::endl;

    zk::snark::r1cs_example<scalar_field_type> example =
        zk::snark::generate_r1cs_example_with_binary_input<scalar_field_type>(num_constraints, input_size);

    std::cout << "R1CS generation finished." << std::endl;

    std::cout << "Starting generator" << std::endl;

    typename scheme_type::keypair_type keypair = zk::generate<scheme_type>(example.constraint_system);

    std::cout << "Starting prover" << std::endl;

    const typename scheme_type::proof_type proof =
        zk::prove<scheme_type>(keypair.first, example.primary_input, example.auxiliary_input);

    using verification_key_marshalling_type =
        types::r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<Endianness>,
                                                  typename scheme_type::verification_key_type>;

    verification_key_marshalling_type filled_verification_key_val =
        types::fill_r1cs_gg_ppzksnark_verification_key<typename scheme_type::verification_key_type, Endianness>(
            keypair.second);

    using proof_marshalling_type =
        types::r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<Endianness>, typename scheme_type::proof_type>;

    proof_marshalling_type filled_proof_val =
        types::fill_r1cs_gg_ppzksnark_proof<typename scheme_type::proof_type, Endianness>(proof);

    using primary_input_marshalling_type =
        types::r1cs_gg_ppzksnark_primary_input<nil::marshalling::field_type<Endianness>,
                                               typename scheme_type::primary_input_type>;

    primary_input_marshalling_type filled_primary_input_val =
        types::fill_r1cs_gg_ppzksnark_primary_input<typename scheme_type::primary_input_type, Endianness>(
            example.primary_input);

    std::cout << "Marshalling types filled." << std::endl;

    using unit_type = unsigned char;

    std::vector<unit_type> verification_key_byteblob;
    verification_key_byteblob.resize(filled_verification_key_val.length(), 0x00);
    auto write_iter = verification_key_byteblob.begin();

    typename nil::marshalling::status_type status =
        filled_verification_key_val.write(write_iter, verification_key_byteblob.size());

    std::vector<unit_type> proof_byteblob;
    proof_byteblob.resize(filled_proof_val.length(), 0x00);
    write_iter = proof_byteblob.begin();

    status = filled_proof_val.write(write_iter, proof_byteblob.size());

    std::vector<unit_type> primary_input_byteblob;

    primary_input_byteblob.resize(filled_primary_input_val.length(), 0x00);
    auto primary_input_write_iter = primary_input_byteblob.begin();

    status = filled_primary_input_val.write(primary_input_write_iter, primary_input_byteblob.size());

    std::cout << "Byteblobs filled." << std::endl;

    verification_key_marshalling_type val_verification_key_read;

    auto read_iter = verification_key_byteblob.begin();
    status = val_verification_key_read.read(read_iter, verification_key_byteblob.size());

    typename scheme_type::verification_key_type constructed_val_verification_key_read =
        types::make_r1cs_gg_ppzksnark_verification_key<typename scheme_type::verification_key_type, Endianness>(
            val_verification_key_read);

    proof_marshalling_type val_proof_read;

    read_iter = proof_byteblob.begin();
    status = val_proof_read.read(read_iter, proof_byteblob.size());

    typename scheme_type::proof_type constructed_val_proof_read =
        types::make_r1cs_gg_ppzksnark_proof<typename scheme_type::proof_type, Endianness>(val_proof_read);

    primary_input_marshalling_type val_primary_input_read;

    read_iter = primary_input_byteblob.begin();
    status = val_primary_input_read.read(read_iter, primary_input_byteblob.size());

    typename scheme_type::primary_input_type constructed_val_primary_input_read =
        types::make_r1cs_gg_ppzksnark_primary_input<typename scheme_type::primary_input_type, Endianness>(
            val_primary_input_read);

    bool ans = zk::verify<scheme_type>(constructed_val_verification_key_read, constructed_val_primary_input_read,
                                              constructed_val_proof_read);

    return ans;
}

BOOST_AUTO_TEST_SUITE(r1cs_gg_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_bls12_381_be) {
    std::cout << "BLS12-381 r1cs_gg_ppzksnark big-endian test started" << std::endl;
    bool res =
        test_r1cs_gg_ppzksnark<nil::crypto3::algebra::curves::bls12<381>, nil::marshalling::option::big_endian>();
    BOOST_CHECK(res);
    std::cout << "BLS12-381 r1cs_gg_ppzksnark big-endian test finished" << std::endl;
}

// BOOST_AUTO_TEST_CASE(proof_bls12_381_le) {
//     std::cout << "BLS12-381 r1cs_gg_ppzksnark proof little-endian test started" << std::endl;
//     test_proof<nil::crypto3::zk::snark::r1cs_gg_ppzksnark<nil::crypto3::algebra::curves::bls12<381>>,
//         nil::marshalling::option::little_endian>();
//     std::cout << "BLS12-381 r1cs_gg_ppzksnark proof little-endian test finished" << std::endl;
// }

BOOST_AUTO_TEST_SUITE_END()