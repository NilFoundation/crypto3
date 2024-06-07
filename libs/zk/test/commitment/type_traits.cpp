//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE commitments_type_traits_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

// #include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/commitments/polynomial/pedersen.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(commitments_type_traits_test_suite)

    BOOST_AUTO_TEST_CASE(commitments_type_traits_basic_test) {

        typedef algebra::curves::bls12<381> curve_type;
        typedef curve_type::base_field_type field_type;

        typedef hashes::sha2<256> merkle_hash_type;
        typedef hashes::sha2<256> transcript_hash_type;

        constexpr static const std::size_t m = 2;

        //    static_assert(zk::is_commitment<
        //            zk::commitments::kzg<curve_type>>::value);
        static_assert(
                zk::is_commitment<zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, m>>::value);
        static_assert(
                zk::is_commitment<zk::commitments::lpc<field_type, zk::commitments::list_polynomial_commitment_params<
                        merkle_hash_type, transcript_hash_type, m>>>::value);
        static_assert(
                zk::is_commitment<zk::commitments::batched_lpc<
                        field_type,
                        zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, m>>>::value);
        static_assert(zk::is_commitment<zk::commitments::pedersen<curve_type>>::value);
        static_assert(zk::is_commitment<zk::commitments::kimchi_pedersen<curve_type>>::value);
    }

BOOST_AUTO_TEST_SUITE_END()
