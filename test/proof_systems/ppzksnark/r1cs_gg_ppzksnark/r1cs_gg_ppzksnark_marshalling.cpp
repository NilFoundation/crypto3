//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Test program that exercises the ppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_gg_ppzksnark_marshalling_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>


#include <nil/crypto3/zk/snark/blueprint.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(r1cs_gg_ppzksnark_marshalling_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_gg_ppzksnark_marshalling_test){
    using curve_type = curves::mnt4<298>;
    std::vector<std::uint8_t> data = nil::crypto3::zk::snark::detail::verifier_data_to_bits<
    	r1cs_gg_ppzksnark<curve_type>>::process();
    nil::crypto3::zk::snark::detail::verifier_data_from_bits<
    	r1cs_gg_ppzksnark<curve_type>>::process(data);
}

BOOST_AUTO_TEST_SUITE_END()
