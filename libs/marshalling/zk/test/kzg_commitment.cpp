//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_kzg_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <iostream>
#include <iomanip>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp> 

/*
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
*/

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/eval_storage.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>

#include "detail/circuits.hpp"

template<
    typename curve_type,
    typename transcript_hash_type
    >
struct placeholder_class_test_initializer {
    bool run_test() {
        typedef typename curve_type::scalar_field_type::value_type scalar_value_type;

        using kzg_type = zk::commitments::batched_kzg<curve_type, transcript_hash_type>;
        typedef typename kzg_type::transcript_type transcript_type;
        using kzg_scheme_type = typename zk::commitments::kzg_commitment_scheme_v2<kzg_type>;
        using endianness = nil::marshalling::option::big_endian;

        scalar_value_type alpha = 7u;
        auto params = kzg_scheme_type::create_params(8, alpha);
        kzg_scheme_type kzg(params);

        typename kzg_type::batch_of_polynomials_type polys(4);

        polys[0].template from_coefficients<std::vector<scalar_value_type>>({{ 1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u}});
        polys[1].template from_coefficients<std::vector<scalar_value_type>>({{11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u}});
        polys[2].template from_coefficients<std::vector<scalar_value_type>>({{21u, 22u, 23u, 24u, 25u, 26u, 27u, 28u}});
        polys[3].template from_coefficients<std::vector<scalar_value_type>>({{31u, 32u, 33u, 34u, 35u, 36u, 37u, 38u}});


        std::size_t batch_id = 0;

        kzg.append_to_batch(batch_id, polys);
        std::map<std::size_t, typename kzg_scheme_type::commitment_type> commitments;
        commitments[batch_id] = kzg.commit(batch_id);

        std::set<scalar_value_type> points_0 = {101u, 2u, 3u};
        std::set<scalar_value_type> points_1 = {102u, 2u, 3u};
        std::set<scalar_value_type> points_2 = {  1u, 2u, 3u};
        std::set<scalar_value_type> points_3 = {104u, 2u, 3u};
        kzg.append_eval_points(batch_id, 0, points_0);
        kzg.append_eval_points(batch_id, 1, points_1);
        kzg.append_eval_points(batch_id, 2, points_2);
        kzg.append_eval_points(batch_id, 3, points_3);

        transcript_type transcript;
        auto proof = kzg.proof_eval(transcript);

        auto filled_proof = nil::crypto3::marshalling::types::fill_eval_proof<endianness, kzg_scheme_type>(proof, params);
        auto _proof = nil::crypto3::marshalling::types::make_eval_proof<endianness, kzg_scheme_type>(filled_proof);

        BOOST_CHECK( _proof == proof);

        transcript_type transcript_verification;
        bool result = kzg.verify_eval(_proof, commitments, transcript_verification);

        std::cout << "test completed for [" << typeid(curve_type).name() << "]" <<std::endl;

        return result;
    }
};

BOOST_AUTO_TEST_SUITE(placeholder_class)
    using TestFixtures = boost::mpl::list<
        placeholder_class_test_initializer< algebra::curves::bls12_381, hashes::keccak_1600<256> >,
        placeholder_class_test_initializer< algebra::curves::mnt4_298, hashes::keccak_1600<256> >,
        placeholder_class_test_initializer< algebra::curves::mnt6_298, hashes::keccak_1600<256> >
        >;

BOOST_AUTO_TEST_CASE_TEMPLATE(placeholder_class_test, F, TestFixtures) {
    F fixture;
    BOOST_CHECK(fixture.run_test());
}

BOOST_AUTO_TEST_SUITE_END()
