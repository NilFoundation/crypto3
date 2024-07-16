//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE proof_of_work_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/proof_of_work.hpp>

#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::commitments;

BOOST_AUTO_TEST_SUITE(proof_of_knowledge_test_suite)

    BOOST_AUTO_TEST_CASE(pow_poseidon_basic_test) {
        using curve_type = curves::pallas;
        using field_type = curve_type::base_field_type;
        using integral_type = typename field_type::integral_type;
        using policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
        using poseidon = nil::crypto3::hashes::poseidon<policy>;
        using pow_type = nil::crypto3::zk::commitments::field_proof_of_work<poseidon, field_type>;

        std::size_t grinding_bits = 9;
        nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<poseidon> transcript;
        auto old_transcript_1 = transcript, old_transcript_2 = transcript;

        auto result = pow_type::generate(transcript, grinding_bits);
        BOOST_ASSERT(pow_type::verify(old_transcript_1, result, grinding_bits));

        // manually reimplement verify to ensure that changes in implementation didn't break it
        old_transcript_2(result);
        auto chal = old_transcript_2.template challenge<field_type>();
        const integral_type expected_mask = integral_type( (1 << grinding_bits) - 1 ) << (field_type::modulus_bits - grinding_bits);

        BOOST_ASSERT((integral_type(chal.data) & expected_mask) == 0);

        using hard_pow_type = nil::crypto3::zk::commitments::field_proof_of_work<poseidon, field_type>;
        // check that random stuff doesn't pass verify
        BOOST_ASSERT(!hard_pow_type::verify(old_transcript_1, result, 9));
    }

    BOOST_AUTO_TEST_CASE(pow_basic_test) {
        using keccak = nil::crypto3::hashes::keccak_1600<512>;

        const std::uint32_t grinding_bits = 20;
        const uint64_t expected_mask = (1ULL << grinding_bits) - 1;

        using pow_type = nil::crypto3::zk::commitments::proof_of_work<keccak, std::uint32_t>;

        nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<keccak> transcript;
        auto old_transcript_1 = transcript, old_transcript_2 = transcript;

        auto result = pow_type::generate(transcript, grinding_bits);
        BOOST_ASSERT(pow_type::verify(old_transcript_1, result, grinding_bits));

        // manually reimplement verify to ensure that changes in implementation didn't break it
        old_transcript_2(pow_type::to_byte_array(result));
        auto chal = old_transcript_2.template int_challenge<std::uint32_t>();
        BOOST_ASSERT( (chal & expected_mask) == 0);

        // check that random stuff doesn't pass verify
        using hard_pow_type = nil::crypto3::zk::commitments::proof_of_work<keccak, std::uint32_t>;
        BOOST_ASSERT(!hard_pow_type::verify(old_transcript_1, result, grinding_bits));
    }

BOOST_AUTO_TEST_SUITE_END()
