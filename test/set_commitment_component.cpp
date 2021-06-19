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

#define BOOST_TEST_MODULE set_commitment_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/components/hashes/sha256/sha256_component.hpp>
#include <nil/crypto3/zk/snark/components/set_commitment/set_commitment_component.hpp>

using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FieldT, typename HashT>
void test_set_commitment_component(){

    const std::size_t digest_len = HashT::digest_bits;
    const std::size_t max_set_size = 16;
    const std::size_t value_size = (HashT::block_bits > 0 ? HashT::block_bits : 10);

    set_commitment_accumulator<HashT> accumulator(max_set_size, value_size);

    std::vector<algebra::bit_vector> set_elems;
    for (std::size_t i = 0; i < max_set_size; ++i){
        algebra::bit_vector elem(value_size);
        std::generate(elem.begin(), elem.end(), [&]() { return std::rand() % 2; });
        set_elems.emplace_back(elem);
        accumulator.add(elem);
        BOOST_CHECK(accumulator.is_in_set(elem));
    }

    components::blueprint<FieldT> bp;
    components::blueprint_variable_array<FieldT> element_bits;
    element_bits.allocate(bp, value_size);
    set_commitment_variable<FieldT, HashT> root_digest(bp, digest_len);

    bp_variable<FieldT> check_succesful;
    check_succesful.allocate(bp);

    set_membership_proof_variable<FieldT, HashT> proof(bp, max_set_size);

    set_commitment_component<FieldT, HashT> sc(bp, max_set_size, element_bits, root_digest, proof, check_succesful);
    sc.generate_r1cs_constraints();

    /* test all elements from set */
    for (std::size_t i = 0; i < max_set_size; ++i){
        element_bits.fill_with_bits(bp, set_elems[i]);
        bp.val(check_succesful) = FieldT::one();
        proof.generate_r1cs_witness(accumulator.get_membership_proof(set_elems[i]));
        sc.generate_r1cs_witness();
        root_digest.generate_r1cs_witness(accumulator.get_commitment());
        BOOST_CHECK(bp.is_satisfied());
    }
    std::cout << "membership tests OK" << std::endl;

    /* test an element not in set */
    for (std::size_t i = 0; i < value_size; ++i){
        bp.val(element_bits[i]) = FieldT(std::rand() % 2);
    }

    bp.val(check_succesful) = FieldT::zero(); /* do not require the check result to be successful */
    proof.generate_r1cs_witness(accumulator.get_membership_proof(set_elems[0])); /* try it with invalid proof */
    sc.generate_r1cs_witness();
    root_digest.generate_r1cs_witness(accumulator.get_commitment());
    BOOST_CHECK(bp.is_satisfied());

    bp.val(check_succesful) = FieldT::one(); /* now require the check result to be succesful */
    proof.generate_r1cs_witness(accumulator.get_membership_proof(set_elems[0])); /* try it with invalid proof */
    sc.generate_r1cs_witness();
    root_digest.generate_r1cs_witness(accumulator.get_commitment());
    BOOST_CHECK(!bp.is_satisfied()); /* the blueprint should be unsatisfied */
    std::cout << "non-membership test OK" << std::endl;
}

template<typename CurveType>
void test_all_set_commitment_components() {
    typedef typename CurveType::scalar_field_type scalar_field_type;

    // for now all CRH components are knapsack CRH's; can be easily extended
    // later to more expressive selector types.
    using crh_with_field_out_component = knapsack_crh_with_field_out_component<scalar_field_type>;
    using crh_with_bit_out_component = knapsack_crh_with_bit_out_component<scalar_field_type>;

    test_set_commitment_component<scalar_field_type, crh_with_bit_out_component>();
    test_set_commitment_component<scalar_field_type, sha256_two_to_one_hash_component<scalar_field_type>>();
}

int main(void) {
    test_all_set_commitment_components<curves::bls12<381>>();
    test_all_set_commitment_components<curves::mnt4<298>>();
    test_all_set_commitment_components<curves::mnt6<298>>();
}
