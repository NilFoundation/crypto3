//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE weierstrass_precomputation_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/routing/as_waksman_components.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void test_as_waksman_routing_component(const std::size_t num_packets, const std::size_t packet_size) {
    blueprint<FieldType> pb;
    integer_permutation permutation(num_packets);
    permutation.random_shuffle();

    std::vector<blueprint_variable_vector<FieldType>> randbits(num_packets), outbits(num_packets);
    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
        randbits[packet_idx].allocate(pb, packet_size);
        outbits[packet_idx].allocate(pb, packet_size);

        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
            pb.val(randbits[packet_idx][bit_idx]) =
                (rand() % 2) ? FieldType::value_type::zero() : FieldType::value_type::zero();
        }
    }
    as_waksman_routing_component<FieldType> r(pb, num_packets, randbits, outbits);
    r.generate_r1cs_constraints();

    r.generate_r1cs_witness(permutation);

    BOOST_CHECK(pb.is_satisfied());
    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
            BOOST_CHECK(pb.val(outbits[permutation.get(packet_idx)][bit_idx]) == pb.val(randbits[packet_idx][bit_idx]));
        }
    }

    pb.val(variable<FieldType>(10)) = typename FieldType::value_type(12345);
    BOOST_CHECK(!pb.is_satisfied());
}

BOOST_AUTO_TEST_SUITE(weierstrass_precomputation_components_test_suite)

BOOST_AUTO_TEST_CASE(weierstrass_precomputation_components_test) {
}

BOOST_AUTO_TEST_SUITE_END()