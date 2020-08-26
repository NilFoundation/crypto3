//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the Benes routing gadget.
//
// The gadget verifies that the outputs are a permutation of the inputs,
// by use of a Benes network.
//---------------------------------------------------------------------------//

#ifndef BENES_ROUTING_GADGET_HPP_
#define BENES_ROUTING_GADGET_HPP_

#include <nil/crypto3/zk/snark/integer_permutation.hpp>
#include <nil/crypto3/zk/snark/routing_algorithms/benes_routing_algorithm.hpp>
#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/protoboard.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class benes_routing_gadget : public gadget<FieldType> {
                private:
                    /*
                      Indexing conventions:

                      routed_packets[column_idx][packet_idx][subpacket_idx]
                      pack_inputs/unpack_outputs[packet_idx]
                      benes_switch_bits[column_idx][row_idx]

                      Where column_idx ranges is in range 0 .. 2*dimension
                      (2*dimension-1 for switch bits/topology) and packet_idx is in
                      range 0 .. num_packets-1.
                    */
                    std::vector<std::vector<pb_variable_array<FieldType>>> routed_packets;
                    std::vector<multipacking_gadget<FieldType>> pack_inputs, unpack_outputs;

                    /*
                      If #packets = 1 then we can route without explicit routing bits
                      (and save half the constraints); in this case benes_switch_bits will
                      be unused.

                      For benes_switch_bits 0 corresponds to straight edge and 1
                      corresponds to cross edge.
                    */
                    std::vector<pb_variable_array<FieldType>> benes_switch_bits;
                    benes_topology neighbors;

                public:
                    const std::size_t num_packets;
                    const std::size_t num_columns;

                    const std::vector<pb_variable_array<FieldType>> routing_input_bits;
                    const std::vector<pb_variable_array<FieldType>> routing_output_bits;
                    std::size_t lines_to_unpack;

                    const std::size_t packet_size, num_subpackets;

                    benes_routing_gadget(protoboard<FieldType> &pb,
                                         const std::size_t num_packets,
                                         const std::vector<pb_variable_array<FieldType>> &routing_input_bits,
                                         const std::vector<pb_variable_array<FieldType>> &routing_output_bits,
                                         const std::size_t lines_to_unpack);

                    void generate_r1cs_constraints();

                    void generate_r1cs_witness(const integer_permutation &permutation);
                };

                template<typename FieldType>
                void test_benes_routing_gadget(const std::size_t num_packets, const std::size_t packet_size);

                template<typename FieldType>
                benes_routing_gadget<FieldType>::benes_routing_gadget(
                    protoboard<FieldType> &pb,
                    const std::size_t num_packets,
                    const std::vector<pb_variable_array<FieldType>> &routing_input_bits,
                    const std::vector<pb_variable_array<FieldType>> &routing_output_bits,
                    const std::size_t lines_to_unpack) :
                    gadget<FieldType>(pb),
                    num_packets(num_packets), num_columns(benes_num_columns(num_packets)),
                    routing_input_bits(routing_input_bits), routing_output_bits(routing_output_bits),
                    lines_to_unpack(lines_to_unpack), packet_size(routing_input_bits[0].size()),
                    num_subpackets((packet_size + FieldType::capacity() - 1) / FieldType::capacity()) {
                    assert(lines_to_unpack <= routing_input_bits.size());
                    assert(num_packets == 1ul << static_cast<std::size_t>(std::ceil(std::log2(num_packets))));
                    assert(routing_input_bits.size() == num_packets);

                    neighbors = generate_benes_topology(num_packets);

                    routed_packets.resize(num_columns + 1);
                    for (std::size_t column_idx = 0; column_idx <= num_columns; ++column_idx) {
                        routed_packets[column_idx].resize(num_packets);
                        for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                            routed_packets[column_idx][packet_idx].allocate(pb, num_subpackets);
                        }
                    }

                    pack_inputs.reserve(num_packets);
                    unpack_outputs.reserve(num_packets);

                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs.emplace_back(multipacking_gadget<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(routing_input_bits[packet_idx].begin(),
                                                         routing_input_bits[packet_idx].end()),
                            routed_packets[0][packet_idx],
                            FieldType::capacity()));
                        if (packet_idx < lines_to_unpack) {
                            unpack_outputs.emplace_back(multipacking_gadget<FieldType>(
                                pb,
                                pb_variable_array<FieldType>(routing_output_bits[packet_idx].begin(),
                                                             routing_output_bits[packet_idx].end()),
                                routed_packets[num_columns][packet_idx],
                                FieldType::capacity()));
                        }
                    }

                    if (num_subpackets > 1) {
                        benes_switch_bits.resize(num_columns);
                        for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                            benes_switch_bits[column_idx].allocate(pb, num_packets);
                        }
                    }
                }

                template<typename FieldType>
                void benes_routing_gadget<FieldType>::generate_r1cs_constraints() {
                    /* packing/unpacking */
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs[packet_idx].generate_r1cs_constraints(false);
                        if (packet_idx < lines_to_unpack) {
                            unpack_outputs[packet_idx].generate_r1cs_constraints(true);
                        } else {
                            for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                this->pb.add_r1cs_constraint(
                                    r1cs_constraint<FieldType>(1, routed_packets[0][packet_idx][subpacket_idx],
                                                               routed_packets[num_columns][packet_idx][subpacket_idx]));
                            }
                        }
                    }

                    /* actual routing constraints */
                    for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                        for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                            const std::size_t straight_edge = neighbors[column_idx][packet_idx].first;
                            const std::size_t cross_edge = neighbors[column_idx][packet_idx].second;

                            if (num_subpackets == 1) {
                                /* easy case: (cur-next)*(cur-cross) = 0 */
                                this->pb.add_r1cs_constraint(
                                    r1cs_constraint<FieldType>(routed_packets[column_idx][packet_idx][0] -
                                                                   routed_packets[column_idx + 1][straight_edge][0],
                                                               routed_packets[column_idx][packet_idx][0] -
                                                                   routed_packets[column_idx + 1][cross_edge][0],
                                                               0));
                            } else {
                                /* routing bit must be boolean */
                                generate_boolean_r1cs_constraint<FieldType>(this->pb,
                                                                            benes_switch_bits[column_idx][packet_idx]);

                                /* route forward according to routing bits */
                                for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                    /*
                                      (1-switch_bit) * (cur-straight_edge) + switch_bit * (cur-cross_edge) = 0
                                      switch_bit * (cross_edge-straight_edge) = cur-straight_edge
                                    */
                                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                                        benes_switch_bits[column_idx][packet_idx],
                                        routed_packets[column_idx + 1][cross_edge][subpacket_idx] -
                                            routed_packets[column_idx + 1][straight_edge][subpacket_idx],
                                        routed_packets[column_idx][packet_idx][subpacket_idx] -
                                            routed_packets[column_idx + 1][straight_edge][subpacket_idx]));
                                }
                            }
                        }
                    }
                }

                template<typename FieldType>
                void benes_routing_gadget<FieldType>::generate_r1cs_witness(const integer_permutation &permutation) {
                    /* pack inputs */
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs[packet_idx].generate_r1cs_witness_from_bits();
                    }

                    /* do the routing */
                    const benes_routing routing = get_benes_routing(permutation);

                    for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                        for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                            const std::size_t straight_edge = neighbors[column_idx][packet_idx].first;
                            const std::size_t cross_edge = neighbors[column_idx][packet_idx].second;

                            if (num_subpackets > 1) {
                                this->pb.val(benes_switch_bits[column_idx][packet_idx]) =
                                    typename FieldType::value_type(routing[column_idx][packet_idx] ? 1 : 0);
                            }

                            for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                this->pb.val(routing[column_idx][packet_idx] ?
                                                 routed_packets[column_idx + 1][cross_edge][subpacket_idx] :
                                                 routed_packets[column_idx + 1][straight_edge][subpacket_idx]) =
                                    this->pb.val(routed_packets[column_idx][packet_idx][subpacket_idx]);
                            }
                        }
                    }

                    /* unpack outputs */
                    for (std::size_t packet_idx = 0; packet_idx < lines_to_unpack; ++packet_idx) {
                        unpack_outputs[packet_idx].generate_r1cs_witness_from_packed();
                    }
                }

                template<typename FieldType>
                void test_benes_routing_gadget(const std::size_t num_packets, const std::size_t packet_size) {
                    const std::size_t dimension = static_cast<std::size_t>(std::ceil(std::log2(num_packets)));
                    assert(num_packets == 1ul << dimension);

                    protoboard<FieldType> pb;
                    integer_permutation permutation(num_packets);
                    permutation.random_shuffle();

                    std::vector<pb_variable_array<FieldType>> randbits(num_packets), outbits(num_packets);
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        randbits[packet_idx].allocate(pb, packet_size);
                        outbits[packet_idx].allocate(pb, packet_size);

                        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
                            pb.val(randbits[packet_idx][bit_idx]) = (rand() % 2) ? FieldType::one() : FieldType::zero();
                        }
                    }

                    benes_routing_gadget<FieldType> r(pb, num_packets, randbits, outbits, num_packets);
                    r.generate_r1cs_constraints();
                    r.generate_r1cs_witness(permutation);

                    assert(pb.is_satisfied());
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
                            assert(pb.val(outbits[permutation.get(packet_idx)][bit_idx]) ==
                                   pb.val(randbits[packet_idx][bit_idx]));
                        }
                    }

                    pb.val(pb_variable<FieldType>(10)) = typename FieldType::value_type(12345);
                    assert(!pb.is_satisfied());
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BENES_ROUTING_GADGET_HPP_
