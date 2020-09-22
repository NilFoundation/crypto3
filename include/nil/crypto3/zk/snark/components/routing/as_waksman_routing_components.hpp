//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the AS-Waksman routing component.
//
// The component verifies that the outputs are a permutation of the inputs,
// by use of an AS-Waksman network.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_AS_WAKSMAN_ROUTING_GADGET_HPP_
#define CRYPTO3_ZK_AS_WAKSMAN_ROUTING_GADGET_HPP_

#include <nil/crypto3/zk/snark/integer_permutation.hpp>
#include <nil/crypto3/zk/snark/routing_algorithms/as_waksman_routing_algorithm.hpp>
#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/blueprint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class as_waksman_routing_component : public component<FieldType> {
                private:
                    /*
                      Indexing conventions:

                      routed_packets[column_idx][packet_idx][subpacket_idx]
                      pack_inputs/unpack_outputs[packet_idx]
                      asw_switch_bits[column_idx][row_idx]

                      Where column_idx ranges is in range 0 .. width and packet_idx is
                      in range 0 .. num_packets-1.

                      Note that unlike in Bene\v{s} routing networks row_idx are
                      *not* necessarily consecutive; similarly for straight edges
                      routed_packets[column_idx][packet_idx] will *reuse* previously
                      allocated variables.

                    */
                    std::vector<std::vector<pb_variable_array<FieldType>>> routed_packets;
                    std::vector<multipacking_component<FieldType>> pack_inputs, unpack_outputs;

                    /*
                      If #packets = 1 then we can route without explicit switch bits
                      (and save half the constraints); in this case asw_switch_bits will
                      be unused.

                      For asw_switch_bits 0 corresponds to switch off (straight
                      connection), and 1 corresponds to switch on (crossed
                      connection).
                    */
                    std::vector<std::map<std::size_t, variable<FieldType>>> asw_switch_bits;
                    as_waksman_topology neighbors;

                public:
                    const std::size_t num_packets;
                    const std::size_t num_columns;
                    const std::vector<pb_variable_array<FieldType>> routing_input_bits;
                    const std::vector<pb_variable_array<FieldType>> routing_output_bits;

                    const std::size_t packet_size, num_subpackets;

                    as_waksman_routing_component(blueprint<FieldType> &pb,
                                              const std::size_t num_packets,
                                              const std::vector<pb_variable_array<FieldType>> &routing_input_bits,
                                              const std::vector<pb_variable_array<FieldType>> &routing_output_bits);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const integer_permutation &permutation);
                };

                template<typename FieldType>
                void test_as_waksman_routing_component(const std::size_t num_packets, const std::size_t packet_size);

                template<typename FieldType>
                as_waksman_routing_component<FieldType>::as_waksman_routing_component(
                    blueprint<FieldType> &pb,
                    const std::size_t num_packets,
                    const std::vector<pb_variable_array<FieldType>> &routing_input_bits,
                    const std::vector<pb_variable_array<FieldType>> &routing_output_bits) :
                    component<FieldType>(pb),
                    num_packets(num_packets), num_columns(as_waksman_num_columns(num_packets)),
                    routing_input_bits(routing_input_bits), routing_output_bits(routing_output_bits),
                    packet_size(routing_input_bits[0].size()),
                    num_subpackets((packet_size + FieldType::capacity() - 1) / FieldType::capacity()) {
                    neighbors = generate_as_waksman_topology(num_packets);
                    routed_packets.resize(num_columns + 1);

                    /* Two pass allocation. First allocate LHS packets, then for every
                       switch either copy over the variables from previously allocated
                       to allocate target packets */
                    routed_packets[0].resize(num_packets);
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        routed_packets[0][packet_idx].allocate(pb, num_subpackets);
                    }

                    for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                        routed_packets[column_idx + 1].resize(num_packets);

                        for (std::size_t row_idx = 0; row_idx < num_packets; ++row_idx) {
                            if (neighbors[column_idx][row_idx].first == neighbors[column_idx][row_idx].second) {
                                /* This is a straight edge, so just copy over the previously allocated subpackets */
                                routed_packets[column_idx + 1][neighbors[column_idx][row_idx].first] =
                                    routed_packets[column_idx][row_idx];
                            } else {
                                const std::size_t straight_edge = neighbors[column_idx][row_idx].first;
                                const std::size_t cross_edge = neighbors[column_idx][row_idx].second;
                                routed_packets[column_idx + 1][straight_edge].allocate(pb, num_subpackets);
                                routed_packets[column_idx + 1][cross_edge].allocate(pb, num_subpackets);
                                ++row_idx; /* skip the next idx, as it to refers to the same packets */
                            }
                        }
                    }

                    /* create packing/unpacking components */
                    pack_inputs.reserve(num_packets);
                    unpack_outputs.reserve(num_packets);
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs.emplace_back(multipacking_component<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(routing_input_bits[packet_idx].begin(),
                                                         routing_input_bits[packet_idx].end()),
                            routed_packets[0][packet_idx],
                            FieldType::capacity()));
                        unpack_outputs.emplace_back(multipacking_component<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(routing_output_bits[packet_idx].begin(),
                                                         routing_output_bits[packet_idx].end()),
                            routed_packets[num_columns][packet_idx],
                            FieldType::capacity()));
                    }

                    /* allocate switch bits */
                    if (num_subpackets > 1) {
                        asw_switch_bits.resize(num_columns);

                        for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                            for (std::size_t row_idx = 0; row_idx < num_packets; ++row_idx) {
                                if (neighbors[column_idx][row_idx].first != neighbors[column_idx][row_idx].second) {
                                    asw_switch_bits[column_idx][row_idx].allocate(pb);
                                    ++row_idx; /* next row_idx corresponds to the same switch, so skip it */
                                }
                            }
                        }
                    }
                }

                template<typename FieldType>
                void as_waksman_routing_component<FieldType>::generate_r1cs_constraints() {
                    /* packing/unpacking */
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs[packet_idx].generate_r1cs_constraints(false);
                        unpack_outputs[packet_idx].generate_r1cs_constraints(true);
                    }

                    /* actual routing constraints */
                    for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                        for (std::size_t row_idx = 0; row_idx < num_packets; ++row_idx) {
                            if (neighbors[column_idx][row_idx].first == neighbors[column_idx][row_idx].second) {
                                /* if there is no switch at this position, then just continue with next row_idx */
                                continue;
                            }

                            if (num_subpackets == 1) {
                                /* easy case: require that
                                   (cur-straight_edge)*(cur-cross_edge) = 0 for both
                                   switch inputs */
                                for (std::size_t switch_input : {row_idx, row_idx + 1}) {
                                    const std::size_t straight_edge = neighbors[column_idx][switch_input].first;
                                    const std::size_t cross_edge = neighbors[column_idx][switch_input].second;

                                    this->pb.add_r1cs_constraint(
                                        r1cs_constraint<FieldType>(routed_packets[column_idx][switch_input][0] -
                                                                       routed_packets[column_idx + 1][straight_edge][0],
                                                                   routed_packets[column_idx][switch_input][0] -
                                                                       routed_packets[column_idx + 1][cross_edge][0],
                                                                   0));
                                }
                            } else {
                                /* require switching bit to be boolean */
                                generate_boolean_r1cs_constraint<FieldType>(this->pb,
                                                                            asw_switch_bits[column_idx][row_idx]);

                                /* route forward according to the switch bit */
                                for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                    /*
                                      (1-switch_bit) * (cur-straight_edge) + switch_bit * (cur-cross_edge) = 0
                                      switch_bit * (cross_edge-straight_edge) = cur-straight_edge
                                     */
                                    for (std::size_t switch_input : {row_idx, row_idx + 1}) {
                                        const std::size_t straight_edge = neighbors[column_idx][switch_input].first;
                                        const std::size_t cross_edge = neighbors[column_idx][switch_input].second;

                                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                                            asw_switch_bits[column_idx][row_idx],
                                            routed_packets[column_idx + 1][cross_edge][subpacket_idx] -
                                                routed_packets[column_idx + 1][straight_edge][subpacket_idx],
                                            routed_packets[column_idx][switch_input][subpacket_idx] -
                                                routed_packets[column_idx + 1][straight_edge][subpacket_idx]));
                                    }
                                }
                            }

                            /* we processed both switch inputs at once, so skip the next iteration */
                            ++row_idx;
                        }
                    }
                }

                template<typename FieldType>
                void as_waksman_routing_component<FieldType>::generate_r1cs_witness(
                    const integer_permutation &permutation) {
                    /* pack inputs */
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        pack_inputs[packet_idx].generate_r1cs_witness_from_bits();
                    }

                    /* do the routing */
                    as_waksman_routing routing = get_as_waksman_routing(permutation);

                    for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                        for (std::size_t row_idx = 0; row_idx < num_packets; ++row_idx) {
                            if (neighbors[column_idx][row_idx].first == neighbors[column_idx][row_idx].second) {
                                /* this is a straight edge, so just pass the values forward */
                                const std::size_t next = neighbors[column_idx][row_idx].first;

                                for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                    this->pb.val(routed_packets[column_idx + 1][next][subpacket_idx]) =
                                        this->pb.val(routed_packets[column_idx][row_idx][subpacket_idx]);
                                }
                            } else {
                                if (num_subpackets > 1) {
                                    /* update the switch bit */
                                    this->pb.val(asw_switch_bits[column_idx][row_idx]) =
                                        typename FieldType::value_type(routing[column_idx][row_idx] ? 1 : 0);
                                }

                                /* route according to the switch bit */
                                const bool switch_val = routing[column_idx][row_idx];

                                for (std::size_t switch_input : {row_idx, row_idx + 1}) {
                                    const std::size_t straight_edge = neighbors[column_idx][switch_input].first;
                                    const std::size_t cross_edge = neighbors[column_idx][switch_input].second;

                                    const std::size_t switched_edge = (switch_val ? cross_edge : straight_edge);

                                    for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                        this->pb.val(routed_packets[column_idx + 1][switched_edge][subpacket_idx]) =
                                            this->pb.val(routed_packets[column_idx][switch_input][subpacket_idx]);
                                    }
                                }

                                /* we processed both switch inputs at once, so skip the next iteration */
                                ++row_idx;
                            }
                        }
                    }

                    /* unpack outputs */
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        unpack_outputs[packet_idx].generate_r1cs_witness_from_packed();
                    }
                }

                template<typename FieldType>
                void test_as_waksman_routing_component(const std::size_t num_packets, const std::size_t packet_size) {
                    blueprint<FieldType> pb;
                    integer_permutation permutation(num_packets);
                    permutation.random_shuffle();

                    std::vector<pb_variable_array<FieldType>> randbits(num_packets), outbits(num_packets);
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        randbits[packet_idx].allocate(pb, packet_size);
                        outbits[packet_idx].allocate(pb, packet_size);

                        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
                            pb.val(randbits[packet_idx][bit_idx]) = (rand() % 2) ? FieldType::value_type::zero() : FieldType::value_type::zero();
                        }
                    }
                    as_waksman_routing_component<FieldType> r(pb, num_packets, randbits, outbits);
                    r.generate_r1cs_constraints();

                    r.generate_r1cs_witness(permutation);

                    assert(pb.is_satisfied());
                    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
                            assert(pb.val(outbits[permutation.get(packet_idx)][bit_idx]) ==
                                   pb.val(randbits[packet_idx][bit_idx]));
                        }
                    }

                    pb.val(variable<FieldType>(10)) = typename FieldType::value_type(12345);
                    assert(!pb.is_satisfied());
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // AS_WAKSMAN_ROUTING_GADGET_HPP_
