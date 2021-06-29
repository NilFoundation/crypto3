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
// @file Declaration of interfaces for the Benes routing component.
//
// The component verifies that the outputs are a permutation of the inputs,
// by use of a Benes network.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BENES_ROUTING_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_BENES_ROUTING_COMPONENT_HPP

#include <nil/crypto3/zk/snark/integer_permutation.hpp>

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/blueprint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType>
                class benes_routing_component : public component<FieldType> {
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
                    std::vector<std::vector<blueprint_variable_vector<FieldType>>> routed_packets;
                    std::vector<multipacking_component<FieldType>> pack_inputs, unpack_outputs;

                    /*
                      If #packets = 1 then we can route without explicit routing bits
                      (and save half the constraints); in this case benes_switch_bits will
                      be unused.

                      For benes_switch_bits 0 corresponds to straight edge and 1
                      corresponds to cross edge.
                    */
                    std::vector<blueprint_variable_vector<FieldType>> benes_switch_bits;
                    benes_topology neighbors;

                public:
                    const std::size_t num_packets;
                    const std::size_t num_columns;

                    const std::vector<blueprint_variable_vector<FieldType>> routing_input_bits;
                    const std::vector<blueprint_variable_vector<FieldType>> routing_output_bits;
                    std::size_t lines_to_unpack;

                    const std::size_t packet_size, num_subpackets;

                    benes_routing_component(
                        blueprint<FieldType> &bp,
                        const std::size_t num_packets,
                        const std::vector<blueprint_variable_vector<FieldType>> &routing_input_bits,
                        const std::vector<blueprint_variable_vector<FieldType>> &routing_output_bits,
                        const std::size_t lines_to_unpack) :
                        component<FieldType>(bp),
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
                                routed_packets[column_idx][packet_idx].allocate(bp, num_subpackets);
                            }
                        }

                        pack_inputs.reserve(num_packets);
                        unpack_outputs.reserve(num_packets);

                        for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                            pack_inputs.emplace_back(multipacking_component<FieldType>(
                                bp,
                                blueprint_variable_vector<FieldType>(routing_input_bits[packet_idx].begin(),
                                                                     routing_input_bits[packet_idx].end()),
                                routed_packets[0][packet_idx],
                                FieldType::capacity()));
                            if (packet_idx < lines_to_unpack) {
                                unpack_outputs.emplace_back(multipacking_component<FieldType>(
                                    bp,
                                    blueprint_variable_vector<FieldType>(routing_output_bits[packet_idx].begin(),
                                                                         routing_output_bits[packet_idx].end()),
                                    routed_packets[num_columns][packet_idx],
                                    FieldType::capacity()));
                            }
                        }

                        if (num_subpackets > 1) {
                            benes_switch_bits.resize(num_columns);
                            for (std::size_t column_idx = 0; column_idx < num_columns; ++column_idx) {
                                benes_switch_bits[column_idx].allocate(bp, num_packets);
                            }
                        }
                    }

                    void generate_r1cs_constraints() {
                        /* packing/unpacking */
                        for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
                            pack_inputs[packet_idx].generate_r1cs_constraints(false);
                            if (packet_idx < lines_to_unpack) {
                                unpack_outputs[packet_idx].generate_r1cs_constraints(true);
                            } else {
                                for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                        1, routed_packets[0][packet_idx][subpacket_idx],
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
                                    this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                        routed_packets[column_idx][packet_idx][0] -
                                            routed_packets[column_idx + 1][straight_edge][0],
                                        routed_packets[column_idx][packet_idx][0] -
                                            routed_packets[column_idx + 1][cross_edge][0],
                                        0));
                                } else {
                                    /* routing bit must be boolean */
                                    generate_boolean_r1cs_constraint<FieldType>(
                                        this->bp, benes_switch_bits[column_idx][packet_idx]);

                                    /* route forward according to routing bits */
                                    for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets;
                                         ++subpacket_idx) {
                                        /*
                                          (1-switch_bit) * (cur-straight_edge) + switch_bit * (cur-cross_edge) = 0
                                          switch_bit * (cross_edge-straight_edge) = cur-straight_edge
                                        */
                                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
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

                    void generate_r1cs_witness(const integer_permutation &permutation) {
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
                                    this->bp.val(benes_switch_bits[column_idx][packet_idx]) =
                                        typename FieldType::value_type(routing[column_idx][packet_idx] ? 1 : 0);
                                }

                                for (std::size_t subpacket_idx = 0; subpacket_idx < num_subpackets; ++subpacket_idx) {
                                    this->bp.val(routing[column_idx][packet_idx] ?
                                                     routed_packets[column_idx + 1][cross_edge][subpacket_idx] :
                                                     routed_packets[column_idx + 1][straight_edge][subpacket_idx]) =
                                        this->bp.val(routed_packets[column_idx][packet_idx][subpacket_idx]);
                                }
                            }
                        }

                        /* unpack outputs */
                        for (std::size_t packet_idx = 0; packet_idx < lines_to_unpack; ++packet_idx) {
                            unpack_outputs[packet_idx].generate_r1cs_witness_from_packed();
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_BENES_ROUTING_COMPONENT_HPP
