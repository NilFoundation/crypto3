//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a protoboard for TinyRAM.
//---------------------------------------------------------------------------//

#ifndef TINYRAM_PROTOBOARD_HPP_
#define TINYRAM_PROTOBOARD_HPP_

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/protoboard.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_aux.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class tinyram_protoboard : public protoboard<FieldType> {
                public:
                    const tinyram_architecture_params ap;

                    tinyram_protoboard(const tinyram_architecture_params &ap);
                };

                template<typename FieldType>
                class tinyram_gadget : public gadget<FieldType> {
                protected:
                    tinyram_protoboard<FieldType> &pb;

                public:
                    tinyram_gadget(tinyram_protoboard<FieldType> &pb);
                };

                // standard gadgets provide two methods: generate_r1cs_constraints and generate_r1cs_witness
                template<typename FieldType>
                class tinyram_standard_gadget : public tinyram_gadget<FieldType> {
                public:
                    tinyram_standard_gadget(tinyram_protoboard<FieldType> &pb);

                    virtual void generate_r1cs_constraints() = 0;
                    virtual void generate_r1cs_witness() = 0;
                };

                template<typename FieldType>
                tinyram_protoboard<FieldType>::tinyram_protoboard(const tinyram_architecture_params &ap) : ap(ap) {
                }

                template<typename FieldType>
                tinyram_gadget<FieldType>::tinyram_gadget(tinyram_protoboard<FieldType> &pb) :
                    gadget<FieldType>(pb), pb(pb) {
                }

                template<typename FieldType>
                tinyram_standard_gadget<FieldType>::tinyram_standard_gadget(tinyram_protoboard<FieldType> &pb) :
                    tinyram_gadget<FieldType>(pb) {
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TINYRAM_PROTOBOARD_HPP_
