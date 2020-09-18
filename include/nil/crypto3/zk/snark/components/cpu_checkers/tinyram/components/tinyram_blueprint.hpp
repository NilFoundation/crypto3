//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a protoboard for TinyRAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TINYRAM_PROTOBOARD_HPP_
#define CRYPTO3_ZK_TINYRAM_PROTOBOARD_HPP_

#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_aux.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class tinyram_blueprint : public blueprint<FieldType> {
                public:
                    const tinyram_architecture_params ap;

                    tinyram_blueprint(const tinyram_architecture_params &ap);
                };

                template<typename FieldType>
                class tinyram_component : public component<FieldType> {
                protected:
                    tinyram_blueprint<FieldType> &pb;

                public:
                    tinyram_component(tinyram_blueprint<FieldType> &pb);
                };

                // standard gadgets provide two methods: generate_r1cs_constraints and generate_r1cs_witness
                template<typename FieldType>
                class tinyram_standard_component : public tinyram_component<FieldType> {
                public:
                    tinyram_standard_component(tinyram_blueprint<FieldType> &pb);

                    virtual void generate_r1cs_constraints() = 0;
                    virtual void generate_r1cs_witness() = 0;
                };

                template<typename FieldType>
                tinyram_blueprint<FieldType>::tinyram_blueprint(const tinyram_architecture_params &ap) : ap(ap) {
                }

                template<typename FieldType>
                tinyram_component<FieldType>::tinyram_component(tinyram_protoboard<FieldType> &pb) :
                    component<FieldType>(pb), pb(pb) {
                }

                template<typename FieldType>
                tinyram_standard_component<FieldType>::tinyram_standard_component(tinyram_protoboard<FieldType> &pb) :
                    tinyram_component<FieldType>(pb) {
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TINYRAM_PROTOBOARD_HPP_
