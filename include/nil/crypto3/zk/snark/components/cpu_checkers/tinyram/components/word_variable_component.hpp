//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for (single and double) word components.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_WORD_VARIABLE_GADGET_HPP
#define CRYPTO3_ZK_WORD_VARIABLE_GADGET_HPP

#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/tinyram_blueprint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Holds both binary and field representaton of a word.
                 */
                template<typename FieldType>
                class word_variable_component : public dual_variable_component<FieldType> {
                public:
                    word_variable_component(tinyram_blueprint<FieldType> &pb) :
                        dual_variable_component<FieldType>(pb, pb.ap.w) {
                    }
                    word_variable_component(tinyram_blueprint<FieldType> &pb, const pb_variable_array<FieldType> &bits) :
                        dual_variable_component<FieldType>(pb, bits) {
                    }
                    word_variable_component(tinyram_blueprint<FieldType> &pb, const blueprint_variable<FieldType> &packed) :
                        dual_variable_component<FieldType>(pb, packed, pb.ap.w) {
                    }
                };

                /**
                 * Holds both binary and field representaton of a double word.
                 */
                template<typename FieldType>
                class doubleword_variable_component : public dual_variable_component<FieldType> {
                public:
                    doubleword_variable_component(tinyram_blueprint<FieldType> &pb) :
                        dual_variable_component<FieldType>(pb, 2 * pb.ap.w) {
                    }
                    doubleword_variable_component(tinyram_blueprint<FieldType> &pb,
                                               const pb_variable_array<FieldType> &bits) :
                        dual_variable_component<FieldType>(pb, bits) {
                    }
                    doubleword_variable_component(tinyram_blueprint<FieldType> &pb,
                                               const blueprint_variable<FieldType> &packed) :
                        dual_variable_component<FieldType>(pb, packed, 2 * pb.ap.w) {
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_WORD_VARIABLE_GADGET_HPP
