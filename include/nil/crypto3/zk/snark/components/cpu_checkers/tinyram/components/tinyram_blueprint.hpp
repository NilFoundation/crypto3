//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for a protoboard for TinyRAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TINYRAM_BLUEPRINT_HPP
#define CRYPTO3_ZK_TINYRAM_BLUEPRINT_HPP

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

                // standard components provide two methods: generate_r1cs_constraints and generate_r1cs_witness
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
                tinyram_component<FieldType>::tinyram_component(tinyram_blueprint<FieldType> &pb) :
                    component<FieldType>(pb), pb(pb) {
                }

                template<typename FieldType>
                tinyram_standard_component<FieldType>::tinyram_standard_component(tinyram_blueprint<FieldType> &pb) :
                    tinyram_component<FieldType>(pb) {
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TINYRAM_BLUEPRINT_HPP
