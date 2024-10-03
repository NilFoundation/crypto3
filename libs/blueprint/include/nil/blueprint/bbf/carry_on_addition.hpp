//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for PLONK BBF carry_on_addition component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CARRY_ON_ADDITION_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CARRY_ON_ADDITION_COMPONENT_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, GenerationStage stage, std::size_t num_chunks, std::size_t bit_size_chunk>
            class carry_on_addition : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;

                public:
                    using typename generic_component<FieldType,stage>::TYPE;

                public:
                    TYPE x[num_chunks], y[num_chunks], z[num_chunks], ck; // interfaces

                    carry_on_addition(context_type &context_object,
                                    std::array<TYPE,num_chunks> input_x,
                                    std::array<TYPE,num_chunks> input_y,
                                    bool make_links = true) :
                        generic_component<FieldType,stage>(context_object) {

                        using integral_type = typename FieldType::integral_type;
                        using value_type = typename FieldType::value_type;

                        TYPE X[num_chunks], Y[num_chunks], C[num_chunks], Z[num_chunks];
                        value_type BASE = integral_type(1) << bit_size_chunk;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = input_x[i];
                                Y[i] = input_y[i];
                            }
                        }

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            allocate(X[i]);
                            allocate(Y[i]);
                        }

                        if (make_links) {
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(X[i],input_x[i]);
                                copy_constrain(Y[i],input_y[i]);
                            }
                        }

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            Z[i] = X[i] + Y[i];
                            if (i > 0) {
                                Z[i] += C[i-1];
                            }
                            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                                C[i] = (Z[i] >= BASE);
                            }
                            allocate(C[i]);
                            constrain(C[i]*(1-C[i]));

                            Z[i] -= BASE*C[i];
                            allocate(Z[i]);
                        }

                        /*
                        // Alternative code: ``old-style''
                        //
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                                Z[i] = X[i] + Y[i];
                                if (i > 0) {
                                    Z[i] += C[i-1];
                                }
                                C[i] = (Z[i] >= BASE);
                                Z[i] -= BASE*C[i];
                            }
                            allocate(C[i]);
                            allocate(Z[i]);

                            constrain(C[i]*(1-C[i]));
                            TYPE R = X[i] + Y[i] - Z[i] - BASE*C[i];
                            if (i > 0) {
                                R += C[i-1];
                            }
                            constrain(R);
                        }
                        */

                        // optional part, not from the original component:
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            lookup(Z[i],"chunk_16_bits/full");
                        }

                        for(std::size_t i = 0; i < num_chunks; i++) {
                            x[i] = X[i];
                            y[i] = Y[i];
                            z[i] = Z[i];
                        }
                        ck = C[num_chunks - 1];
                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_CARRY_ON_ADDITIION_COMPONENT_HPP
