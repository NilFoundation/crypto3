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
// @file Declaration of interfaces for PLONK BBF choice_function component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP

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

            template<typename FieldType, GenerationStage stage, std::size_t num_chunks>
            class choice_function : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;

                public:
                    using typename generic_component<FieldType,stage>::TYPE;

                public:
                    TYPE q, x[num_chunks], y[num_chunks], z[num_chunks]; // interfaces

                    choice_function(context_type &context_object,
                                    TYPE input_q,
                                    std::array<TYPE,num_chunks> input_x,
                                    std::array<TYPE,num_chunks> input_y,
                                    bool make_links = true) :
                        generic_component<FieldType,stage>(context_object) {

                        TYPE Q, X[num_chunks], Y[num_chunks], Z[num_chunks];

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            Q = input_q;
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                X[i] = input_x[i];
                                Y[i] = input_y[i];
                            }
                        }

                        allocate(Q);
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            allocate(X[i]);
                        }
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            allocate(Y[i]);
                        }

                        if (make_links) {
                            copy_constrain(Q,input_q);
                            for(std::size_t i = 0; i < num_chunks; i++) {
                                copy_constrain(X[i],input_x[i]);
                                copy_constrain(Y[i],input_y[i]);
                            }
                        }

                        constrain(Q*(1-Q));
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            Z[i] = (1-Q)*X[i] + Q*Y[i];
                            allocate(Z[i]);
                        }

                        q = Q;
                        for(std::size_t i = 0; i < num_chunks; i++) {
                            x[i] = X[i];
                            y[i] = Y[i];
                            z[i] = Z[i];
                        }
                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_CHOICE_FUNCTION_COMPONENT_HPP
