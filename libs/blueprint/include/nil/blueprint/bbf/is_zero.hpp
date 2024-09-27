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
// @file Declaration of interfaces for PLONK BBF is_zero component class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_IS_ZERO_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_IS_ZERO_COMPONENT_HPP

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

            template<typename FieldType, GenerationStage stage>
            class is_zero : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;

                public:
                    using typename generic_component<FieldType,stage>::TYPE;

                public:
                    TYPE input;
                    TYPE res;

                    is_zero(context_type &context_object, TYPE input_x, bool make_links = true) :
                        generic_component<FieldType,stage>(context_object) {

                        TYPE X, I, R;

                        if constexpr (stage == GenerationStage::ASSIGNMENT) {
                            X = input_x;
                            I = (X == 0) ? 0 : X.inversed();
                        }

                        allocate(X,0,0);
                        allocate(I,0,2);

                        if (make_links) {
                            copy_constrain(X,input_x);
                        }

                        R = 1 - X*I;
                        allocate(R,0,1);

                        constrain(X*R);

                        input = X;
                        res = R;
                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_IS_ZERO_COMPONENT_HPP
