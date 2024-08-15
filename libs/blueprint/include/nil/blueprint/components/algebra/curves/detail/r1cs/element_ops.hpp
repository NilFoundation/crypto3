//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file Declaration of available operation components over curve group elements.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_ELEMENT_OPS_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_ELEMENT_OPS_COMPONENT_HPP

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {
                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1_is_well_formed { };

                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1_addition { };

                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1_conditional_addition { };

                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1_to_twisted_edwards { };

                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1_to_bits { };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_ELEMENT_OPS_COMPONENT_HPP
