//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_INCOMPLETE_ADDITION_CHIP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_INCOMPLETE_ADDITION_CHIP_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace chips {

                template<typename ArithmetizationType,
                         typename CurveType>
                class incomplete_addition;

                template<typename BlueprintFieldType,

                         typename CurveType>
                class incomplete_addition<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;
                public:
                    constexpr static const std::size_t rows_amount = 0;

                    static snark::plonk_constraint<BlueprintFieldType> generate(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const var& X1, const var& Y1, const var& X2, const var& Y2,
                        const var& X3, const var& Y3) {

                        return bp.add_constraint();
                    }
                };
            }    // namespace chips
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_INCOMPLETE_ADDITION_CHIP_HPP
