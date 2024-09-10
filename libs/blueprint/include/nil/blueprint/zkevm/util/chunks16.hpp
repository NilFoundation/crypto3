//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // chunks are not range checked here.
            template <typename BlueprintFieldType>
            crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
            chunk16_composition(
                const std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &chunks,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &acc
            ){
                std::cout << "Chunk 16 composition" << chunks.size() << std::endl;
                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> constr;
                constr = chunks[0];
                for( std::size_t i = 1; i < chunks.size(); i++){
                    std::cout << i << std::endl;
                    constr *= (1 << 16);
                    constr += chunks[i];
                    std::cout << "done" << std::endl;
                }
                constr -= acc;
                return constr;
            }
        }
    }
}