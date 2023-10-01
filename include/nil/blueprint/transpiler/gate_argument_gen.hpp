//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of PLONK table profiling util.
//---------------------------------------------------------------------------//

#ifndef __GATE_ARGUMENT_GEN_HPP__
#define __GATE_ARGUMENT_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp> 
#include <nil/blueprint/transpiler/templates/modular_verifier.hpp>
#include <nil/blueprint/transpiler/templates/gate_argument.hpp>
#include <nil/blueprint/transpiler/templates/permutation_argument.hpp>
#include <nil/blueprint/transpiler/templates/lookup_argument.hpp>
#include <nil/blueprint/transpiler/templates/commitment_scheme.hpp>
#include <nil/blueprint/transpiler/lpc_scheme_gen.hpp>
#include <nil/blueprint/transpiler/util.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams> 
        std::string print_gate_argument(
            const typename PlaceholderParams::constraint_system_type &constraint_system,
            const common_data_type<PlaceholderParams> &common_data,
            std::size_t permutation_size,
            std::string folder_name
        ){
        }
    }
}

#endif //__GATE_ARGUMENT_GEN_HPP__