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
// @file Declaration of public parameters for FOORAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_FOORAM_PARAMS_HPP_
#define CRYPTO3_ZK_FOORAM_PARAMS_HPP_

#include <nil/crypto3/zk/snark/components/cpu_checkers/fooram/fooram_cpu_checker.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/fooram/fooram_aux.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class ram_fooram {
                public:
                    typedef FieldType base_field_type;
                    typedef fooram_blueprint<FieldType> protoboard_type;
                    typedef fooram_component<FieldType> component_base_type;
                    typedef fooram_cpu_checker<FieldType> cpu_checker_type;
                    typedef fooram_architecture_params architecture_params_type;

                    static std::size_t timestamp_length;
                };

                template<typename FieldType>
                std::size_t ram_fooram<FieldType>::timestamp_length = 300;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // FOORAM_PARAMS_HPP_
