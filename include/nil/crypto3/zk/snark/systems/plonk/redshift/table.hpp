//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP

#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, 
                         typename RedshiftParams>
                class redshift_table {

                    using variable_type = variable<FieldType, true>;
                    std::array<variable_type, RedshiftParams::witness_columns> witness_variables;
                    std::vector<variable_type> selector_variables;
                    // std::vector<variable_type> public_input_variables;

                public:

                    variable_type witness(std::size_t index) const{
                        assert(index < RedshiftParams::witness_columns);
                        return witness_variables[index];
                    }

                    variable_type& witness(std::size_t index){
                        assert(index < RedshiftParams::witness_columns);
                        return witness_variables[index];
                    }

                    variable_type selector(std::size_t index) const{
                        assert(index < selector_variables.size());
                        return selector_variables[index];
                    }

                    variable_type& selector(std::size_t index){
                        assert(index < selector_variables.size());
                        return selector_variables[index];
                    }

                    // variable_type public_input(std::size_t index) const{
                    //     assert(index < public_input_variables.size());
                    //     return public_input_variables[index];
                    // }

                    // variable_type& public_input(std::size_t index){
                    //     assert(index < public_input_variables.size());
                    //     return public_input_variables[index];
                    // }

                    variable_type operator[](std::size_t index) const{
                        if (index < RedshiftParams::witness_columns)
                            return witness_variables[index];
                        index -= RedshiftParams::witness_columns;
                        if (index < selector_variables.size())
                            return selector_variables[index];
                        index -= selector_variables.size();
                        // if (index < public_input_variables.size())
                        //     return public_input_variables[index];
                        // index -= public_input_variables.size();
                    }

                    variable_type& operator[](std::size_t index){
                        if (index < RedshiftParams::witness_columns)
                            return witness_variables[index];
                        index -= RedshiftParams::witness_columns;
                        if (index < selector_variables.size())
                            return selector_variables[index];
                        index -= selector_variables.size();
                        // if (index < public_input_variables.size())
                        //     return public_input_variables[index];
                        // index -= public_input_variables.size();
                    }

                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP
