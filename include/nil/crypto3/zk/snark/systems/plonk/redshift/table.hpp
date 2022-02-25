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

                using plonk_column = std::vector<typename FieldType::value_type>;

                template<typename FieldType, 
                         typename RedshiftParams>
                class plonk_private_table {

                    std::array<plonk_column, RedshiftParams::witness_columns> witness_columns;

                public:

                    plonk_column witness(std::size_t index) const{
                        assert(index < RedshiftParams::witness_columns);
                        return witness_columns[index];
                    }

                    plonk_column operator[](std::size_t index) const{
                        if (index < RedshiftParams::witness_columns)
                            return witness_columns[index];
                        index -= RedshiftParams::witness_columns;
                    }

                    std::size_t size() const{
                        return witness_columns.size();
                    }
                };

                template<typename FieldType, 
                         typename RedshiftParams>
                class plonk_public_table {

                    std::vector<plonk_column> selector_columns;
                    // std::vector<plonk_column> public_input_columns;

                public:

                    plonk_column selector(std::size_t index) const{
                        assert(index < selector_columns.size());
                        return selector_columns[index];
                    }

                    plonk_column public_input(std::size_t index) const{
                        assert(index < public_input_columns.size());
                        return public_input_columns[index];
                    }

                    plonk_column operator[](std::size_t index) const{
                        if (index < selector_columns.size())
                            return selector_columns[index];
                        index -= selector_columns.size();
                        // if (index < public_input_columns.size())
                        //     return public_input_columns[index];
                        // index -= public_input_columns.size();
                    }

                    std::size_t size() const{
                        return selector_columns.size() + public_input_columns.size();
                    }
                };

                template<typename FieldType, 
                         typename RedshiftParams>
                class plonk_table {

                    plonk_private_table<FieldType, RedshiftParams> private_table;
                    plonk_public_table<FieldType, RedshiftParams> public_table;

                public:

                    plonk_table(plonk_private_table<FieldType, RedshiftParams> private_table, 
                        plonk_public_table<FieldType, RedshiftParams> public_table): 
                        private_table(private_table), public_table(public_table){
                    }

                    plonk_column witness(std::size_t index) const{
                        return private_table.witness(index);
                    }

                    plonk_column selector(std::size_t index) const{
                        return public_table.selector(index);
                    }

                    plonk_column public_input(std::size_t index) const{
                        return public_table.public_input(index);
                    }

                    plonk_column operator[](std::size_t index) const{
                        if (index < private_table.size())
                            return private_table[index];
                        index -= private_table.size();
                        if (index < public_table.size())
                            return public_table[index];
                    }

                    plonk_private_table<FieldType, RedshiftParams> private_table() const{
                        return private_table;
                    }

                    plonk_public_table<FieldType, RedshiftParams> public_table() const{
                        return public_table;
                    }

                    std::size_t size() const{
                        return private_table.size() + public_table.size();
                    }

                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_TABLE_HPP
