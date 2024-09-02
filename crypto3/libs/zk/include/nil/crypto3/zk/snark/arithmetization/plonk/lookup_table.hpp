//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_LOOKUP_TABLE_HPP
#define CRYPTO3_ZK_PLONK_LOOKUP_TABLE_HPP

#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <boost/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                struct plonk_lookup_table {
                    typedef FieldType field_type;
                    typedef plonk_variable<typename FieldType::value_type> variable_type;
                    using lookup_options_type = std::vector<std::vector<variable_type>>;

                    std::size_t columns_number;
                    std::size_t tag_index;
                    lookup_options_type lookup_options;

                    bool operator==(const plonk_lookup_table<FieldType> &other) const {
                        return (tag_index == other.tag_index) && (columns_number == other.columns_number) &&
                               (lookup_options == other.lookup_options);
                    }

                    plonk_lookup_table() : columns_number(0), tag_index(0) {
                    }

                    plonk_lookup_table(std::size_t _columns_number, std::size_t _tag_index) :
                        columns_number(_columns_number), tag_index(_tag_index) {
                    }

                    void append_option(const std::vector<variable_type> &variables){
                        BOOST_ASSERT(variables.size() == columns_number);
                        lookup_options.push_back(variables);
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_GATE_HPP
