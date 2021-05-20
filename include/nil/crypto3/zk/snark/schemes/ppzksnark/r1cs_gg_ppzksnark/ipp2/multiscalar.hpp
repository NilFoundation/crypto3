//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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
#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_MULTISCALAR_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_MULTISCALAR_HPP

#include <vector>
#include <type_traits>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename GroupType>
                struct multiscalar_precomp_owned {
                    typedef GroupType group_type;
                    typedef typename group_type::value_type group_value_type;

                    std::size_t num_points;
                    std::size_t window_size;
                    std::size_t window_mask;
                    std::size_t table_entries;
                    std::vector<std::vector<group_value_type>> tables;

                    static constexpr const std::size_t WINDOW_SIZE = 8;
                };

                template<typename GroupType, typename InputGIterator,
                         typename ValueType = typename std::iterator_traits<InputGIterator>::value_type,
                         typename std::enable_if<std::is_same<typename GroupType::value_type, ValueType>::value,
                                                 bool>::type = true>
                multiscalar_precomp_owned<GroupType> precompute_fixed_window(InputGIterator points_first, InputGIterator points_last, std::size_t window_size) {
                    multiscalar_precomp_owned<GroupType> result;
                    result.num_points = std::distance(points_first, points_last);
                    result.window_size = window_size;
                    result.window_mask = (1 << window_size) - 1;
                    result.table_entries = result.window_mask;

                    // TODO: parallel
                    for (auto points_iter = points_first; points_iter != points_last; points_iter++) {
                        std::vector<typename multiscalar_precomp_owned<GroupType>::group_value_type> table;
                        table.emplace_back(*points_iter);

                        typename multiscalar_precomp_owned<GroupType>::group_value_type cur_precomp_point = *points_iter;
                        for (auto i = 1; i < result.table_entries; i++) {
                            cur_precomp_point = cur_precomp_point + *points_iter;
                            table.emplace_back(cur_precomp_point);
                        }
                        result.tables.emplace_back(table);
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_MULTISCALAR_HPP
