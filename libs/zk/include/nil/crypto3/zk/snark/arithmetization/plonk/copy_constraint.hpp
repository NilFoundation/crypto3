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

#ifndef CRYPTO3_ZK_PLONK_COPY_CONSTRAINT_HPP
#define CRYPTO3_ZK_PLONK_COPY_CONSTRAINT_HPP

#include <utility>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                struct plonk_copy_constraint {
                    plonk_copy_constraint() = default;
                    plonk_copy_constraint(const plonk_copy_constraint<FieldType> &other){
                        initialize(other.first, other.second);
                    }
                    plonk_copy_constraint(
                        const plonk_variable<typename FieldType::value_type> &_first,
                        const plonk_variable<typename FieldType::value_type> &_second
                    ){
                        initialize(_first, _second);
                    }
                    plonk_variable<typename FieldType::value_type> first;
                    plonk_variable<typename FieldType::value_type> second;
                protected:
                    void initialize(
                        const plonk_variable<typename FieldType::value_type> &_first,
                        const plonk_variable<typename FieldType::value_type> &_second
                    ){
                        BOOST_ASSERT(_first.relative == false);
                        BOOST_ASSERT(_second.relative == false);
                        first = _first;
                        second = _second;

                        if (_first > _second) {
                            std::swap(first, second);
                        }
                   }
                };

                template <typename FieldType>
                bool operator==(const plonk_copy_constraint<FieldType> &a, const plonk_copy_constraint<FieldType> &b) {
                    return a.first == b.first && a.second == b.second;
                }

                template <typename FieldType>
                bool operator!=(const plonk_copy_constraint<FieldType> &a, const plonk_copy_constraint<FieldType> &b) {
                    return !(a == b);
                }

                template <typename FieldType>
                bool operator<(const plonk_copy_constraint<FieldType> &a, const plonk_copy_constraint<FieldType> &b) {
                    return a.first < b.first || (a.first == b.first && a.second < b.second);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_COPY_CONSTRAINT_HPP
