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

#ifndef CRYPTO3_ZK_BLUEPRINT_NON_LINEAR_COMBINATION_HPP
#define CRYPTO3_ZK_BLUEPRINT_NON_LINEAR_COMBINATION_HPP

#include <vector>

#include <nil/crypto3/multiprecision/integer.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/zk/snark/relations/variable.hpp>
#include <nil/crypto3/zk/snark/relations/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization, typename TBlueprintField>
                class blueprint;

                template<typename TArithmetization, typename TBlueprintField>
                class blueprint_non_linear_combination;

                template<typename TBlueprintField>
                class blueprint_non_linear_combination<snark::plonk_constraint_system<TBlueprintField>, TBlueprintField> : 
                    public snark::non_linear_combination<TBlueprintField> {
                    typedef TBlueprintField field_type;
                    typedef typename field_type::value_type field_value_type;

                public:

                    using index_type = std::size_t;
                    bool is_variable;
                    index_type index;

                    blueprint_non_linear_combination() {
                        this->is_variable = false;
                    }

                    blueprint_non_linear_combination(const blueprint_variable<field_type> &var) {
                        this->is_variable = true;
                        this->index = var.index;
                        this->terms.emplace_back(snark::linear_term<field_type>(var));
                    }

                    // template<typename TArithmetization>
                    // void evaluate(std::size_t row_index, blueprint<TArithmetization, field_type> &bp) const {
                    //     if (this->is_variable) {
                    //         return;    // do nothing
                    //     }

                    //     field_value_type sum = 0;
                    //     for (auto term : this->terms) {
                    //         sum += term.coeff * bp.val(blueprint_variable<field_type>(term.index));
                    //     }

                    //     bp.lc_val(*this) = sum;
                    // }

                    bool is_constant() const {
                        if (is_variable) {
                            return (index == 0);
                        } else {
                            for (auto term : this->terms) {
                                if (term.vars.size() != 0) {
                                    return false;
                                }
                            }

                            return true;
                        }
                    }

                    field_value_type constant_term() const {
                        if (is_variable) {
                            return (index == 0 ? field_value_type::one() : field_value_type::zero());
                        } else {
                            field_value_type result = field_value_type::zero();
                            for (auto term : this->terms) {
                                if (term.index == 0) {
                                    result += term.coeff;
                                }
                            }
                            return result;
                        }
                    }
                };

                template<typename TBlueprintField>
                class blueprint_non_linear_combination_vector
                    : private std::vector<blueprint_non_linear_combination<TBlueprintField>> {

                    typedef TBlueprintField field_type;
                    typedef typename field_type::value_type field_value_type;
                    typedef std::vector<blueprint_non_linear_combination<field_type>> contents;

                public:
                    using typename contents::const_iterator;
                    using typename contents::const_reverse_iterator;
                    using typename contents::iterator;
                    using typename contents::reverse_iterator;

                    using contents::begin;
                    using contents::emplace_back;
                    using contents::empty;
                    using contents::end;
                    using contents::insert;
                    using contents::rbegin;
                    using contents::rend;
                    using contents::reserve;
                    using contents::size;
                    using contents::operator[];
                    using contents::resize;

                    blueprint_non_linear_combination_vector() : contents() {};
                    blueprint_non_linear_combination_vector(const blueprint_variable_vector<field_type> &arr) {
                        for (auto &v : arr)
                            this->emplace_back(blueprint_non_linear_combination<field_type>(v));
                    };
                    blueprint_non_linear_combination_vector(std::size_t count) : contents(count) {};
                    blueprint_non_linear_combination_vector(std::size_t count,
                                                        const blueprint_non_linear_combination<field_type> &value) :
                        contents(count, value) {};
                    blueprint_non_linear_combination_vector(typename contents::const_iterator first,
                                                        typename contents::const_iterator last) :
                        contents(first, last) {};
                    blueprint_non_linear_combination_vector(typename contents::const_reverse_iterator first,
                                                        typename contents::const_reverse_iterator last) :
                        contents(first, last) {};

                    template<typename TArithmetization>
                    void evaluate(blueprint<TArithmetization, field_type> &bp) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            (*this)[i].evaluate(bp);
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_NON_LINEAR_COMBINATION_HPP
