//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Noam Yemini <@NoamDev at GitHub>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_LINEAR_COMBINATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_LINEAR_COMBINATION_HPP

#include <vector>

#include <boost/multiprecision/integer.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/zk/math/linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint;

            namespace detail {

                template<typename ArithmetizationType>
                class blueprint_linear_combination;

                template<typename BlueprintFieldType>
                class blueprint_linear_combination<crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>>
                    : public math::linear_combination<BlueprintFieldType> {

                    typedef zk::snark::r1cs_constraint_system<BlueprintFieldType> ArithmetizationType;
                    typedef BlueprintFieldType field_type;
                    typedef typename field_type::value_type field_value_type;

                public:
                    using index_type = std::size_t;
                    bool is_variable;
                    index_type index;

                    blueprint_linear_combination() {
                        this->is_variable = false;
                    }

                    blueprint_linear_combination(const blueprint_variable<ArithmetizationType> &var) {
                        this->is_variable = true;
                        this->index = var.index;
                        this->terms.emplace_back(math::linear_term<field_type>(var));
                    }

                    void assign(blueprint<ArithmetizationType> &bp, const math::linear_combination<field_type> &lc) {
                        assert(this->is_variable == false);
                        this->index = bp.allocate_lc_index();
                        this->terms = lc.terms;
                    }

                    void evaluate(blueprint<ArithmetizationType> &bp) const {
                        if (this->is_variable) {
                            return;    // do nothing
                        }

                        field_value_type sum = 0;
                        for (auto term : this->terms) {
                            sum += term.coeff * bp.val(blueprint_variable<ArithmetizationType>(term.index));
                        }

                        bp.lc_val(*this) = sum;
                    }

                    bool is_constant() const {
                        if (is_variable) {
                            return (index == 0);
                        } else {
                            for (auto term : this->terms) {
                                if (term.index != 0) {
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

                template<typename TArithmetizatio>
                class blueprint_linear_combination_vector;

                template<typename BlueprintFieldType>
                class blueprint_linear_combination_vector<
                    crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>>
                    : private std::vector<blueprint_linear_combination<
                          crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>>> {

                    typedef zk::snark::r1cs_constraint_system<BlueprintFieldType> ArithmetizationType;
                    typedef typename BlueprintFieldType::value_type field_value_type;
                    typedef std::vector<blueprint_linear_combination<ArithmetizationType>> contents;

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

                    blueprint_linear_combination_vector() : contents() {};
                    blueprint_linear_combination_vector(const blueprint_variable_vector<ArithmetizationType> &arr) {
                        for (auto &v : arr)
                            this->emplace_back(blueprint_linear_combination<ArithmetizationType>(v));
                    };
                    blueprint_linear_combination_vector(std::size_t count) : contents(count) {};
                    blueprint_linear_combination_vector(
                        std::size_t count,
                        const blueprint_linear_combination<ArithmetizationType> &value) :
                        contents(count, value) {};
                    blueprint_linear_combination_vector(typename contents::const_iterator first,
                                                        typename contents::const_iterator last) :
                        contents(first, last) {};
                    blueprint_linear_combination_vector(typename contents::const_reverse_iterator first,
                                                        typename contents::const_reverse_iterator last) :
                        contents(first, last) {};

                    void evaluate(blueprint<ArithmetizationType> &bp) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            (*this)[i].evaluate(bp);
                        }
                    }

                    void fill_with_field_elements(blueprint<ArithmetizationType> &bp,
                                                  const std::vector<field_value_type> &vals) const {
                        assert(this->size() == vals.size());
                        for (std::size_t i = 0; i < vals.size(); ++i) {
                            bp.lc_val((*this)[i]) = vals[i];
                        }
                    }

                    void fill_with_bits(blueprint<ArithmetizationType> &bp, const std::vector<bool> &bits) const {
                        assert(this->size() == bits.size());
                        for (std::size_t i = 0; i < bits.size(); ++i) {
                            bp.lc_val((*this)[i]) = (bits[i] ? field_value_type::one() : field_value_type::zero());
                        }
                    }

                    void fill_with_bits_of_ulong(blueprint<ArithmetizationType> &bp, const unsigned long i) const {
                        this->fill_with_bits_of_field_element(bp, field_value_type(i));
                    }

                    void fill_with_bits_of_field_element(blueprint<ArithmetizationType> &bp,
                                                         const field_value_type &r) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            bp.lc_val((*this)[i]) = boost::multiprecision::bit_test(r.data, i) ? field_value_type::one() :
                                                                                          field_value_type::zero();
                        }
                    }

                    std::vector<field_value_type> get_vals(const blueprint<ArithmetizationType> &bp) const {
                        std::vector<field_value_type> result(this->size());
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            result[i] = bp.lc_val((*this)[i]);
                        }
                        return result;
                    }

                    std::vector<bool> get_bits(const blueprint<ArithmetizationType> &bp) const {
                        std::vector<bool> result;
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            const field_value_type v = bp.lc_val((*this)[i]);
                            assert(v.is_zero() || v.is_one());
                            result.push_back(v.is_one());
                        }
                        return result;
                    }

                    field_value_type get_field_element_from_bits(const blueprint<ArithmetizationType> &bp) const {
                        field_value_type result = field_value_type::zero();

                        for (std::size_t i = 0; i < this->size(); ++i) {
                            /* push in the new bit */
                            const field_value_type v = bp.lc_val((*this)[this->size() - 1 - i]);
                            assert(v.is_zero() || v.is_one());
                            result += result + v;
                        }

                        return result;
                    }
                };

                template<typename ArithmetizationType, typename FieldType>
                math::linear_combination<FieldType>
                    blueprint_sum(const blueprint_linear_combination_vector<ArithmetizationType> &v) {

                    math::linear_combination<FieldType> result;
                    for (auto &term : v) {
                        result = result + term;
                    }

                    return result;
                }

                template<typename ArithmetizationType, typename FieldType>
                math::linear_combination<FieldType>
                    blueprint_packing_sum(const blueprint_linear_combination_vector<ArithmetizationType> &v) {

                    typename FieldType::value_type twoi =
                        FieldType::value_type::one();    // will hold 2^i entering each iteration
                    std::vector<math::linear_term<FieldType>> all_terms;
                    for (auto &lc : v) {
                        for (auto &term : lc.terms) {
                            all_terms.emplace_back(twoi * term);
                        }
                        twoi += twoi;
                    }

                    return math::linear_combination<FieldType>(all_terms);
                }

                template<typename ArithmetizationType, typename FieldType>
                math::linear_combination<FieldType>
                    blueprint_coeff_sum(const blueprint_linear_combination_vector<ArithmetizationType> &v,
                                        const std::vector<typename FieldType::value_type> &coeffs) {

                    assert(v.size() == coeffs.size());
                    std::vector<math::linear_term<FieldType>> all_terms;

                    auto coeff_it = coeffs.begin();
                    for (auto &lc : v) {
                        for (auto &term : lc.terms) {
                            all_terms.emplace_back((*coeff_it) * term);
                        }
                        ++coeff_it;
                    }

                    return math::linear_combination<FieldType>(all_terms);
                }
            }    // namespace detail
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_LINEAR_COMBINATION_HPP
