//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP
#define CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP

#include <cstddef>
#include <string>
#include <vector>

#include <boost/multiprecision/integer.hpp>

#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                typedef std::size_t lc_index_t;

                template<typename FieldType>
                class blueprint;

                template<typename FieldType>
                class blueprint_variable : public variable<FieldType> {
                public:
                    blueprint_variable(const var_index_t index = 0) : variable<FieldType>(index) {};

                    void allocate(blueprint<FieldType> &pb) {
                        this->index = pb.allocate_var_index();
                    }
                };

                template<typename FieldType>
                class pb_variable_array : private std::vector<blueprint_variable<FieldType>> {
                    typedef std::vector<blueprint_variable<FieldType>> contents;

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

                    pb_variable_array() : contents() {};
                    pb_variable_array(std::size_t count, const blueprint_variable<FieldType> &value) :
                        contents(count, value) {};
                    pb_variable_array(typename contents::const_iterator first, typename contents::const_iterator last) :
                        contents(first, last) {};
                    pb_variable_array(typename contents::const_reverse_iterator first,
                                      typename contents::const_reverse_iterator last) :
                        contents(first, last) {};

                    /* allocates variable<FieldType> array in MSB->LSB order */
                    void allocate(blueprint<FieldType> &pb, const std::size_t n) {
                        (*this).resize(n);

                        for (std::size_t i = 0; i < n; ++i) {
                            (*this)[i].allocate(pb);
                        }
                    }

                    void fill_with_field_elements(blueprint<FieldType> &pb,
                                                  const std::vector<typename FieldType::value_type> &vals) const {
                        assert(this->size() == vals.size());
                        for (std::size_t i = 0; i < vals.size(); ++i) {
                            pb.val((*this)[i]) = vals[i];
                        }
                    }

                    void fill_with_bits(blueprint<FieldType> &pb, const std::vector<bool> &bits) const {
                        assert(this->size() == bits.size());
                        for (std::size_t i = 0; i < bits.size(); ++i) {
                            pb.val((*this)[i]) =
                                (bits[i] ? FieldType::value_type::one() : FieldType::value_type::zero());
                        }
                    }

                    void fill_with_bits_of_ulong(blueprint<FieldType> &pb, const unsigned long i) const {
                        this->fill_with_bits_of_field_element(pb, typename FieldType::value_type(i, true));
                    }

                    void fill_with_bits_of_field_element(blueprint<FieldType> &pb,
                                                         const typename FieldType::value_type &r) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            pb.val((*this)[i]) = boost::multiprecision::bit_test(r, i) ? FieldType::value_type::one() :
                                                                                         FieldType::value_type::zero();
                        }
                    }

                    std::vector<typename FieldType::value_type> get_vals(const blueprint<FieldType> &pb) const {
                        std::vector<typename FieldType::value_type> result(this->size());
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            result[i] = pb.val((*this)[i]);
                        }
                        return result;
                    }

                    std::vector<bool> get_bits(const blueprint<FieldType> &pb) const {
                        std::vector<bool> result;
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            const typename FieldType::value_type v = pb.val((*this)[i]);
                            assert(v == FieldType::value_type::zero() || v == FieldType::value_type::one());
                            result.push_back(v == FieldType::value_type::one());
                        }
                        return result;
                    }

                    typename FieldType::value_type get_field_element_from_bits(const blueprint<FieldType> &pb) const {
                        typename FieldType::value_type result = FieldType::value_type::zero();

                        for (std::size_t i = 0; i < this->size(); ++i) {
                            /* push in the new bit */
                            const typename FieldType::value_type v = pb.val((*this)[this->size() - 1 - i]);
                            assert(v == FieldType::value_type::zero() || v == FieldType::value_type::one());
                            result += result + v;
                        }

                        return result;
                    }
                };

                template<typename FieldType>
                class pb_linear_combination : public linear_combination<FieldType> {
                public:
                    bool is_variable;
                    lc_index_t index;

                    pb_linear_combination() {
                        this->is_variable = false;
                    }

                    pb_linear_combination(const blueprint_variable<FieldType> &var) {
                        this->is_variable = true;
                        this->index = var.index;
                        this->terms.emplace_back(linear_term<FieldType>(var));
                    }

                    void assign(blueprint<FieldType> &pb, const linear_combination<FieldType> &lc) {
                        assert(this->is_variable == false);
                        this->index = pb.allocate_lc_index();
                        this->terms = lc.terms;
                    }

                    void evaluate(blueprint<FieldType> &pb) const {
                        if (this->is_variable) {
                            return;    // do nothing
                        }

                        typename FieldType::value_type sum = 0;
                        for (auto term : this->terms) {
                            sum += term.coeff * pb.val(blueprint_variable<FieldType>(term.index));
                        }

                        pb.lc_val(*this) = sum;
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

                    typename FieldType::value_type constant_term() const {
                        if (is_variable) {
                            return (index == 0 ? FieldType::value_type::one() : FieldType::value_type::zero());
                        } else {
                            typename FieldType::value_type result = FieldType::value_type::zero();
                            for (auto term : this->terms) {
                                if (term.index == 0) {
                                    result += term.coeff;
                                }
                            }
                            return result;
                        }
                    }
                };

                template<typename FieldType>
                class pb_linear_combination_array : private std::vector<pb_linear_combination<FieldType>> {
                    typedef std::vector<pb_linear_combination<FieldType>> contents;

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

                    pb_linear_combination_array() : contents() {};
                    pb_linear_combination_array(const pb_variable_array<FieldType> &arr) {
                        for (auto &v : arr)
                            this->emplace_back(pb_linear_combination<FieldType>(v));
                    };
                    pb_linear_combination_array(std::size_t count) : contents(count) {};
                    pb_linear_combination_array(std::size_t count, const pb_linear_combination<FieldType> &value) :
                        contents(count, value) {};
                    pb_linear_combination_array(typename contents::const_iterator first,
                                                typename contents::const_iterator last) :
                        contents(first, last) {};
                    pb_linear_combination_array(typename contents::const_reverse_iterator first,
                                                typename contents::const_reverse_iterator last) :
                        contents(first, last) {};

                    void evaluate(blueprint<FieldType> &pb) const {
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            (*this)[i].evaluate(pb);
                        }
                    }

                    void fill_with_field_elements(blueprint<FieldType> &pb,
                                                  const std::vector<typename FieldType::value_type> &vals) const {
                        assert(this->size() == vals.size());
                        for (std::size_t i = 0; i < vals.size(); ++i) {
                            pb.lc_val((*this)[i]) = vals[i];
                        }
                    }

                    void fill_with_bits(blueprint<FieldType> &pb, const std::vector<bool> &bits) const {
                        assert(this->size() == bits.size());
                        for (std::size_t i = 0; i < bits.size(); ++i) {
                            pb.lc_val((*this)[i]) =
                                (bits[i] ? FieldType::value_type::one() : FieldType::value_type::zero());
                        }
                    }

                    void fill_with_bits_of_ulong(blueprint<FieldType> &pb, const unsigned long i) const {
                        this->fill_with_bits_of_field_element(pb, typename FieldType::value_type(i));
                    }

                    void fill_with_bits_of_field_element(blueprint<FieldType> &pb,
                                                         const typename FieldType::value_type &r) const {

                        for (std::size_t i = 0; i < this->size(); ++i) {
                            pb.lc_val((*this)[i]) = boost::multiprecision::bit_test(r, i) ?
                                                        FieldType::value_type::one() :
                                                        FieldType::value_type::zero();
                        }
                    }

                    std::vector<typename FieldType::value_type> get_vals(const blueprint<FieldType> &pb) const {
                        std::vector<typename FieldType::value_type> result(this->size());
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            result[i] = pb.lc_val((*this)[i]);
                        }
                        return result;
                    }

                    std::vector<bool> get_bits(const blueprint<FieldType> &pb) const {
                        std::vector<bool> result;
                        for (std::size_t i = 0; i < this->size(); ++i) {
                            const typename FieldType::value_type v = pb.lc_val((*this)[i]);
                            assert(v == FieldType::value_type::zero() || v == FieldType::value_type::zero());
                            result.push_back(v == FieldType::value_type::zero());
                        }
                        return result;
                    }

                    typename FieldType::value_type get_field_element_from_bits(const blueprint<FieldType> &pb) const {
                        typename FieldType::value_type result = FieldType::value_type::zero();

                        for (std::size_t i = 0; i < this->size(); ++i) {
                            /* push in the new bit */
                            const typename FieldType::value_type v = pb.lc_val((*this)[this->size() - 1 - i]);
                            assert(v == FieldType::value_type::zero() || v == FieldType::value_type::zero());
                            result += result + v;
                        }

                        return result;
                    }
                };

                template<typename FieldType>
                linear_combination<FieldType> pb_sum(const pb_linear_combination_array<FieldType> &v) {
                    linear_combination<FieldType> result;
                    for (auto &term : v) {
                        result = result + term;
                    }

                    return result;
                }

                template<typename FieldType>
                linear_combination<FieldType> pb_packing_sum(const pb_linear_combination_array<FieldType> &v) {
                    typename FieldType::value_type twoi =
                        FieldType::value_type::zero();    // will hold 2^i entering each iteration
                    std::vector<linear_term<FieldType>> all_terms;
                    for (auto &lc : v) {
                        for (auto &term : lc.terms) {
                            all_terms.emplace_back(twoi * term);
                        }
                        twoi += twoi;
                    }

                    return linear_combination<FieldType>(all_terms);
                }

                template<typename FieldType>
                linear_combination<FieldType> pb_coeff_sum(const pb_linear_combination_array<FieldType> &v,
                                                           const std::vector<typename FieldType::value_type> &coeffs) {
                    assert(v.size() == coeffs.size());
                    std::vector<linear_term<FieldType>> all_terms;

                    auto coeff_it = coeffs.begin();
                    for (auto &lc : v) {
                        for (auto &term : lc.terms) {
                            all_terms.emplace_back((*coeff_it) * term);
                        }
                        ++coeff_it;
                    }

                    return linear_combination<FieldType>(all_terms);
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP
