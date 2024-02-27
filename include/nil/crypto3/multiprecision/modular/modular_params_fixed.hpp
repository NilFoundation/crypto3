//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP

#include <nil/crypto3/multiprecision/modular/modular_functions_fixed.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            using backends::modular_fixed_cpp_int_backend;
            using default_ops::eval_bit_test;

            // fixed precision modular params type which supports compile-time execution
            template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
            class modular_params<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>> {
            protected:
                typedef modular_fixed_cpp_int_backend<MinBits, SignType, Checked> Backend;
                typedef backends::modular_functions_fixed<Backend> modular_logic;

            public:
                typedef typename modular_logic::policy_type policy_type;

            protected:
                typedef typename policy_type::internal_limb_type internal_limb_type;
                typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::number_type_u number_type_u;

                constexpr auto &get_mod_obj() {
                    return m_mod_obj;
                }
                constexpr const auto &get_mod_obj() const {
                    return m_mod_obj;
                }

                constexpr auto &get_is_odd_mod() {
                    return is_odd_mod;
                }
                constexpr const auto &get_is_odd_mod() const {
                    return is_odd_mod;
                }

            public:
                constexpr auto get_mod() const {
                    return m_mod_obj.get_mod();
                }

                // TODO: add universal ref constructor
                constexpr modular_params() {
                }

                constexpr modular_params(const number_type_u &m) : m_mod_obj(m) {
                    is_odd_mod = eval_bit_test(m.backend(), 0);
                }

                constexpr modular_params(const number_type &m) : m_mod_obj(m) {
                    is_odd_mod = eval_bit_test(m.backend(), 0);
                }

                constexpr modular_params(const modular_params &o) : m_mod_obj(o.get_mod_obj()) {
                    is_odd_mod = o.get_is_odd_mod();
                }

                template<typename Backend1>
                constexpr void reduce(Backend1 &result) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_reduce(result);
                    } else {
                        m_mod_obj.barrett_reduce(result);
                    }
                }

                template<typename Backend1>
                constexpr typename boost::enable_if_c<boost::is_same<Backend1, Backend>::value>::type
                    adjust_modular(Backend1 &result) const {
                    adjust_modular(result, result);
                }

                template<typename Backend1, typename Backend2>
                constexpr typename boost::enable_if_c<boost::is_same<Backend1, Backend>::value>::type
                    adjust_modular(Backend1 &result, Backend2 input) const {
                    Backend_doubled_limbs tmp;
                    m_mod_obj.barrett_reduce(tmp, input);
                    if (is_odd_mod) {
                        //
                        // to prevent problems with trivial cpp_int
                        //
                        Backend_doubled_limbs r2(m_mod_obj.get_r2());

                        eval_multiply(tmp, r2);
                        m_mod_obj.montgomery_reduce(tmp);
                    }
                    result = tmp;
                }

                template<
                    typename Backend1, typename Backend2,
                    typename = typename boost::enable_if_c<
                        /// input number should fit in result
                        backends::max_precision<Backend1>::value >= backends::max_precision<Backend2>::value>::type>
                constexpr void adjust_regular(Backend1 &result, const Backend2 &input) const {
                    result = input;
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_reduce(result);
                    }
                }

                template<typename Backend1, typename T>
                constexpr void mod_exp(Backend1 &result, const T &exp) const {
                    mod_exp(result, result, exp);
                }

                template<typename Backend1, typename Backend2, typename T>
                constexpr void mod_exp(Backend1 &result, const Backend2 &a, const T &exp) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_exp(result, a, exp);
                    } else {
                        m_mod_obj.regular_exp(result, a, exp);
                    }
                }

                template<typename Backend1, typename Backend2>
                constexpr void mod_mul(Backend1 &result, const Backend2 &y) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_mul(result, y);
                    } else {
                        m_mod_obj.regular_mul(result, y);
                    }
                }

                template<typename Backend1, typename Backend2>
                constexpr void mod_add(Backend1 &result, const Backend2 &y) const {
                    m_mod_obj.regular_add(result, y);
                }

                template<typename Backend1, expression_template_option ExpressionTemplates>
                constexpr operator number<Backend1, ExpressionTemplates>() {
                    return get_mod();
                };

                constexpr int compare(const modular_params &o) const {
                    // They are either equal or not:
                    return get_mod().compare(o.get_mod());
                }

                constexpr void swap(modular_params &o) {
                    m_mod_obj.swap(o.get_mod_obj());
                    bool t = is_odd_mod;
                    is_odd_mod = o.get_is_odd_mod();
                    o.get_is_odd_mod() = t;
                }

                constexpr modular_params &operator=(const modular_params &o) {
                    m_mod_obj = o.get_mod_obj();
                    is_odd_mod = o.get_is_odd_mod();
                    return *this;
                }

                constexpr modular_params &operator=(const number_type &m) {
                    m_mod_obj = m;
                    is_odd_mod = eval_bit_test(m.backend(), 0);
                    return *this;
                }

                // TODO: check function correctness
                constexpr friend std::ostream &operator<<(std::ostream &o, const modular_params &a) {
                    o << a.get_mod();
                    return o;
                }

            protected:
                modular_logic m_mod_obj;
                bool is_odd_mod = false;
            };

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
