//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

                constexpr auto& get_mod_obj() {
                    return m_mod_obj;
                }
                constexpr const auto& get_mod_obj() const {
                    return m_mod_obj;
                }

            public:
                constexpr auto get_mod() const {
                    return get_mod_obj().get_mod();
                }

                // TODO: add universal ref constructor
                constexpr modular_params() {
                }

                constexpr modular_params(const number_type& m) : m_mod_obj(m) {
                }

                constexpr modular_params(const modular_params& o) : m_mod_obj(o.get_mod_obj()) {
                }

                template<typename Backend1>
                constexpr void reduce(Backend1& result) const {
                    if (check_montgomery_constraints(get_mod_obj())) {
                        get_mod_obj().montgomery_reduce(result);
                    } else {
                        get_mod_obj().barrett_reduce(result);
                    }
                }

                template<typename Backend1>
                constexpr typename boost::enable_if_c<boost::is_same<Backend1, Backend>::value>::type
                    adjust_modular(Backend1& result) {
                    adjust_modular(result, result);
                }

                template<typename Backend1, typename Backend2>
                constexpr typename boost::enable_if_c<boost::is_same<Backend1, Backend>::value>::type
                    adjust_modular(Backend1& result, Backend2 input) {
                    Backend_doubled_limbs tmp;
                    get_mod_obj().barrett_reduce(tmp, input);
                    if (check_montgomery_constraints(get_mod_obj())) {
                        //
                        // to prevent problems with trivial cpp_int
                        //
                        Backend_doubled_limbs r2(get_mod_obj().get_r2());

                        eval_multiply(tmp, r2);
                        get_mod_obj().montgomery_reduce(tmp);
                    }
                    result = tmp;
                }

                template<
                    typename Backend1, typename Backend2,
                    typename = typename boost::enable_if_c<
                        /// input number should fit in result
                        backends::max_precision<Backend1>::value >= backends::max_precision<Backend2>::value>::type>
                constexpr void adjust_regular(Backend1& result, const Backend2& input) const {
                    result = input;
                    if (check_montgomery_constraints(get_mod_obj())) {
                        get_mod_obj().montgomery_reduce(result);
                    }
                }

                template<typename Backend1, typename T>
                constexpr void mod_exp(Backend1& result, const T& exp) const {
                    mod_exp(result, result, exp);
                }

                template<typename Backend1, typename Backend2, typename T>
                constexpr void mod_exp(Backend1& result, const Backend2& a, const T& exp) const {
                    if (check_montgomery_constraints(get_mod_obj())) {
                        get_mod_obj().montgomery_exp(result, a, exp);
                    } else {
                        get_mod_obj().regular_exp(result, a, exp);
                    }
                }

                template<typename Backend1, typename Backend2>
                constexpr void mod_mul(Backend1& result, const Backend2& y) {
                    mod_mul(result, result, y);
                }

                template<typename Backend1, typename Backend2, typename Backend3>
                constexpr void mod_mul(Backend1& result, const Backend2& x, const Backend3& y) {
                    if (check_montgomery_constraints(get_mod_obj())) {
                        get_mod_obj().montgomery_mul(result, x, y);
                    } else {
                        get_mod_obj().regular_mul(result, x, y);
                    }
                }

                template<typename Backend1, typename Backend2>
                constexpr void mod_add(Backend1& result, const Backend2& y) {
                    mod_add(result, result, y);
                }

                template<typename Backend1, typename Backend2, typename Backend3>
                constexpr void mod_add(Backend1& result, const Backend2& x, const Backend3& y) {
                    get_mod_obj().regular_add(result, x, y);
                }

                template<typename Backend1, expression_template_option ExpressionTemplates>
                constexpr operator number<Backend1, ExpressionTemplates>() {
                    return get_mod();
                };

                constexpr int compare(const modular_params& o) const {
                    // They are either equal or not:
                    return get_mod().compare(o.get_mod());
                }

                constexpr void swap(modular_params& o) {
                    get_mod_obj().swap(o.get_mod_obj());
                }

                constexpr modular_params& operator=(const modular_params& o) {
                    modular_params tmp(o);
                    swap(tmp);

                    return *this;
                }

                constexpr modular_params& operator=(const number_type& m) {
                    m_mod_obj = m;

                    return *this;
                }

                // TODO: check function correctness
                constexpr friend std::ostream& operator<<(std::ostream& o, const modular_params& a) {
                    o << a.get_mod();
                    return o;
                }

            protected:
                modular_logic m_mod_obj;
            };

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
