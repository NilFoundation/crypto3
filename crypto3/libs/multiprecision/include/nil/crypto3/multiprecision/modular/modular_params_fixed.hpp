//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
#define CRYPTO3_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP

#include <nil/crypto3/multiprecision/modular/modular_functions_fixed.hpp>

namespace boost {   
    namespace multiprecision {
        namespace backends {

            using backends::cpp_int_modular_backend;

            template<typename Backend>
            class modular_params;

            // fixed precision modular params type which supports compile-time execution
            template<unsigned Bits>
            class modular_params<cpp_int_modular_backend<Bits>> {
            protected:
                typedef cpp_int_modular_backend<Bits> Backend;
                typedef backends::modular_functions_fixed<Backend> modular_logic;

            public:
                typedef typename modular_logic::policy_type policy_type;

            public:
                typedef typename policy_type::internal_limb_type internal_limb_type;
                typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                // typedef typename policy_type::Backend Backend;

                BOOST_MP_CXX14_CONSTEXPR auto &get_mod_obj() {
                    return m_mod_obj;
                }
                BOOST_MP_CXX14_CONSTEXPR const auto &get_mod_obj() const {
                    return m_mod_obj;
                }

                BOOST_MP_CXX14_CONSTEXPR auto &get_is_odd_mod() {
                    return is_odd_mod;
                }
                BOOST_MP_CXX14_CONSTEXPR const auto &get_is_odd_mod() const {
                    return is_odd_mod;
                }

            public:
                BOOST_MP_CXX14_CONSTEXPR auto get_mod() const {
                    return m_mod_obj.get_mod();
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params() {
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params(const Backend &m) : m_mod_obj(m) {
                    using boost::multiprecision::default_ops::eval_bit_test;
                    is_odd_mod = eval_bit_test(m, 0);
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params(const modular_params &o) : m_mod_obj(o.get_mod_obj()) {
                    is_odd_mod = o.get_is_odd_mod();
                }

                template<unsigned Bits1>
                BOOST_MP_CXX14_CONSTEXPR void reduce(cpp_int_modular_backend<Bits1> &result) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_reduce(result);
                    } else {
                        m_mod_obj.barrett_reduce(result);
                    }
                }

                BOOST_MP_CXX14_CONSTEXPR void adjust_modular(Backend &result) const {
                    adjust_modular(result, result);
                }

                template<unsigned Bits2>
                BOOST_MP_CXX14_CONSTEXPR void adjust_modular(Backend &result, const cpp_int_modular_backend<Bits2>& input) const {
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

                template<unsigned Bits1, unsigned Bits2,
                    /// input number should fit in result
                    typename = typename boost::enable_if_c<Bits1 >= Bits2>::type>
                BOOST_MP_CXX14_CONSTEXPR void adjust_regular(cpp_int_modular_backend<Bits1>& result,
                                              const cpp_int_modular_backend<Bits2>& input) const {
                    result = input;
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_reduce(result);
                    }
                }

                template<typename Backend1, typename T>
                BOOST_MP_CXX14_CONSTEXPR void mod_exp(Backend1 &result, const T &exp) const {
                    mod_exp(result, result, exp);
                }

                template<typename Backend1, typename Backend2, typename T>
                BOOST_MP_CXX14_CONSTEXPR void mod_exp(Backend1 &result, const Backend2 &a, const T &exp) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_exp(result, a, exp);
                    } else {
                        m_mod_obj.regular_exp(result, a, exp);
                    }
                }

                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR void mod_mul(Backend1 &result, const Backend1 &y) const {
                    if (is_odd_mod) {
                        m_mod_obj.montgomery_mul(result, y,
                            std::integral_constant<bool, is_trivial_cpp_int_modular<Backend1>::value>());
                    } else {
                        m_mod_obj.regular_mul(result, y);
                    }
                }

                template<typename Backend1, typename Backend2>
                BOOST_MP_CXX14_CONSTEXPR void mod_add(Backend1 &result, const Backend2 &y) const {
                    m_mod_obj.regular_add(result, y);
                }

                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR operator Backend1() {
                    return get_mod();
                };

                BOOST_MP_CXX14_CONSTEXPR int compare(const modular_params &o) const {
                    // They are either equal or not:
                    return get_mod().compare(o.get_mod());
                }

                BOOST_MP_CXX14_CONSTEXPR void swap(modular_params &o) {
                    m_mod_obj.swap(o.get_mod_obj());
                    bool t = is_odd_mod;
                    is_odd_mod = o.get_is_odd_mod();
                    o.get_is_odd_mod() = t;
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params &operator=(const modular_params &o) {
                    m_mod_obj = o.get_mod_obj();
                    is_odd_mod = o.get_is_odd_mod();
                    return *this;
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params &operator=(const Backend &m) {
                    m_mod_obj = m;
                    is_odd_mod = boost::multiprecision::default_ops::eval_bit_test(m, 0);
                    return *this;
                }

                // TODO: check function correctness
                BOOST_MP_CXX14_CONSTEXPR friend std::ostream &operator<<(std::ostream &o, const modular_params &a) {
                    o << a.get_mod();
                    return o;
                }

            protected:
                modular_logic m_mod_obj;
                bool is_odd_mod = false;
            };
        }  // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif    // CRYPTO3_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
