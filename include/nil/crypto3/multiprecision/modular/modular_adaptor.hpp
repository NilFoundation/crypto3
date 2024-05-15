//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_HPP
#define CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_HPP

#include <boost/cstdint.hpp>
#include <boost/functional/hash_fwd.hpp>
#include <boost/predef.h>

#include <nil/crypto3/multiprecision/modular/modular_adaptor_fixed.hpp>

#include <boost/container/small_vector.hpp>

#include <algorithm>
#include <cmath>
#include <vector>

namespace boost {   
    namespace multiprecision {
        namespace backends {
            template<typename Backend, const modular_params<Backend> &Modulus>
            class modular_params_ct {
            public:
                typedef modular_params<Backend> modular_type;
 
                BOOST_MP_CXX14_CONSTEXPR modular_params_ct() {
                }
 
                BOOST_MP_CXX14_CONSTEXPR modular_params_ct(modular_type &input) {
                }
 
                BOOST_MP_CXX14_CONSTEXPR void set_modular_params(const modular_type &input) {
                }
 
                template<typename T>
                BOOST_MP_CXX14_CONSTEXPR void set_modular_params(const T &input) {
                }
 
                BOOST_MP_CXX14_CONSTEXPR const modular_type &mod_data() const {
                    return m_mod;
                }
 
            protected:
                BOOST_MP_CXX14_CONSTEXPR static const modular_type m_mod = Modulus;
            };
 
            // Must be used only in the tests, we must normally use only modular_params_ct.
            template<typename Backend>
            class modular_params_rt {
            public:
                typedef modular_params<Backend> modular_type;
 
                BOOST_MP_CXX14_CONSTEXPR modular_params_rt() {
                }

                BOOST_MP_CXX14_CONSTEXPR modular_params_rt(modular_type input) {
                    m_mod = input;
                }
 
                BOOST_MP_CXX14_CONSTEXPR void set_modular_params(const modular_type &input) {
                    m_mod = input;
                }
 
                BOOST_MP_CXX14_CONSTEXPR void set_modular_params(const Backend &input) {
                    m_mod = input;
                }
 
                BOOST_MP_CXX14_CONSTEXPR modular_type &mod_data() {
                    return m_mod;
                }
                BOOST_MP_CXX14_CONSTEXPR const modular_type &mod_data() const {
                    return m_mod;
                }
 
            public:
                modular_type m_mod;
            };
 
            // Used for converting number<modular_adaptor<Backend>> to number<Backend>.
            // We cannot change the first argument to a reference...
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_convert_to(Backend *result, const modular_adaptor<Backend, ModularParamsType> &val) {
                val.mod_data().adjust_regular(*result, val.base_data());
            }

            template<class Backend, typename ModularParamsType, class T>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if<boost::is_arithmetic<T>, bool>::type
                eval_eq(const modular_adaptor<Backend, ModularParamsType> &a, const T &b) {
                return a.compare(b) == 0;
            }
 
            template<class Backend1, class Backend2>
            BOOST_MP_CXX14_CONSTEXPR void eval_redc(Backend1 &result, const modular_params<Backend2> &mod) {
                mod.reduce(result);
                eval_modulus(result, mod.get_mod());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_add(modular_adaptor<Backend, ModularParamsType> &result,
                                    const modular_adaptor<Backend, ModularParamsType> &o) {
                eval_add(result.base_data(), o.base_data());
                if (!eval_lt(result.base_data(), result.mod_data().get_mod())) {
                    eval_subtract(result.base_data(), result.mod_data().get_mod());
                }
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_subtract(modular_adaptor<Backend, ModularParamsType> &result,
                                         const modular_adaptor<Backend, ModularParamsType> &o) {
                using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                eval_subtract(result.base_data(), o.base_data());
                if (eval_lt(result.base_data(), ui_type(0u))) {
                    eval_add(result.base_data(), result.mod_data().get_mod());
                }
            }
 
            template<unsigned Bits, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_subtract(
                modular_adaptor<cpp_int_modular_backend<Bits>, ModularParamsType> &result,
                const modular_adaptor<cpp_int_modular_backend<Bits>, ModularParamsType> &o) {
 
                if (eval_lt(result.base_data(), o.base_data())) {
                    auto v = result.mod_data().get_mod();
                    eval_subtract(v, o.base_data());
                    eval_add(result.base_data(), v);
                } else {
                    eval_subtract(result.base_data(), o.base_data());
                }
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_multiply(modular_adaptor<Backend, ModularParamsType> &result,
                                         const modular_adaptor<Backend, ModularParamsType> &o) {
                eval_multiply(result.base_data(), o.base_data());
                eval_redc(result.base_data(), result.mod_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_divide(modular_adaptor<Backend, ModularParamsType> &result,
                                       const modular_adaptor<Backend, ModularParamsType> &o) {
                Backend tmp1, tmp2;
                result.mod_data().adjust_regular(tmp1, result.base_data());
                result.mod_data().adjust_regular(tmp2, o.base_data());
                eval_divide(tmp1, tmp2);
                result.base_data() = tmp1;
                result.mod_data().adjust_modular(result.base_data());
                result.mod_data().adjust_regular(tmp2, result.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_modulus(modular_adaptor<Backend, ModularParamsType> &result,
                                        const modular_adaptor<Backend, ModularParamsType> &o) {
                Backend tmp1, tmp2;
                result.mod_data().adjust_regular(tmp1, result.base_data());
                result.mod_data().adjust_regular(tmp2, o.base_data());
                eval_modulus(tmp1, tmp2);
                result.base_data() = tmp1;
                result.mod_data().adjust_modular(result.base_data());
                // result.mod_data().adjust_regular(tmp2, result.base_data());
            }

            // If called with 3 arguments, delegate the call to the upper function.
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_modulus(modular_adaptor<Backend, ModularParamsType> &result,
                                        const modular_adaptor<Backend, ModularParamsType> &u,
                                        const modular_adaptor<Backend, ModularParamsType> &v) {
                result = std::move(u);
                eval_modulus(result, v);
            }

            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR bool eval_is_zero(const modular_adaptor<Backend, ModularParamsType> &val)
                BOOST_NOEXCEPT {
                return eval_is_zero(val.base_data());
            }
 
            // TODO: check returned value
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR int eval_get_sign(const modular_adaptor<Backend, ModularParamsType> &) {
                return 1;
            }
 
            template<class Backend, typename ModularParamsType, class T, class V>
            BOOST_MP_CXX14_CONSTEXPR void assign_components(modular_adaptor<Backend, ModularParamsType> &result, const T &a,
                                             const V &b) {
                result.base_data() = a;
                result.mod_data() = b;
                result.mod_data().adjust_modular(result.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_sqrt(modular_adaptor<Backend, ModularParamsType> &result,
                                     const modular_adaptor<Backend, ModularParamsType> &val) {
                eval_sqrt(result.base_data(), val.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_abs(modular_adaptor<Backend, ModularParamsType> &result,
                                    const modular_adaptor<Backend, ModularParamsType> &val) {
                result = val;
            }
 
            inline size_t window_bits(size_t exp_bits) {
                BOOST_STATIC_CONSTEXPR size_t wsize_count = 6;
                BOOST_STATIC_CONSTEXPR size_t wsize[wsize_count][2] = {{1434, 7}, {539, 6}, {197, 4},
                                                                       {70, 3},   {17, 2},  {0, 0}};
 
                size_t window_bits = 1;
 
                size_t j = wsize_count - 1;
                while (wsize[j][0] > exp_bits) {
                    --j;
                }
                window_bits += wsize[j][1];
 
                return window_bits;
            }
 
            template<class Backend, typename ModularParamsType>
            inline void find_modular_pow(modular_adaptor<Backend, ModularParamsType> &result,
                                         const modular_adaptor<Backend, ModularParamsType> &b,
                                         const Backend &exp) {
                modular_params<Backend> mod = b.mod_data();
                size_t m_window_bits;
                unsigned long cur_exp_index;
                size_t exp_bits = eval_msb(exp);
                m_window_bits = window_bits(exp_bits + 1);
 
                std::vector<Backend> m_g(1U << m_window_bits);
                Backend *p_g = m_g.data();
                Backend x(1, mod);
                Backend nibble = exp;
                Backend mask;
                eval_bit_set(mask, m_window_bits);
                eval_decrement(mask);
                *p_g = x;
                ++p_g;
                *p_g = b;
                ++p_g;
                for (size_t i = 2; i < (1U << m_window_bits); i++) {
                    eval_multiply(*p_g, m_g[i - 1], b);
                    ++p_g;
                }
                size_t exp_nibbles = (exp_bits + 1 + m_window_bits - 1) / m_window_bits;
                std::vector<size_t> exp_index;
 
                for (size_t i = 0; i < exp_nibbles; ++i) {
                    Backend tmp = nibble;
                    eval_bitwise_and(tmp, mask);
                    eval_convert_to(&cur_exp_index, tmp);
                    eval_right_shift(nibble, m_window_bits);
                    exp_index.push_back(cur_exp_index);
                }
 
                eval_multiply(x, m_g[exp_index[exp_nibbles - 1]]);
                for (size_t i = exp_nibbles - 1; i > 0; --i) {
 
                    for (size_t j = 0; j != m_window_bits; ++j) {
                        eval_multiply(x, x);
                    }
 
                    eval_multiply(x, m_g[exp_index[i - 1]]);
                }
                result = x;
            }
 
            template<class Backend, typename ModularParamsType, typename T>
            BOOST_MP_CXX14_CONSTEXPR void eval_pow(modular_adaptor<Backend, ModularParamsType> &result,
                                    const modular_adaptor<Backend, ModularParamsType> &b, const T &e) {
                find_modular_pow(result, b, e);
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_pow(modular_adaptor<Backend, ModularParamsType> &result,
                                    const modular_adaptor<Backend, ModularParamsType> &b,
                                    const modular_adaptor<Backend, ModularParamsType> &e) {
                Backend exp;
                e.mod_data().adjust_regular(exp, e.base_data());
                find_modular_pow(result, b, exp);
            }
 
            template<typename Backend1, typename Backend2, typename T, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_powm(modular_adaptor<Backend1, ModularParamsType> &result,
                                     const modular_adaptor<Backend2, ModularParamsType> &b, const T &e) {
                eval_pow(result, b, e);
            }
 
            template<typename Backend1, typename Backend2, typename Backend3, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_powm(modular_adaptor<Backend1, ModularParamsType> &result,
                                     const modular_adaptor<Backend2, ModularParamsType> &b,
                                     const modular_adaptor<Backend3, ModularParamsType> &e) {
                eval_pow(result, b, e);
            }
 
            template<class Backend, typename ModularParamsType, class UI>
            inline BOOST_MP_CXX14_CONSTEXPR void eval_left_shift(modular_adaptor<Backend, ModularParamsType> &t, UI i) noexcept {
                Backend tmp;
                t.mod_data().adjust_regular(tmp, t.base_data());
                eval_left_shift(tmp, i);
                t.base_data() = tmp;
                t.mod_data().adjust_modular(t.base_data());
            }
 
            template<class Backend, typename ModularParamsType, class UI>
            BOOST_MP_CXX14_CONSTEXPR void eval_right_shift(modular_adaptor<Backend, ModularParamsType> &t, UI i) {
                Backend tmp;
                t.mod_data().adjust_regular(tmp, t.base_data());
                eval_right_shift(tmp, i);
                t.base_data() = tmp;
                t.mod_data().adjust_modular(t.base_data());
            }
 
            template<class Backend, typename ModularParamsType, class UI>
            BOOST_MP_CXX14_CONSTEXPR void eval_left_shift(modular_adaptor<Backend, ModularParamsType> &t,
                                           const modular_adaptor<Backend, ModularParamsType> &v, UI i) {
                Backend tmp1, tmp2;
                t.mod_data().adjust_regular(tmp1, t.base_data());
                t.mod_data().adjust_regular(tmp2, v.base_data());
                eval_left_shift(tmp1, tmp2, static_cast<unsigned long>(i));
                t.base_data() = tmp1;
                t.mod_data().adjust_modular(t.base_data());
            }
 
            template<class Backend, typename ModularParamsType, class UI>
            BOOST_MP_CXX14_CONSTEXPR void eval_right_shift(modular_adaptor<Backend, ModularParamsType> &t,
                                            const modular_adaptor<Backend, ModularParamsType> &v, UI i) {
                Backend tmp1, tmp2;
                t.mod_data().adjust_regular(tmp1, t.base_data());
                t.mod_data().adjust_regular(tmp2, v.base_data());
                eval_right_shift(tmp1, tmp2, static_cast<unsigned long>(i));
                t.base_data() = tmp1;
                t.mod_data().adjust_modular(t.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bitwise_and(modular_adaptor<Backend, ModularParamsType> &result,
                                            const modular_adaptor<Backend, ModularParamsType> &v) {
                Backend tmp1, tmp2;
                result.mod_data().adjust_regular(tmp1, result.base_data());
                v.mod_data().adjust_regular(tmp2, v.base_data());
                eval_bitwise_and(tmp1, tmp2);
                result.base_data() = tmp1;
                result.mod_data().adjust_modular(result.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bitwise_or(modular_adaptor<Backend, ModularParamsType> &result,
                                           const modular_adaptor<Backend, ModularParamsType> &v) {
                Backend tmp1, tmp2;
                result.mod_data().adjust_regular(tmp1, result.base_data());
                v.mod_data().adjust_regular(tmp2, v.base_data());
                eval_bitwise_or(tmp1, tmp2);
                result.base_data() = tmp1;
                result.mod_data().adjust_modular(result.base_data());
            }
 
            template<class Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bitwise_xor(modular_adaptor<Backend, ModularParamsType> &result,
                                            const modular_adaptor<Backend, ModularParamsType> &v) {
                Backend tmp1, tmp2;
                result.mod_data().adjust_regular(tmp1, result.base_data());
                v.mod_data().adjust_regular(tmp2, v.base_data());
                eval_bitwise_xor(tmp1, tmp2);
                result.base_data() = tmp1;
                result.mod_data().adjust_modular(result.base_data());
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR int eval_msb(const modular_adaptor<Backend, ModularParamsType> &m) {
                Backend tmp;
                m.mod_data().adjust_regular(tmp, m.base_data());
                return eval_msb(tmp);
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR unsigned eval_lsb(const modular_adaptor<Backend, ModularParamsType> &m) {
                Backend tmp;
                m.mod_data().adjust_regular(tmp, m.base_data());
                return eval_lsb(tmp);
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR bool eval_bit_test(const modular_adaptor<Backend, ModularParamsType> &m, std::size_t index) {
                Backend tmp;
                m.mod_data().adjust_regular(tmp, m.base_data());
                return eval_bit_test(tmp, index);
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bit_set(modular_adaptor<Backend, ModularParamsType> &result, std::size_t index) {
                Backend tmp;
                result.mod_data().adjust_regular(tmp, result.base_data());
                eval_bit_set(tmp, index);
                result.mod_data().adjust_modular(result.base_data(), tmp);
            }
 
             // We must make sure any call with any integral type ends up here, if we use std::size_t here, something this function is not preferred by
             // the compiler and boost's version is used, which is worse.            
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bit_unset(modular_adaptor<Backend, ModularParamsType> &result, std::size_t index) {
                Backend tmp;
                result.mod_data().adjust_regular(tmp, result.base_data());
                eval_bit_unset(tmp, index);
                result.mod_data().adjust_modular(result.base_data(), tmp);
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_bit_flip(modular_adaptor<Backend, ModularParamsType> &result, std::size_t index) {
                Backend tmp;
                result.mod_data().adjust_regular(tmp, result.base_data());
                eval_bit_flip(tmp, index);
                result.mod_data().adjust_modular(result.base_data(), tmp);
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR modular_adaptor<Backend, ModularParamsType>
                eval_ressol(const modular_adaptor<Backend, ModularParamsType> &input) {
 
                Backend new_base, res;
                modular_adaptor<Backend, ModularParamsType> res_mod;
 
                input.mod_data().adjust_regular(new_base, input.base_data());
                res = eval_ressol(new_base, input.mod_data().get_mod());
                assign_components(res_mod, res, input.mod_data().get_mod());
 
                return res_mod;
            }
 
            template<typename Backend, typename ModularParamsType>
            BOOST_MP_CXX14_CONSTEXPR void eval_inverse_mod(modular_adaptor<Backend, ModularParamsType> &result,
                                            const modular_adaptor<Backend, ModularParamsType> &input) {
                Backend new_base, res;
 
                input.mod_data().adjust_regular(new_base, input.base_data());
                eval_inverse_mod(res, new_base, input.mod_data().get_mod());
                assign_components(result, res, input.mod_data().get_mod());
            }
 
            template<typename Backend, typename ModularParamsType>
            inline BOOST_MP_CXX14_CONSTEXPR std::size_t hash_value(
                const modular_adaptor<Backend, ModularParamsType> &val) noexcept {
                return hash_value(val.base_data());
            }

        } // namespace backends

        // We need to override this function for our modular types.
        template<class Backend, typename ModularParamsType>
        BOOST_MP_CXX14_CONSTEXPR void generic_interconvert(
                Backend& to, const backends::modular_adaptor<Backend, ModularParamsType> & from,
                const std::integral_constant<int, number_kind_integer>& /*to_type*/,
                const std::integral_constant<int, number_kind_integer>& /*from_type*/) {
            eval_convert_to(&to, from);
        }

        template<class Backend, typename ModularParamsType>
        BOOST_MP_CXX14_CONSTEXPR void generic_interconvert(
                number<Backend>& to, const number<backends::modular_adaptor<Backend, ModularParamsType>> & from,
                const std::integral_constant<int, number_kind_integer>& /*to_type*/,
                const std::integral_constant<int, number_kind_integer>& /*from_type*/) {
            eval_convert_to(&to.backend(), from.backend());
        }

        // This type-trait is needed for bitwise operations over boost::number class.
        template<class Backend, typename ModularParamsType>
        struct number_category<boost::multiprecision::backends::modular_adaptor<Backend, ModularParamsType>>
            : public std::integral_constant<int, boost::multiprecision::number_kind_integer> { };

    } // namespace multiprecision
} // namespace boost

#endif // CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_HPP
