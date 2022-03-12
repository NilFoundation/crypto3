//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_RESSOL_HPP
#define BOOST_MULTIPRECISION_RESSOL_HPP

#include <nil/crypto3/multiprecision/jacobi.hpp>
#include <nil/crypto3/multiprecision/detail/default_ops.hpp>

#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                template<typename Backend>
                constexpr Backend eval_ressol(const Backend &a, const Backend &p) {

                    using default_ops::eval_add;
                    using default_ops::eval_bit_set;
                    using default_ops::eval_eq;
                    using default_ops::eval_get_sign;
                    using default_ops::eval_gt;
                    using default_ops::eval_integer_modulus;
                    using default_ops::eval_is_zero;
                    using default_ops::eval_left_shift;
                    using default_ops::eval_lsb;
                    using default_ops::eval_lt;
                    using default_ops::eval_right_shift;
                    using default_ops::eval_subtract;

                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;

                    Backend zero, posone, two, negone, res;
                    zero = ui_type(0u);
                    posone = ui_type(1u);
                    two = ui_type(2u);

                    eval_subtract(negone, posone);

                    if (eval_is_zero(a)) {
                        return zero;
                    } else if (eval_get_sign(a) < 0) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be positive"));
                    } else if (!eval_lt(a, p)) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be less than p"));
                    }

                    if (eval_eq(p, 2ul)) {
                        return a;
                    } else if (!eval_gt(p, 1ul)) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: prime must be > 1 a"));
                    } else if (eval_integer_modulus(p, 2) == 0) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: invalid prime"));
                    }

                    if (eval_jacobi(a, p) != 1) {    // not a quadratic residue
                        return negone;
                    }

                    modular_adaptor<Backend, modular_params_rt<Backend>> a_mod, res_mod;

                    assign_components(a_mod, a, p);

                    if (eval_integer_modulus(p, 4) == 3) {
                        Backend exp = p;

                        eval_add(exp, posone);
                        eval_right_shift(exp, 2);
                        eval_pow(res_mod, a_mod, exp);
                        res_mod.mod_data().adjust_regular(res, res_mod.base_data());

                        return res;
                    }

                    Backend p_negone = p, q = p;

                    eval_add(p_negone, negone);

                    size_t s = eval_lsb(p_negone);

                    eval_right_shift(q, s);
                    eval_subtract(q, posone);
                    eval_right_shift(q, 1);

                    modular_adaptor<Backend, modular_params_rt<Backend>> r_mod, n_mod = a_mod, r_sq_mod;

                    eval_pow(r_mod, a_mod, q);
                    eval_pow(r_sq_mod, r_mod, two);
                    eval_multiply(n_mod, r_sq_mod);
                    eval_multiply(r_mod, a_mod);

                    Backend n, r;
                    n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                    if (eval_eq(n, posone)) {
                        r_mod.mod_data().adjust_regular(r, r_mod.base_data());
                        return r;
                    }

                    // find random non quadratic residue z
                    Backend z = two;
                    while (eval_jacobi(z, p) == 1) {    // while z quadratic residue
                        eval_add(z, posone);
                    }

                    eval_left_shift(q, 1);
                    eval_add(q, posone);

                    modular_adaptor<Backend, modular_params_rt<Backend>> z_mod, c_mod, q_mod;

                    assign_components(z_mod, z, p);
                    eval_pow(c_mod, z_mod, q);
                    n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                    while (eval_gt(n, 1ul)) {
                        Backend q;
                        size_t i = 0;

                        q_mod = n_mod;
                        q_mod.mod_data().adjust_regular(q, q_mod.base_data());

                        while (!eval_eq(q, 1ul)) {
                            eval_pow(res_mod, q_mod, two);
                            q_mod = res_mod;
                            ++i;

                            if (i >= s) {
                                return negone;
                            }

                            q_mod.mod_data().adjust_regular(q, q_mod.base_data());
                        }

                        Backend power_of_2;

                        eval_bit_set(power_of_2, s - i - 1);
                        eval_pow(c_mod, c_mod, power_of_2);
                        eval_multiply(r_mod, c_mod);
                        eval_pow(c_mod, c_mod, two);
                        eval_multiply(n_mod, c_mod);

                        n_mod.mod_data().adjust_regular(n, n_mod.base_data());
                        s = i;
                    }

                    r_mod.mod_data().adjust_regular(res, r_mod.base_data());

                    return res;
                }

                template<unsigned MinBits, unsigned MaxBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr cpp_int_backend<MinBits, MaxBits, SignType, Checked, void>
                    eval_ressol(const cpp_int_backend<MinBits, MaxBits, SignType, Checked, void> &a,
                                const cpp_int_backend<MinBits, MaxBits, SignType, Checked, void> &p) {
                    using Backend = cpp_int_backend<MinBits, MaxBits, SignType, Checked, void>;
                    using Backend_padded = cpp_int_backend<MinBits + 1, MaxBits + 1, SignType, Checked, void>;
                    using default_ops::eval_add;
                    using default_ops::eval_bit_set;
                    using default_ops::eval_eq;
                    using default_ops::eval_get_sign;
                    using default_ops::eval_gt;
                    using default_ops::eval_integer_modulus;
                    using default_ops::eval_is_zero;
                    using default_ops::eval_left_shift;
                    using default_ops::eval_lsb;
                    using default_ops::eval_lt;
                    using default_ops::eval_right_shift;
                    using default_ops::eval_subtract;

                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;

                    Backend zero = ui_type(0u);
                    Backend posone = ui_type(1u);
                    Backend two = ui_type(2u);
                    Backend negone, res;

                    eval_subtract(negone, posone);

                    if (eval_is_zero(a)) {
                        return zero;
                    } else if (eval_get_sign(a) < 0) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be positive"));
                    } else if (!eval_lt(a, p)) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be less than p"));
                    }

                    if (eval_eq(p, 2ul)) {
                        return a;
                    } else if (!eval_gt(p, 1ul)) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: prime must be > 1 a"));
                    } else if (eval_integer_modulus(p, 2) == 0) {
                        BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: invalid prime"));
                    }

                    if (eval_jacobi(a, p) != 1) {    // not a quadratic residue
                        return negone;
                    }

                    modular_adaptor<Backend, modular_params_rt<Backend>> a_mod, res_mod;

                    assign_components(a_mod, a, p);

                    if (eval_integer_modulus(p, 4) == 3) {
                        Backend_padded exp_padded = p;

                        eval_add(exp_padded, posone);
                        eval_right_shift(exp_padded, 2);
                        eval_pow(res_mod, a_mod, Backend(exp_padded));
                        res_mod.mod_data().adjust_regular(res, res_mod.base_data());

                        return res;
                    }

                    Backend p_negone = p;
                    eval_add(p_negone, negone);
                    size_t s = eval_lsb(p_negone);

                    Backend q = p;
                    custom_right_shift(q, s);
                    eval_subtract(q, posone);
                    eval_right_shift(q, 1);

                    modular_adaptor<Backend, modular_params_rt<Backend>> r_mod, n_mod = a_mod, r_sq_mod;

                    eval_pow(r_mod, a_mod, q);
                    eval_pow(r_sq_mod, r_mod, two);
                    eval_multiply(n_mod, r_sq_mod);
                    eval_multiply(r_mod, a_mod);

                    Backend n, r;
                    n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                    if (eval_eq(n, posone)) {
                        r_mod.mod_data().adjust_regular(r, r_mod.base_data());
                        return r;
                    }

                    // TODO: maybe overflow error here
                    // find random non quadratic residue z
                    Backend z = two;
                    while (eval_jacobi(z, p) == 1) {    // while z quadratic residue
                        eval_add(z, posone);
                    }

                    eval_left_shift(q, 1);
                    eval_add(q, posone);

                    modular_adaptor<Backend, modular_params_rt<Backend>> z_mod, c_mod, q_mod;

                    assign_components(z_mod, z, p);
                    eval_pow(c_mod, z_mod, q);
                    n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                    while (eval_gt(n, 1ul)) {
                        Backend q;
                        size_t i = 0;

                        q_mod = n_mod;
                        q_mod.mod_data().adjust_regular(q, q_mod.base_data());

                        while (!eval_eq(q, 1ul)) {
                            eval_pow(res_mod, q_mod, two);
                            q_mod = res_mod;
                            ++i;

                            if (i >= s) {
                                return negone;
                            }

                            q_mod.mod_data().adjust_regular(q, q_mod.base_data());
                        }

                        Backend power_of_2;

                        eval_bit_set(power_of_2, s - i - 1);
                        eval_pow(c_mod, c_mod, power_of_2);
                        eval_multiply(r_mod, c_mod);
                        eval_pow(c_mod, c_mod, two);
                        eval_multiply(n_mod, c_mod);

                        n_mod.mod_data().adjust_regular(n, n_mod.base_data());
                        s = i;
                    }

                    r_mod.mod_data().adjust_regular(res, r_mod.base_data());

                    return res;
                }
            }    // namespace backends
            /**
             * Compute the square root of x modulo a prime using the
             * Shanks-Tonnelli algorithm
             *
             * @param a the input
             * @param p the prime
             * @return y such that (y*y)%p == a, or -1 if no such integer
             *
             */
            template<typename Backend, expression_template_option ExpressionTemplates>
            constexpr number<Backend, ExpressionTemplates> ressol(const number<Backend, ExpressionTemplates> &a,
                                                                  const number<Backend, ExpressionTemplates> &p) {
                return number<Backend, ExpressionTemplates>(backends::eval_ressol(a.backend(), p.backend()));
            }

            /**
             * Compute the square root of x modulo a prime using the
             * Shanks-Tonnelli algorithm
             *
             * @param modular such modular number with p - prime field, and x - current value
             * @return y such that (y*y)%p == x, or p - 1 if no such integer
             */

            template<typename Backend, typename StorageType, expression_template_option ExpressionTemplates>
            constexpr number<modular_adaptor<Backend, StorageType>, ExpressionTemplates>
                ressol(const number<modular_adaptor<Backend, StorageType>, ExpressionTemplates> &modular) {

                return number<modular_adaptor<Backend, StorageType>, ExpressionTemplates>(
                    backends::eval_ressol(modular.backend()));
            }

            /*
             * For tommath:
             * The implementation is split for two different cases:
                1. if p mod 4 == 3 we apply Handbook of Applied Cryptography algorithm 3.36 and compute r directly as r
             = n(p+1)/4 mod p
                2. otherwise we use Tonelli-Shanks algorithm
             */

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_RESSOL_HPP
