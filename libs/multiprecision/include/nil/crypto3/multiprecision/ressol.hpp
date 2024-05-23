//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_RESSOL_HPP
#define CRYPTO3_MULTIPRECISION_RESSOL_HPP

#include <nil/crypto3/multiprecision/jacobi.hpp>
#include <boost/multiprecision/detail/default_ops.hpp>

#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor_fixed.hpp>

namespace boost {
    namespace multiprecision {
        namespace backends {
            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR Backend eval_ressol(const Backend &a, const Backend &p) {

                using default_ops::eval_add;
                using default_ops::eval_bit_set;
                using default_ops::eval_eq;
                using default_ops::eval_gt;
                using default_ops::eval_integer_modulus;
                using default_ops::eval_is_zero;
                using default_ops::eval_left_shift;
                using default_ops::eval_lsb;
                using default_ops::eval_lt;
                using default_ops::eval_right_shift;
                using default_ops::eval_subtract;

                using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;

                Backend zero, one, two, res;
                zero = ui_type(0u);
                one = ui_type(1u);
                two = ui_type(2u);

                // Martun: we do not throw any more, the caller must take care of providing correct arguments.
                if (eval_is_zero(a)) {
                    return zero;
                }
                //    BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be positive"));
                //} else if (!eval_lt(a, p)) {
                //    BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: value to solve for must be less than p"));
                //}

                if (eval_eq(p, 2ul)) {
                    return a;
                }
                //else if (!eval_gt(p, 1ul)) {
                //    BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: prime must be > 1 a"));
                //} else if (eval_integer_modulus(p, 2) == 0) {
                //    BOOST_THROW_EXCEPTION(std::invalid_argument("ressol: invalid prime"));
                //}

                if (eval_jacobi(a, p) != 1) {    // not a quadratic residue
                    // Martun: We used to return negative one here as an indication of a value now having a square root.
                    // Now we can't do that any more, no negative numbers, so we will return zero, and the caller
                    // Must check if the initial value was not zero, then there is no sqare root.
                    // This is temporary solution before we introduce proper error handling.
                    return zero;
                }

                modular_adaptor<Backend, modular_params_rt<Backend>> a_mod, res_mod;

                assign_components(a_mod, a, p);

                if (eval_integer_modulus(p, 4) == 3) {
                    Backend exp = p;

                    eval_add(exp, one);
                    eval_right_shift(exp, 2);
                    eval_powm(res_mod, a_mod, exp);
                    res_mod.mod_data().adjust_regular(res, res_mod.base_data());

                    return res;
                }

                Backend p_negone = p, q = p;

                eval_subtract(p_negone, 1);

                size_t s = eval_lsb(p_negone);

                eval_right_shift(q, s);
                eval_subtract(q, one);
                eval_right_shift(q, 1);

                modular_adaptor<Backend, modular_params_rt<Backend>> r_mod, n_mod = a_mod, r_sq_mod;

                eval_powm(r_mod, a_mod, q);
                eval_powm(r_sq_mod, r_mod, two);
                eval_multiply(n_mod, r_sq_mod);
                eval_multiply(r_mod, a_mod);

                Backend n, r;
                n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                if (eval_eq(n, one)) {
                    r_mod.mod_data().adjust_regular(r, r_mod.base_data());
                    return r;
                }

                // find random non quadratic residue z
                Backend z = two;
                while (eval_jacobi(z, p) == 1) {    // while z quadratic residue
                    eval_add(z, one);
                }

                eval_left_shift(q, 1);
                eval_add(q, one);

                modular_adaptor<Backend, modular_params_rt<Backend>> z_mod, c_mod, q_mod;

                assign_components(z_mod, z, p);
                eval_powm(c_mod, z_mod, q);
                n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                while (eval_gt(n, 1ul)) {
                    Backend q;
                    size_t i = 0;

                    q_mod = n_mod;
                    q_mod.mod_data().adjust_regular(q, q_mod.base_data());

                    while (!eval_eq(q, 1ul)) {
                        eval_powm(res_mod, q_mod, two);
                        q_mod = res_mod;
                        ++i;

                        if (i >= s) {
                            // Martun: We used to return negative one here as an indication of a value now having a square root.
                            // Now we can't do that any more, no negative numbers, so we will return zero, and the caller
                            // Must check if the initial value was not zero, then there is no sqare root.
                            // This is temporary solution before we introduce proper error handling.
                            return zero;
                        }

                        q_mod.mod_data().adjust_regular(q, q_mod.base_data());
                    }

                    Backend power_of_2;

                    eval_bit_set(power_of_2, s - i - 1);
                    eval_powm(c_mod, c_mod, power_of_2);
                    eval_multiply(r_mod, c_mod);
                    eval_powm(c_mod, c_mod, two);
                    eval_multiply(n_mod, c_mod);

                    n_mod.mod_data().adjust_regular(n, n_mod.base_data());
                    s = i;
                }

                r_mod.mod_data().adjust_regular(res, r_mod.base_data());
                return res;
            }

            template<unsigned Bits>
            BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend<Bits>
                eval_ressol(const cpp_int_modular_backend<Bits> &a, const cpp_int_modular_backend<Bits> &p) {

                using Backend = cpp_int_modular_backend<Bits>;
                using Backend_padded = cpp_int_modular_backend<Bits + 1>;
                using default_ops::eval_add;
                using default_ops::eval_bit_set;
                using default_ops::eval_eq;
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
                Backend one = ui_type(1u);
                Backend two = ui_type(2u);
                Backend res;

                if (eval_is_zero(a)) {
                    return zero;
                }
                BOOST_ASSERT(eval_lt(a, p));

                if (eval_eq(p, two)) {
                    return a;
                }
                BOOST_ASSERT(eval_gt(p, one));
                BOOST_ASSERT(eval_integer_modulus(p, 2) != 0);

                if (eval_jacobi(a, p) != 1) {    // not a quadratic residue
                    // Martun: We used to return negative one here as an indication of a value now having a square root.
                    // Now we can't do that any more, no negative numbers, so we will return zero, and the caller
                    // Must check if the initial value was not zero, then there is no sqare root.
                    // This is temporary solution before we introduce proper error handling.
                    return zero;
                }

                modular_adaptor<Backend, modular_params_rt<Backend>> a_mod, res_mod;

                assign_components(a_mod, a, p);

                if (eval_integer_modulus(p, 4) == 3) {
                    Backend_padded exp_padded = p;

                    eval_add(exp_padded, one);
                    eval_right_shift(exp_padded, 2);

                    // TODO(martun): check this with tests, I changed eval_pow to eval_powm in the whole file.
                    eval_powm(res_mod, a_mod, Backend(exp_padded));
                    res_mod.mod_data().adjust_regular(res, res_mod.base_data());

                    return res;
                }

                Backend p_negone = p;
                eval_subtract(p_negone, one);
                size_t s = eval_lsb(p_negone);

                Backend q = p;
                custom_right_shift(q, s);
                eval_subtract(q, one);
                eval_right_shift(q, 1u);

                modular_adaptor<Backend, modular_params_rt<Backend>> r_mod, n_mod = a_mod, r_sq_mod;

                eval_powm(r_mod, a_mod, q);
                eval_powm(r_sq_mod, r_mod, two);
                eval_multiply(n_mod, r_sq_mod);
                eval_multiply(r_mod, a_mod);

                Backend n, r;
                n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                if (eval_eq(n, one)) {
                    r_mod.mod_data().adjust_regular(r, r_mod.base_data());
                    return r;
                }

                // TODO: maybe overflow error here
                // find random non quadratic residue z
                Backend z = two;
                while (eval_jacobi(z, p) == 1u) {    // while z quadratic residue
                    eval_add(z, one);
                }

                eval_left_shift(q, 1u);
                eval_add(q, one);

                modular_adaptor<Backend, modular_params_rt<Backend>> z_mod, c_mod, q_mod;

                assign_components(z_mod, z, p);
                eval_powm(c_mod, z_mod, q);
                n_mod.mod_data().adjust_regular(n, n_mod.base_data());

                while (eval_gt(n, 1ul)) {
                    Backend q;
                    size_t i = 0u;

                    q_mod = n_mod;
                    q_mod.mod_data().adjust_regular(q, q_mod.base_data());

                    while (!eval_eq(q, 1ul)) {
                        eval_powm(res_mod, q_mod, two);
                        q_mod = res_mod;
                        ++i;

                        if (i >= s) {
                            // Martun: We used to return negative one here as an indication of a value now having a square root.
                            // Now we can't do that any more, no negative numbers, so we will return zero, and the caller
                            // Must check if the initial value was not zero, then there is no sqare root.
                            // This is temporary solution before we introduce proper error handling.
                            return zero;
                        }
                        q_mod.mod_data().adjust_regular(q, q_mod.base_data());
                    }

                    Backend power_of_2;

                    eval_bit_set(power_of_2, s - i - 1);
                    eval_powm(c_mod, c_mod, power_of_2);
                    eval_multiply(r_mod, c_mod);
                    eval_powm(c_mod, c_mod, two);
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
        BOOST_MP_CXX14_CONSTEXPR number<Backend, ExpressionTemplates> ressol(const number<Backend, ExpressionTemplates> &a,
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
        BOOST_MP_CXX14_CONSTEXPR number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates>
            ressol(const number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates> &modular) {

            return number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates>(
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
} // namespace boost

#endif    // CRYPTO3_MULTIPRECISION_RESSOL_HPP
