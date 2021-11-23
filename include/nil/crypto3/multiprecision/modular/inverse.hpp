//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_BACKENDS_INVERSE_HPP
#define BOOST_MULTIPRECISION_MODULAR_BACKENDS_INVERSE_HPP

#include <boost/container/vector.hpp>
#include <boost/type_traits/is_integral.hpp>

#include <nil/crypto3/multiprecision/detail/default_ops.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                template<typename Backend>
                constexpr Backend eval_extended_euclidean_algorithm(Backend &num1, Backend& num2, Backend &bezout_x, Backend &bezout_y) {
                    Backend x, y, tmp_num1 = num1, tmp_num2 = num2;
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    y = ui_type(1u);
                    bezout_x = ui_type(1u);

                    // Extended Euclidean Algorithm
                    while (!eval_is_zero(tmp_num2)) {
                        Backend quotient, remainder, placeholder;

                        eval_divide(quotient, tmp_num1, tmp_num2);
                        eval_modulus(remainder, tmp_num1, tmp_num2);

                        tmp_num1 = tmp_num2;
                        tmp_num2 = remainder;

                        Backend temp_x = x, temp_y = y;
                        eval_multiply(placeholder, quotient, x);
                        eval_subtract(placeholder, bezout_x, placeholder);
                        x = placeholder;
                        bezout_x = temp_x;

                        eval_multiply(placeholder, quotient, y);
                        eval_subtract(placeholder, bezout_y, placeholder);
                        y = placeholder;
                        bezout_y = temp_y;

                    }
                    return tmp_num1;
                }

                // a^(-1) mod p
                // http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
                template<typename Backend>
                constexpr Backend eval_inverse_extended_euclidean_algorithm(const Backend& a, const Backend& m) {
                    using Backend_doubled = typename default_ops::double_precision_type<Backend>::type;

                    Backend aa = a, mm = m, x, y, g;
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    g = eval_extended_euclidean_algorithm(aa, mm, x, y);
                    if (!eval_eq(g, ui_type(1u))) {
                        // BOOST_THROW_EXCEPTION(std::invalid_argument("eval_inverse_with_gcd: no inverse element"));
                        return ui_type(0u);
                    } else {
                        eval_modulus(x, m);
                        Backend_doubled tmp(x);
                        eval_add(tmp, m);
                        eval_modulus(tmp, m);
                        return static_cast<Backend>(tmp);
                    }
                }

                template<typename Backend>
                Backend eval_monty_inverse_pow2(Backend a, Backend k) {
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    Backend tmp;
                    Backend zero = ui_type(0u);
                    Backend one = ui_type(1u);
                    Backend two = ui_type(2u);

                    eval_modulus(tmp, a, two);
                    if (eval_is_zero(tmp) || eval_is_zero(k))
                        return zero;
                    if (eval_eq(k, one))
                        return one;
                    /*
                     * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
                     * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
                     */
                    Backend b = one;
                    Backend r;
                    Backend cur_add = one;
                    for (Backend i = zero; !eval_eq(i, k); eval_increment(i)) {
                        if (eval_bit_test(b, 0)) {
                            eval_subtract(b, a);
                            eval_add(r, cur_add);
                        }
                        eval_left_shift(cur_add, 1);
                        eval_right_shift(b, 1);
                    }

                    return r;
                }

                template<typename Backend>
                Backend inverse_mod_odd_modulus(const Backend& n, const Backend& mod)
                {
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    Backend zero = ui_type(0u);
                    Backend one = ui_type(1u);
                    Backend two = ui_type(2u);
                    // Caller should assure these preconditions:
//                    BOOST_ASSERT(n >= 0);
//                    BOOST_ASSERT(mod >= 0);
//                    BOOST_ASSERT(n < mod);
//                    BOOST_ASSERT(mod >= 3 && mod % 2 != 0);

                    /*
                    This uses a modular inversion algorithm designed by Niels Möller
                    and implemented in Nettle. The same algorithm was later also
                    adapted to GMP in mpn_sec_invert.

                   There is also a description of the algorithm in Appendix 5 of "Fast
                    Software Polynomial Multiplication on ARM Processors using the NEON Engine"
                    by Danilo Câmara, Conrado P. L. Gouvêa, Julio López, and Ricardo
                    Dahab in LNCS 8182
                       https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf

                    */

                    Backend a = n;
                    Backend b = mod;
                    Backend u = one;
                    Backend v = zero;

                    size_t ell = eval_msb(mod);
                    for (size_t i = 0; i < 2 * ell; ++i) {

                        size_t odd = eval_bit_test(a, 0);
                        //Backend gteq = (a >= b);
                        size_t gteq = default_ops::eval_gt(a, b) || eval_eq(a, b);
                        if (odd && gteq) {
                            eval_subtract(a, b);
//                            a -= b;
                        } else if (odd && !gteq) {
                            swap(u, v);
                            Backend tmp = a;
                            eval_subtract(a, b, a);
//                            a = b - a;
                            b = tmp;
                        }
                        eval_right_shift(a, 1);
//                        a >>= 1;
//                        Backend gteq2 = (u >= v);
                        size_t gteq2 = default_ops::eval_gt(u, v) || eval_eq(u, v);
                        if (odd && gteq2) {
                            eval_subtract(u, v);
//                            u -= v;
                        } else if (odd && !gteq2) {
                            eval_add(u, mod);
                            eval_subtract(u, v);
//                            u = u + mod - v;
                        }

                        auto tmp = u; //to_length<N + 1>(u);
//                        if (u & 1) {
                        if (eval_bit_test(u, 0)) {
//                            tmp += mod; //add(u, n);
                            eval_add(tmp, u, mod);
                        }
                        u = tmp;
                        eval_right_shift(u, 1);
                    }
                    if (!eval_eq(b, one)) { // if b != 1 then gcd(n,mod) > 1 and inverse does not exist
                        return zero;
                    }
                    return v;
                }

                template<typename Backend>
                Backend eval_inverse_mod(const Backend& n, const Backend& mod)
                {
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    Backend zero = ui_type(0u);
                    Backend one = ui_type(1u);
                    Backend two = ui_type(2u);
//                    BOOST_ASSERT(mod > 0 && n >= 0);
                    if (eval_is_zero(n) || (!eval_bit_test(n, 0) && !eval_bit_test(mod, 0))) {
                        return zero;
                    }
//                    if(n == 0 || (n % 2 == 0 && mod % 2 == 0))
//                        return zero;

//                    if(mod % 2 != 0) {
                    if(eval_bit_test(mod, 0)) {
                        /*
                        Fastpath for common case. This leaks if n is greater than mod or
                        not, but we don't guarantee const time behavior in that case.
                        */
                        Backend tmp1;
                        eval_modulus(tmp1, n, mod);
//                        Backend tmp1 = n % mod;
//                        if(n < mod)
                        if (default_ops::eval_lt(n, mod))
                            return inverse_mod_odd_modulus(n, mod);
                        else
                            return inverse_mod_odd_modulus(tmp1, mod);
                    }

                    // If n is even and mod is even we already returned 0
                    // If n is even and mod is odd we jumped directly to odd-modulus algo
//                    BOOST_ASSERT(n % 2 == 1);
                    const size_t mod_lz = eval_lsb(mod);
//                    if (mod == 1 << mod_lz) {
                    Backend tmp4 = one;
                    eval_left_shift(tmp4, mod_lz);
                    if (eval_eq(mod, tmp4)) {
                        // In this case we are performing an inversion modulo 2^k
                        Backend tmp5 = ui_type(mod_lz);
                        return eval_monty_inverse_pow2(n, tmp5);
                    }

                    if(mod_lz == 1) {
                        /*
                        Inversion modulo 2*o is an easier special case of CRT

                        This is exactly the main CRT flow below but taking advantage of
                        the fact that any odd number ^-1 modulo 2 is 1. As a result both
                        inv_2k and c can be taken to be 1, m2k is 2, and h is always
                        either 0 or 1, and its value depends only on the low bit of inv_o.

                        This is worth special casing because we generate RSA primes such
                        that phi(n) is of this form. However this only works for keys
                        that we generated in this way; pre-existing keys will typically
                        fall back to the general algorithm below.
                        */

//                        const Backend o = mod >> 1;
                        Backend o = mod;
                        eval_right_shift(o, 1);
//                        const Backend n_redc = n % o;
                        Backend n_redc;
                        eval_modulus(n_redc, n, o);
                        const Backend inv_o = inverse_mod_odd_modulus(n_redc, o);

                        // No modular inverse in this case:
//                        if(inv_o == 0)
                        if (eval_is_zero(inv_o))
                            return zero;

                        Backend h = inv_o;
//                        if (inv_o % 2 == 0) {
                        if (!eval_bit_test(inv_o, 0)) {
                            eval_add(h, o);
                        }
//                        h.ct_cond_add(!inv_o.get_bit(0), o);
                        return h;
                    }

                    /*
                    * In this case we are performing an inversion modulo 2^k*o for
                    * some k >= 2 and some odd (not necessarily prime) integer.
                    * Compute the inversions modulo 2^k and modulo o, then combine them
                    * using CRT, which is possible because 2^k and o are relatively prime.
                    */

//                    const Backend o = mod >> mod_lz;
//                    const Backend n_redc = n % o; // ct_modulo(n, o);
                    Backend o = mod;
                    eval_right_shift(o, mod_lz);
                    Backend n_redc = n;
                    eval_modulus(n_redc, o);
                    const Backend inv_o = inverse_mod_odd_modulus(n_redc, o);
                    Backend tmp5 = ui_type(mod_lz);
                    const Backend inv_2k = eval_monty_inverse_pow2(n, tmp5);

                    // No modular inverse in this case:
//                    if(inv_o == 0 || inv_2k == 0)
                    if(eval_is_zero(inv_o) || eval_is_zero(inv_2k))
                        return zero;

//                    const Backend m2k = 1 << mod_lz; //BigInt::power_of_2(mod_lz);
                    Backend m2k = one;
                    eval_left_shift(m2k, mod_lz);
                    // Compute the CRT parameter
                    Backend tmp6 = ui_type(mod_lz);
                    const Backend c = eval_monty_inverse_pow2(o, tmp6);

                    // Compute h = c*(inv_2k-inv_o) mod 2^k
//                    Backend h = c * (inv_2k - inv_o);
                    Backend h;
                    eval_subtract(h, inv_2k, inv_o);
                    eval_multiply(h, c);
//                    const bool h_neg = h <= 0;

//                    h.set_sign(BigInt::Positive);
//                    h.mask_bits(mod_lz);
                    Backend tmp3 = one;
                    eval_left_shift(tmp3, mod_lz);
                    eval_subtract(tmp3, one);
                    eval_bitwise_and(h, tmp3);
//                    h &= (1 << mod_lz) - 1;
//                    h <<= mod_lz;
//                    const bool h_nonzero = h.is_nonzero();
//                    h.ct_cond_assign(h_nonzero && h_neg, m2k - h);
//                    if (h_neg) {
//                        h = m2k - h;
//                    }
                    // Return result inv_o + h * o
                    eval_multiply(h, o);
                    eval_add(h, inv_o);
//                    h = inv_o + h * o;
                    return h;
                }

                /*
                * Compute the inversion number mod p^k.
                * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç.
                * @see https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
                *
                * @param a is a non-negative integer
                * @param p is a prime number, where gcd(a,p) = 1
                * @param k is a non-negative integer, where a < p^k
                * @return x = a^(−1) mod p^k
               */
                template<typename Backend>
                constexpr void eval_monty_inverse(Backend& res, const Backend& a, const Backend& p, const Backend& k) {

                    using default_ops::eval_abs;
                    using default_ops::eval_gt;
                    using default_ops::eval_modulus;
                    using default_ops::eval_subtract;

                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    Backend zero = ui_type(0u);
                    Backend one = ui_type(1u);
                    Backend two = ui_type(2u);

                    /*
                     * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
                     * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
                     */
                    Backend c, tmp;

                    // a^(-1) mod p:
                    c = eval_inverse_extended_euclidean_algorithm(a, p);
//                    с = inverse_mod(a, p);

                    Backend bi = one, bt, i = zero, xi, nextp = one;
                    res = zero;

                    while (!eval_eq(i, k)) {
                        // xi:
                        xi = bi;
                        eval_multiply(xi, c);
                        eval_modulus(xi, p);

                        if (eval_get_sign(xi) < 0) {
                            tmp = xi;
                            eval_abs(tmp, tmp);
                            eval_modulus(tmp, p);
                            xi = p;
                            eval_subtract(xi, tmp);
                        }

                        // bi:
                        tmp = a;
                        eval_multiply(tmp, xi);
                        eval_subtract(bi, tmp);
                        eval_divide(bi, p);

                        // res:
                        tmp = xi;
                        eval_multiply(tmp, nextp);
                        eval_multiply(nextp, p);
                        eval_add(res, tmp);
                        eval_add(i, one);
                    }
                }
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
