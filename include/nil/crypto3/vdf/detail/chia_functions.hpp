//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_VDF_CHIA_FUNCTIONS_HPP
#define CRYPTO3_VDF_CHIA_FUNCTIONS_HPP

#include <boost/mpl/vector.hpp>

#include <nil/crypto3/vdf/detail/chia_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace vdf {
            namespace detail {
                struct chia_functions : public chia_policy {
                    typedef chia_policy policy_type;

                    template<typename T>
                    using state_type = policy_type::state_type<T>;

#if defined(CRYPTO3_VDF_GMP) || defined(CRYPTO3_VDF_MPIR)

                    /*!
                     * @brief
                     * @tparam IntegerNumberType
                     * @param f
                     */
                    template<typename T>
                    inline static void normalize(state_type<T> &state) {
                        bool bleqa = (mpz_cmp(state.form.b, state.form.a) <= 0);
                        mpz_neg(state.form.a, state.form.a);
                        if (mpz_cmp(state.form.b, state.form.a) > 0 && bleqa) {
                            // Already normalized
                            return;
                        }
                        mpz_neg(state.form.a, state.form.a);
                        mpz_sub(state.r, state.form.a, state.form.b);

                        mpz_mul_si(state.ra, state.form.a, -3);
                        bool falb = (mpz_cmp(state.ra, state.form.b) < 0);

                        mpz_mul_2exp(state.ra, state.form.a, 1);

                        if (mpz_cmp(state.r, state.ra) >= 0 && falb) {
                            mpz_add(state.form.c, state.form.c, state.form.a);
                            mpz_add(state.form.c, state.form.c, state.form.b);
                            mpz_add(state.form.b, state.form.b, state.ra);

                            return;
                        }

                        mpz_fdiv_q(state.r, state.r, state.ra);
                        mpz_mul(state.ra, state.r, state.form.a);
                        mpz_addmul(state.form.c, state.ra, state.r);
                        mpz_addmul(state.form.c, state.r, state.form.b);
                        mpz_mul_2exp(state.ra, state.ra, 1);
                        mpz_add(state.form.b, state.form.b, state.ra);
                    }

                    /*!
                     * @brief Test if f is reduced. If it almost is but a, c are
                     * swapped, then just swap them to make it reduced.
                     * @tparam T
                     * @param f
                     * @return
                     */
                    template<typename T>
                    inline static bool test_reduction(binary_quadratic_form<T> &f) {
                        int a_b = mpz_cmpabs(f.a, f.b);
                        int c_b = mpz_cmpabs(f.c, f.b);

                        if (a_b < 0 || c_b < 0) {
                            return false;
                        }

                        int a_c = mpz_cmp(f.a, f.c);

                        if (a_c > 0) {
                            mpz_swap(f.a, f.c);
                            mpz_neg(f.b, f.b);
                        }

                        if (a_c == 0 && mpz_sgn(f.b) < 0) {
                            mpz_neg(f.b, f.b);
                        }

                        return true;
                    }

                    template<typename T>
                    inline static void fast_reduce(state_type<T> &state) {

                        int64_t u, v, w, x, u_, v_, w_, x_;
                        int64_t delta, gamma, sgn;
                        int64_t a, b, c, a_, b_, c_;
                        int64_t aa, ab, ac, ba, bb, bc, ca, cb, cc;
                        signed long int a_exp, b_exp, c_exp, max_exp, min_exp;

                        while (!test_reduction(state.form)) {

                            a = mpz_get_si_2exp(&a_exp, state.form.a);
                            b = mpz_get_si_2exp(&b_exp, state.form.b);
                            c = mpz_get_si_2exp(&c_exp, state.form.c);

                            max_exp = a_exp;
                            min_exp = a_exp;

                            if (max_exp < b_exp) {
                                max_exp = b_exp;
                            }
                            if (min_exp > b_exp) {
                                min_exp = b_exp;
                            }

                            if (max_exp < c_exp) {
                                max_exp = c_exp;
                            }
                            if (min_exp > c_exp) {
                                min_exp = c_exp;
                            }

                            if (max_exp - min_exp > exp_threshold) {
                                normalize(state);
                                continue;
                            }
                            max_exp++;    // for safety vs overflow

                            // Ensure a, b, c are shifted so that a : b : c ratios are same as
                            // state.form.a : state.form.b : state.form.c
                            // a, b, c will be used as approximations to state.form.a, state.form.b, state.form.c
                            a >>= (max_exp - a_exp);
                            b >>= (max_exp - b_exp);
                            c >>= (max_exp - c_exp);

                            u_ = 1;
                            v_ = 0;
                            w_ = 0;
                            x_ = 1;

                            // We must be very careful about overflow in the following steps
                            do {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                                // Ensure that delta = floor ((b+c) / 2c)
                                delta = b >= 0 ? (b + c) / (c << 1) : -(-b + c) / (c << 1);
                                a_ = c;
                                c_ = c * delta;
                                b_ = -b + (c_ << 1);
                                gamma = b - c_;
                                c_ = a - delta * gamma;

                                a = a_;
                                b = b_;
                                c = c_;

                                u_ = v;
                                v_ = -u + delta * v;
                                w_ = x;
                                x_ = -w + delta * x;
                                // The condition (abs(v_) | abs(x_)) <= THRESH protects against overflow
                            } while ((abs(v_) | abs(x_)) <= threshold && a > c && c > 0);

                            if ((abs(v_) | abs(x_)) <= threshold) {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                            }

                            aa = u * u;
                            ab = u * w;
                            ac = w * w;
                            ba = u * v << 1;
                            bb = u * x + v * w;
                            bc = w * x << 1;
                            ca = v * v;
                            cb = v * x;
                            cc = x * x;

                            // The following operations take 40% of the overall runtime.

                            mpz_mul_si(state.faa, state.form.a, aa);
                            mpz_mul_si(state.fab, state.form.b, ab);
                            mpz_mul_si(state.fac, state.form.c, ac);

                            mpz_mul_si(state.fba, state.form.a, ba);
                            mpz_mul_si(state.fbb, state.form.b, bb);
                            mpz_mul_si(state.fbc, state.form.c, bc);

                            mpz_mul_si(state.fca, state.form.a, ca);
                            mpz_mul_si(state.fcb, state.form.b, cb);
                            mpz_mul_si(state.fcc, state.form.c, cc);

                            mpz_add(state.form.a, state.faa, state.fab);
                            mpz_add(state.form.a, state.form.a, state.fac);

                            mpz_add(state.form.b, state.fba, state.fbb);
                            mpz_add(state.form.b, state.form.b, state.fbc);

                            mpz_add(state.form.c, state.fca, state.fcb);
                            mpz_add(state.form.c, state.form.c, state.fcc);
                        }
                    }

                    template<typename I>
                    inline static long mpz_bits(I x) {
                        if (x->_mp_size == 0) {
                            return 0;
                        }
                        return mpz_sizeinbase(x, 2);
                    }

                    inline static void mpz_addmul_si(mpz_t r, mpz_t x, long u) {
                        if (u >= 0) {
                            mpz_addmul_ui(r, x, u);
                        } else {
                            mpz_submul_ui(r, x, -u);
                        }
                    }

                    inline static uint64_t signed_shift(uint64_t op, int shift) {
                        if (shift > 0) {
                            return op << shift;
                        }
                        if (shift <= -64) {
                            return 0;
                        }
                        return op >> (-shift);
                    }

                    // Return an approximation x of the large mpz_t op by an int64_t and the exponent e adjustment.
                    // We must have (x * 2^e) / op = constant approximately.
                    inline static int64_t mpz_get_si_2exp(signed long int *exp, const mpz_t op) {
                        uint64_t size = mpz_size(op);
                        uint64_t last = mpz_getlimbn(op, size - 1);
                        uint64_t ret;
                        int lg2 = LOG2(last) + 1;
                        *exp = lg2;
                        ret = signed_shift(last, 63 - *exp);
                        if (size > 1) {
                            *exp += (size - 1) * 64;
                            uint64_t prev = mpz_getlimbn(op, size - 2);
                            ret += signed_shift(prev, -1 - lg2);
                        }
                        if (mpz_sgn(op) < 0) {
                            return -((int64_t)ret);
                        }
                        return ret;
                    }

                    template<typename T>
                    static void mpz_xgcd_partial(state_type<T> &state) {
                        mp_limb_signed_t aa2, aa1, bb2, bb1, rr1, rr2, qq, bb, t1, t2, t3, i;
                        mp_limb_signed_t bits, bits1, bits2;

                        mpz_set_si(state.y, 0);
                        mpz_set_si(state.x, -1);

                        while (*state.bx->_mp_d != 0 && mpz_cmp(state.bx, state.L) > 0) {
                            bits2 = mpz_bits(state.by);
                            bits1 = mpz_bits(state.bx);
                            bits = __GMP_MAX(bits2, bits1) - GMP_LIMB_BITS + 1;
                            if (bits < 0) {
                                bits = 0;
                            }

                            mpz_tdiv_q_2exp(state.r, state.by, bits);
                            rr2 = mpz_get_ui(state.r);
                            mpz_tdiv_q_2exp(state.r, state.bx, bits);
                            rr1 = mpz_get_ui(state.r);
                            mpz_tdiv_q_2exp(state.r, state.L, bits);
                            bb = mpz_get_ui(state.r);

                            aa2 = 0;
                            aa1 = 1;
                            bb2 = 1;
                            bb1 = 0;

                            for (i = 0; rr1 != 0 && rr1 > bb; i++) {
                                qq = rr2 / rr1;

                                t1 = rr2 - qq * rr1;
                                t2 = aa2 - qq * aa1;
                                t3 = bb2 - qq * bb1;

                                if (i & 1) {
                                    if (t1 < -t3 || rr1 - t1 < t2 - aa1) {
                                        break;
                                    }
                                } else {
                                    if (t1 < -t2 || rr1 - t1 < t3 - bb1) {
                                        break;
                                    }
                                }

                                rr2 = rr1;
                                rr1 = t1;
                                aa2 = aa1;
                                aa1 = t2;
                                bb2 = bb1;
                                bb1 = t3;
                            }

                            if (i == 0) {
                                mpz_fdiv_qr(state.ra, state.by, state.by, state.bx);
                                mpz_swap(state.by, state.bx);

                                mpz_submul(state.y, state.x, state.ra);
                                mpz_swap(state.y, state.x);
                            } else {
                                mpz_mul_si(state.r, state.by, bb2);
                                if (aa2 >= 0) {
                                    mpz_addmul_ui(state.r, state.bx, aa2);
                                } else {
                                    mpz_submul_ui(state.r, state.bx, -aa2);
                                }
                                mpz_mul_si(state.bx, state.bx, aa1);
                                if (bb1 >= 0) {
                                    mpz_addmul_ui(state.bx, state.by, bb1);
                                } else {
                                    mpz_submul_ui(state.bx, state.by, -bb1);
                                }
                                mpz_set(state.by, state.r);

                                mpz_mul_si(state.r, state.y, bb2);
                                if (aa2 >= 0) {
                                    mpz_addmul_ui(state.r, state.x, aa2);
                                } else {
                                    mpz_submul_ui(state.r, state.x, -aa2);
                                }
                                mpz_mul_si(state.x, state.x, aa1);
                                if (bb1 >= 0) {
                                    mpz_addmul_ui(state.x, state.y, bb1);
                                } else {
                                    mpz_submul_ui(state.x, state.y, -bb1);
                                }
                                mpz_set(state.y, state.r);

                                if (mpz_sgn(state.bx) < 0) {
                                    mpz_neg(state.x, state.x);
                                    mpz_neg(state.bx, state.bx);
                                }
                                if (mpz_sgn(state.by) < 0) {
                                    mpz_neg(state.y, state.y);
                                    mpz_neg(state.by, state.by);
                                }
                            }
                        }

                        if (mpz_sgn(state.by) < 0) {
                            mpz_neg(state.y, state.y);
                            mpz_neg(state.x, state.x);
                            mpz_neg(state.by, state.by);
                        }
                    }

                    // https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP
                    template<typename T>
                    static void nudupl(state_type<T> &state) {

                        mpz_gcdext(state.G, state.y, NULL, state.form.b, state.form.a);

#if defined(CRYPTO3_VDF_GMP)

                        mpz_divexact(state.By, state.form.a, state.G);
                        mpz_divexact(state.Dy, state.form.b, state.G);

#elif defined(CRYPTO3_VDF_MPIR)

                        mpz_divexact_gcd(state.By, state.form.a, state.G);
                        mpz_divexact_gcd(state.Dy, state.form.b, state.G);

#endif

                        mpz_mul(state.bx, state.y, state.form.c);
                        mpz_mod(state.bx, state.bx, state.By);

                        mpz_set(state.by, state.By);

                        if (mpz_cmpabs(state.by, state.L) <= 0) {
                            mpz_mul(state.dx, state.bx, state.Dy);
                            mpz_sub(state.dx, state.dx, state.form.c);
                            mpz_divexact(state.dx, state.dx, state.By);
                            mpz_mul(state.form.a, state.by, state.by);
                            mpz_mul(state.form.c, state.bx, state.bx);
                            mpz_add(state.t, state.bx, state.by);
                            mpz_mul(state.t, state.t, state.t);
                            mpz_sub(state.form.b, state.form.b, state.t);
                            mpz_add(state.form.b, state.form.b, state.form.a);
                            mpz_add(state.form.b, state.form.b, state.form.c);
                            mpz_mul(state.t, state.G, state.dx);
                            mpz_sub(state.form.c, state.form.c, state.t);
                            return;
                        }

                        mpz_xgcd_partial(state);

                        mpz_neg(state.x, state.x);
                        if (mpz_sgn((state.x)) > 0) {
                            mpz_neg(state.y, state.y);
                        } else {
                            mpz_neg(state.by, state.by);
                        }

                        mpz_mul(state.ax, state.G, state.x);
                        mpz_mul(state.ay, state.G, state.y);

                        mpz_mul(state.t, state.Dy, state.bx);
                        mpz_submul(state.t, state.form.c, state.x);
                        mpz_divexact(state.dx, state.t, state.By);
                        mpz_mul(state.Q1, state.y, state.dx);
                        mpz_add(state.dy, state.Q1, state.Dy);
                        mpz_add(state.form.b, state.dy, state.Q1);
                        mpz_mul(state.form.b, state.form.b, state.G);
                        mpz_divexact(state.dy, state.dy, state.x);
                        mpz_mul(state.form.a, state.by, state.by);
                        mpz_mul(state.form.c, state.bx, state.bx);
                        mpz_add(state.t, state.bx, state.by);
                        mpz_submul(state.form.b, state.t, state.t);
                        mpz_add(state.form.b, state.form.b, state.form.a);
                        mpz_add(state.form.b, state.form.b, state.form.c);
                        mpz_submul(state.form.a, state.ay, state.dy);
                        mpz_submul(state.form.c, state.ax, state.dx);
                    }

                    template<typename T>
                    static inline void discriminant_generator(state_type<T> &state, const T &d) {
                        T denom;
                        mpz_init(denom);
                        mpz_set_ui(state.form.a, 2);
                        mpz_set_ui(state.form.b, 1);
                        mpz_set_ui(state.form.b, 1);
                        mpz_mul(state.form.c, state.form.b, state.form.b);
                        mpz_sub(state.form.c, state.form.c, d);
                        mpz_mul_ui(denom, state.form.a, 4);
                        mpz_fdiv_q(state.form.c, state.form.c, denom);
                        fast_reduce(state);
                        mpz_clear(denom);
                    }

#elif defined(CRYPTO3_VDF_FLINT)

                    /*!
                     * @brief
                     * @tparam IntegerNumberType
                     * @param f
                     */
                    template<typename T>
                    inline static void normalize(state_type<T> &state) {
                        fmpz_neg(state.r, state.form.a);
                        if (fmpz_cmp(state.form.b, state.r) > 0 && fmpz_cmp(state.form.b, state.form.a) <= 0) {
                            // Already normalized
                            return;
                        }
                        fmpz_sub(state.r, state.form.a, state.form.b);
                        fmpz_mul_2exp(state.ra, state.form.a, 1);
                        fmpz_fdiv_q(state.r, state.r, state.ra);
                        fmpz_mul(state.ra, state.r, state.form.a);
                        fmpz_addmul(state.form.c, state.ra, state.r);
                        fmpz_addmul(state.form.c, state.r, state.form.b);
                        fmpz_mul_2exp(state.ra, state.ra, 1);
                        fmpz_add(state.form.b, state.form.b, state.ra);
                    }

                    /*!
                     * @brief Test if f is reduced. If it almost is but a, c are
                     * swapped, then just swap them to make it reduced.
                     * @tparam T
                     * @param f
                     * @return
                     */
                    template<typename T>
                    inline static bool test_reduction(binary_quadratic_form<T> &f) {
                        int a_b = fmpz_cmpabs(f.a, f.b);
                        int c_b = fmpz_cmpabs(f.c, f.b);

                        if (a_b < 0 || c_b < 0) {
                            return false;
                        }

                        int a_c = fmpz_cmp(f.a, f.c);

                        if (a_c > 0) {
                            fmpz_swap(f.a, f.c);
                            fmpz_neg(f.b, f.b);
                        }

                        if (a_c == 0 && fmpz_sgn(f.b) < 0) {
                            fmpz_neg(f.b, f.b);
                        }

                        return true;
                    }

                    /*!
                     * @brief
                     * @tparam IntegerNumberType
                     * @param form
                     */
                    template<typename T>
                    inline static void reduce(state_type<T> &state) {
                        normalize(state);
                        int cmp;
                        while (((cmp = fmpz_cmp(state.form.a, state.form.c)) > 0) ||
                               (cmp == 0 && fmpz_sgn(state.form.b) < 0)) {
                            fmpz_add(state.s, state.form.c, state.form.b);

                            // x = 2c
                            fmpz_mul_2exp(state.p, state.form.c, 1);
                            fmpz_fdiv_q(state.s, state.s, state.p);

                            fmpz_set(state.previous_form.a, state.form.a);
                            fmpz_set(state.previous_form.b, state.form.b);

                            // b = -b
                            fmpz_set(state.form.a, state.form.c);
                            fmpz_neg(state.form.b, state.form.b);

                            // x = 2sc
                            fmpz_mul(state.p, state.s, state.form.c);
                            fmpz_mul_2exp(state.p, state.p, 1);

                            // b += 2sc
                            fmpz_add(state.form.b, state.form.b, state.p);

                            // x = bs
                            fmpz_mul(state.p, state.previous_form.b, state.s);

                            // s = s^2
                            fmpz_mul(state.s, state.s, state.s);

                            // c = cs
                            fmpz_mul(state.form.c, state.form.c, state.s);

                            // c -= cx
                            fmpz_sub(state.form.c, state.form.c, state.p);

                            // c += a
                            fmpz_add(state.form.c, state.form.c, state.previous_form.a);
                        }
                        normalize(state);
                    }

                    template<typename T>
                    inline static void fast_reduce(state_type<T> &state) {

                        int64_t u, v, w, x, u_, v_, w_, x_;
                        int64_t delta, gamma, sgn;
                        int64_t a, b, c, a_, b_, c_;
                        int64_t aa, ab, ac, ba, bb, bc, ca, cb, cc;
                        signed long int a_exp, b_exp, c_exp, max_exp, min_exp;

                        while (!test_reduction(state.form)) {

                            a = fmpz_get_si_2exp(&a_exp, state.form.a);
                            b = fmpz_get_si_2exp(&b_exp, state.form.b);
                            c = fmpz_get_si_2exp(&c_exp, state.form.c);

                            max_exp = a_exp;
                            min_exp = a_exp;

                            if (max_exp < b_exp) {
                                max_exp = b_exp;
                            }
                            if (min_exp > b_exp) {
                                min_exp = b_exp;
                            }

                            if (max_exp < c_exp) {
                                max_exp = c_exp;
                            }
                            if (min_exp > c_exp) {
                                min_exp = c_exp;
                            }

                            if (max_exp - min_exp > exp_threshold) {
                                normalize(state);
                                continue;
                            }
                            max_exp++;    // for safety vs overflow

                            // Ensure a, b, c are shifted so that a : b : c ratios are same as
                            // state.form.a : state.form.b : state.form.c
                            // a, b, c will be used as approximations to state.form.a, state.form.b, state.form.c
                            a >>= (max_exp - a_exp);
                            b >>= (max_exp - b_exp);
                            c >>= (max_exp - c_exp);

                            u_ = 1;
                            v_ = 0;
                            w_ = 0;
                            x_ = 1;

                            // We must be very careful about overflow in the following steps
                            do {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                                // Ensure that delta = floor ((b+c) / 2c)
                                delta = b >= 0 ? (b + c) / (c << 1) : -(-b + c) / (c << 1);
                                a_ = c;
                                c_ = c * delta;
                                b_ = -b + (c_ << 1);
                                gamma = b - c_;
                                c_ = a - delta * gamma;

                                a = a_;
                                b = b_;
                                c = c_;

                                u_ = v;
                                v_ = -u + delta * v;
                                w_ = x;
                                x_ = -w + delta * x;
                                // The condition (abs(v_) | abs(x_)) <= THRESH protects against overflow
                            } while ((abs(v_) | abs(x_)) <= threshold && a > c && c > 0);

                            if ((abs(v_) | abs(x_)) <= threshold) {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                            }

                            aa = u * u;
                            ab = u * w;
                            ac = w * w;
                            ba = u * v << 1;
                            bb = u * x + v * w;
                            bc = w * x << 1;
                            ca = v * v;
                            cb = v * x;
                            cc = x * x;

                            // The following operations take 40% of the overall runtime.

                            fmpz_mul_si(state.faa, state.form.a, aa);
                            fmpz_mul_si(state.fab, state.form.b, ab);
                            fmpz_mul_si(state.fac, state.form.c, ac);

                            fmpz_mul_si(state.fba, state.form.a, ba);
                            fmpz_mul_si(state.fbb, state.form.b, bb);
                            fmpz_mul_si(state.fbc, state.form.c, bc);

                            fmpz_mul_si(state.fca, state.form.a, ca);
                            fmpz_mul_si(state.fcb, state.form.b, cb);
                            fmpz_mul_si(state.fcc, state.form.c, cc);

                            fmpz_add(state.form.a, state.faa, state.fab);
                            fmpz_add(state.form.a, state.form.a, state.fac);

                            fmpz_add(state.form.b, state.fba, state.fbb);
                            fmpz_add(state.form.b, state.form.b, state.fbc);

                            fmpz_add(state.form.c, state.fca, state.fcb);
                            fmpz_add(state.form.c, state.form.c, state.fcc);
                        }
                    }

                    template<typename I>
                    inline static long fmpz_bits(I x) {
                        if (x->_mp_size == 0) {
                            return 0;
                        }
                        return fmpz_sizeinbase(x, 2);
                    }

                    inline static void fmpz_addmul_si(fmpz_t r, fmpz_t x, long u) {
                        if (u >= 0) {
                            fmpz_addmul_ui(r, x, u);
                        } else {
                            fmpz_submul_ui(r, x, -u);
                        }
                    }

                    inline static uint64_t signed_shift(uint64_t op, int shift) {
                        if (shift > 0) {
                            return op << shift;
                        }
                        if (shift <= -64) {
                            return 0;
                        }
                        return op >> (-shift);
                    }

                    // Return an approximation x of the large fmpz_t op by an int64_t and the exponent e adjustment.
                    // We must have (x * 2^e) / op = constant approximately.
                    inline static int64_t fmpz_get_si_2exp(signed long int *exp, const fmpz_t op) {
                        uint64_t size = fmpz_size(op);
                        uint64_t last = op[size - 1];
                        uint64_t ret;
                        int lg2 = LOG2(last) + 1;
                        *exp = lg2;
                        ret = signed_shift(last, 63 - *exp);
                        if (size > 1) {
                            *exp += (size - 1) * 64;
                            uint64_t prev = op[size - 2];
                            ret += signed_shift(prev, -1 - lg2);
                        }
                        if (fmpz_sgn(op) < 0) {
                            return -((int64_t)ret);
                        }
                        return ret;
                    }

                    /* Find such g, x that a*x == g (mod n). Optimize for g == 1, so that x =
                     * a^(-1) (mod n) . */
                    void fast_gcdinv(fmpz_t g, fmpz_t x, const fmpz_t a, const fmpz_t n) {
                        int ret = fmpz_invmod(x, a, n);
                        if (ret) {
                            fmpz_one(g);
                            return;
                        }

                        fmpz_gcdinv(g, x, a, n);
                    }

                    // https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP
                    template<typename T>
                    static void nudupl(state_type<T> &state) {

                        fmpz_xgcd(state.G, state.y, NULL, state.form.b, state.form.a);

                        fmpz_divexact(state.By, state.form.a, state.G);
                        fmpz_divexact(state.Dy, state.form.b, state.G);

                        fmpz_mul(state.bx, state.y, state.form.c);
                        fmpz_mod(state.bx, state.bx, state.By);

                        fmpz_set(state.by, state.By);

                        if (fmpz_cmpabs(state.by, state.L) <= 0) {
                            fmpz_mul(state.dx, state.bx, state.Dy);
                            fmpz_sub(state.dx, state.dx, state.form.c);
                            fmpz_divexact(state.dx, state.dx, state.By);
                            fmpz_mul(state.form.a, state.by, state.by);
                            fmpz_mul(state.form.c, state.bx, state.bx);
                            fmpz_add(state.t, state.bx, state.by);
                            fmpz_mul(state.t, state.t, state.t);
                            fmpz_sub(state.form.b, state.form.b, state.t);
                            fmpz_add(state.form.b, state.form.b, state.form.a);
                            fmpz_add(state.form.b, state.form.b, state.form.c);
                            fmpz_mul(state.t, state.G, state.dx);
                            fmpz_sub(state.form.c, state.form.c, state.t);
                            return;
                        }

                        fmpz_xgcd_partial(state.y, state.x, state.by, state.bx, state.L);

                        fmpz_neg(state.x, state.x);
                        if (fmpz_sgn((state.x)) > 0) {
                            fmpz_neg(state.y, state.y);
                        } else {
                            fmpz_neg(state.by, state.by);
                        }

                        fmpz_mul(state.ax, state.G, state.x);
                        fmpz_mul(state.ay, state.G, state.y);

                        fmpz_mul(state.t, state.Dy, state.bx);
                        fmpz_submul(state.t, state.form.c, state.x);
                        fmpz_divexact(state.dx, state.t, state.By);
                        fmpz_mul(state.Q1, state.y, state.dx);
                        fmpz_add(state.dy, state.Q1, state.Dy);
                        fmpz_add(state.form.b, state.dy, state.Q1);
                        fmpz_mul(state.form.b, state.form.b, state.G);
                        fmpz_divexact(state.dy, state.dy, state.x);
                        fmpz_mul(state.form.a, state.by, state.by);
                        fmpz_mul(state.form.c, state.bx, state.bx);
                        fmpz_add(state.t, state.bx, state.by);
                        fmpz_submul(state.form.b, state.t, state.t);
                        fmpz_add(state.form.b, state.form.b, state.form.a);
                        fmpz_add(state.form.b, state.form.b, state.form.c);
                        fmpz_submul(state.form.a, state.ay, state.dy);
                        fmpz_submul(state.form.c, state.ax, state.dx);
                    }

                    template<typename T>
                    static inline void discriminant_generator(state_type<T> &state, const T &d) {
                        T denom;
                        fmpz_init(denom);
                        fmpz_set_ui(state.form.a, 2);
                        fmpz_set_ui(state.form.b, 1);
                        fmpz_mul(state.form.c, state.form.b, state.form.b);
                        fmpz_sub(state.form.c, state.form.c, d);
                        fmpz_mul_ui(denom, state.form.a, 4);
                        fmpz_fdiv_q(state.form.c, state.form.c, denom);
                        fast_reduce(state);
                        fmpz_clear(denom);
                    }

#elif defined(CRYPTO3_VDF_BOOST)

                    template<typename T>
                    inline static void normalize(state_type<T> &state) {
                        bool bleqa = (state.form.b <= state.form.a);
                        state.form.a = -state.form.a;
                        if (state.form.b > state.form.a && bleqa) {
                            // Already normalized
                            return;
                        }
                        state.form.a = -state.form.a;
                        state.r = state.form.a - state.form.b;

                        state.ra = state.form.a * -3;
                        bool falb = (state.ra < state.form.b < 0);

                        state.ra = state.form.a << 1;

                        if (state.r >= state.ra && falb) {
                            state.form.c += state.form.a + state.form.b;
                            state.form.b += state.ra;

                            return;
                        }

                        state.r = state.r / state.ra;
                        state.ra = state.r * state.form.a;
                        state.form.c += state.ra * state.r;
                        state.form.c += state.r * state.form.b;
                        state.ra <<= 1;
                        state.form.b += state.ra;
                    }

                    /*!
                     * @brief Test if f is reduced. If it almost is but a, c are
                     * swapped, then just swap them to make it reduced.
                     * @tparam T
                     * @param f
                     * @return
                     */
                    template<typename T>
                    inline static bool test_reduction(binary_quadratic_form<T> &f) {
                        if (abs(f.a) < abs(f.b) || abs(f.c) < abs(f.b)) {
                            return false;
                        }

                        if (f.a > f.c) {
                            std::swap(f.a, f.c);
                            f.b = -f.b;
                        }

                        if (f.a == f.c && f.b < 0) {
                            f.b = -f.b;
                        }

                        return true;
                    }

                    template<typename T>
                    inline static void fast_reduce(state_type<T> &state) {

                        int64_t u, v, w, x, u_, v_, w_, x_;
                        int64_t delta, gamma, sgn;
                        int64_t a, b, c, a_, b_, c_;
                        int64_t aa, ab, ac, ba, bb, bc, ca, cb, cc;
                        signed long int a_exp, b_exp, c_exp, max_exp, min_exp;

                        while (!test_reduction(state.form)) {

                            a = mpz_get_si_2exp(&a_exp, state.form.a);
                            b = mpz_get_si_2exp(&b_exp, state.form.b);
                            c = mpz_get_si_2exp(&c_exp, state.form.c);

                            max_exp = a_exp;
                            min_exp = a_exp;

                            if (max_exp < b_exp) {
                                max_exp = b_exp;
                            }
                            if (min_exp > b_exp) {
                                min_exp = b_exp;
                            }

                            if (max_exp < c_exp) {
                                max_exp = c_exp;
                            }
                            if (min_exp > c_exp) {
                                min_exp = c_exp;
                            }

                            if (max_exp - min_exp > exp_threshold) {
                                normalize(state);
                                continue;
                            }
                            max_exp++;    // for safety vs overflow

                            // Ensure a, b, c are shifted so that a : b : c ratios are same as
                            // state.form.a : state.form.b : state.form.c
                            // a, b, c will be used as approximations to state.form.a, state.form.b, state.form.c
                            a >>= (max_exp - a_exp);
                            b >>= (max_exp - b_exp);
                            c >>= (max_exp - c_exp);

                            u_ = 1;
                            v_ = 0;
                            w_ = 0;
                            x_ = 1;

                            // We must be very careful about overflow in the following steps
                            do {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                                // Ensure that delta = floor ((b+c) / 2c)
                                delta = b >= 0 ? (b + c) / (c << 1) : -(-b + c) / (c << 1);
                                a_ = c;
                                c_ = c * delta;
                                b_ = -b + (c_ << 1);
                                gamma = b - c_;
                                c_ = a - delta * gamma;

                                a = a_;
                                b = b_;
                                c = c_;

                                u_ = v;
                                v_ = -u + delta * v;
                                w_ = x;
                                x_ = -w + delta * x;
                                // The condition (abs(v_) | abs(x_)) <= THRESH protects against overflow
                            } while ((::abs(v_) | ::abs(x_)) <= threshold && a > c && c > 0);

                            if ((::abs(v_) | ::abs(x_)) <= threshold) {
                                u = u_;
                                v = v_;
                                w = w_;
                                x = x_;
                            }

                            aa = u * u;
                            ab = u * w;
                            ac = w * w;
                            ba = u * v << 1;
                            bb = u * x + v * w;
                            bc = w * x << 1;
                            ca = v * v;
                            cb = v * x;
                            cc = x * x;

                            // The following operations take 40% of the overall runtime.

                            state.faa = state.form.a * aa;
                            state.fab = state.form.b * ab;
                            state.fac = state.form.c * ac;

                            state.fba = state.form.a * ba;
                            state.fbb = state.form.b * bb;
                            state.fbc = state.form.c * bc;

                            state.fca = state.form.a * ca;
                            state.fcb = state.form.b * cb;
                            state.fcc = state.form.c * cc;

                            state.form.a = state.faa + state.fab + state.fac;
                            state.form.b = state.fba + state.fbb + state.fbc;
                            state.form.c = state.fca + state.fcb + state.fcc;
                        }
                    }

                    template<typename Backend, expression_template_option ExpressionTemplates>
                    inline static long mpz_bits(number<Backend, ExpressionTemplates> x) {
                        if (x->_mp_size == 0) {
                            return 0;
                        }
                        return mpz_sizeinbase(x, 2);
                    }

                    inline static uint64_t signed_shift(uint64_t op, int shift) {
                        if (shift > 0) {
                            return op << shift;
                        }
                        if (shift <= -64) {
                            return 0;
                        }
                        return op >> (-shift);
                    }

                    // Return an approximation x of the large mpz_t op by an int64_t and the exponent e adjustment.
                    // We must have (x * 2^e) / op = constant approximately.
                    template<typename Backend, expression_template_option ExpressionTemplates>
                    inline static int64_t mpz_get_si_2exp(signed long int *exp,
                                                          const number<Backend, ExpressionTemplates> &op) {
                        uint64_t size = op.backend().size();
                        uint64_t last = op.backend().limbs()[size - 1];
                        uint64_t ret;
                        int lg2 = LOG2(last) + 1;
                        *exp = lg2;
                        ret = signed_shift(last, 63 - *exp);
                        if (size > 1) {
                            *exp += (size - 1) * 64;
                            uint64_t prev = op.backend().limbs()[size - 2];
                            ret += signed_shift(prev, -1 - lg2);
                        }
                        if (op < 0) {
                            return -((int64_t)ret);
                        }
                        return ret;
                    }

                    template<typename T>
                    static void mpz_xgcd_partial(state_type<T> &state) {
                        typedef typename state_type<T>::number_type number_type;
                        typedef typename number_type::backend_type backend_type;

                        typedef typename boost::mpl::front<typename backend_type::signed_types>::type limb_type;

                        limb_type aa2, aa1, bb2, bb1, rr1, rr2, qq, bb, t1, t2, t3, i;
                        limb_type bits, bits1, bits2;

                        state.y = 0;
                        state.x = -1;

                        while (*state.bx->_mp_d != 0 && state.bx > state.L) {
                            bits2 = mpz_bits(state.by);
                            bits1 = mpz_bits(state.bx);
                            bits = __GMP_MAX(bits2, bits1) - sizeof(limb_type) * CHAR_BIT + 1;
                            if (bits < 0) {
                                bits = 0;
                            }

                            state.r = state.by >> bits;
                            rr2 = static_cast<limb_type>(state.r);
                            state.r = state.bx >> bits;
                            rr1 = static_cast<limb_type>(state.r);
                            state.r = state.L >> bits;
                            bb = static_cast<limb_type>(state.r);

                            aa2 = 0;
                            aa1 = 1;
                            bb2 = 1;
                            bb1 = 0;

                            for (i = 0; rr1 != 0 && rr1 > bb; i++) {
                                qq = rr2 / rr1;

                                t1 = rr2 - qq * rr1;
                                t2 = aa2 - qq * aa1;
                                t3 = bb2 - qq * bb1;

                                if (i & 1) {
                                    if (t1 < -t3 || rr1 - t1 < t2 - aa1) {
                                        break;
                                    }
                                } else {
                                    if (t1 < -t2 || rr1 - t1 < t3 - bb1) {
                                        break;
                                    }
                                }

                                rr2 = rr1;
                                rr1 = t1;
                                aa2 = aa1;
                                aa1 = t2;
                                bb2 = bb1;
                                bb1 = t3;
                            }

                            if (i == 0) {
                                mpz_fdiv_qr(state.ra, state.by, state.by, state.bx);
                                std::swap(state.by, state.bx);

                                state.y -= state.x * state.ra;
                                std::swap(state.y, state.x);
                            } else {
                                state.r = state.by * bb2;
                                if (aa2 >= 0) {
                                    state.r += state.bx * aa2;
                                } else {
                                    state.r -= state.bx * -aa2;
                                }
                                state.bx *= aa1;
                                if (bb1 >= 0) {
                                    state.bx += state.by * bb1;
                                } else {
                                    state.bx -= state.by * -bb1;
                                }
                                state.by = state.r;

                                state.r = state.y * bb2;
                                if (aa2 >= 0) {
                                    state.r += state.x * aa2;
                                } else {
                                    state.r -= state.x * -aa2;
                                }
                                state.x *= aa1;
                                if (bb1 >= 0) {
                                    state.x += state.y * bb1;
                                } else {
                                    state.x -= state.y * -bb1;
                                }
                                state.y = state.r;

                                if (state.bx < 0) {
                                    state.x = -state.x;
                                    state.bx = -state.bx;
                                }
                                if (state.by < 0) {
                                    state.y = -state.y;
                                    state.by = -state.by;
                                }
                            }
                        }

                        if (state.by < 0) {
                            state.y = -state.y;
                            state.x = -state.x;
                            state.by = -state.by;
                        }
                    }

                    // https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP
                    template<typename T>
                    static void nudupl(state_type<T> &state) {

                        mpz_gcdext(state.G, state.y, NULL, state.form.b, state.form.a);

                        state.By = state.form.a / state.G;
                        state.Dy = state.form.b / state.G;

                        state.bx = (state.y * state.form.c) % state.By;
                        state.by = state.By;

                        if (state.by <= state.L) {
                            state.dx = state.bx * state.Dy;
                            state.dx = state.dx - state.form.c;

                            state.dx = state.dx / state.By;

                            state.form.a = state.by * state.by;
                            state.form.c = state.bx * state.bx;

                            state.t = state.bx + state.by;
                            state.t *= state.t;

                            state.form.b = state.form.b - state.t;
                            state.form.b = state.form.b + state.form.a;
                            state.form.b = state.form.b + state.form.c;

                            state.t = state.G * state.dx;
                            state.form.c = state.form.c - state.t;
                            return;
                        }

                        mpz_xgcd_partial(state);

                        state.x = -state.x;
                        if (state.x > 0) {
                            state.y = -state.y;
                        } else {
                            state.by = -state.by;
                        }

                        state.ax = state.G * state.x;
                        state.ay = state.G * state.y;

                        state.t = state.Dy * state.bx;
                        state.t -= state.form.c * state.x;

                        state.dx = state.t / state.By;

                        state.Q1 = state.y * state.dx;
                        state.dy = state.dy + state.Q1;
                        state.form.b = state.dy + state.Q1;
                        state.form.b = state.form.b * state.G;
                        state.dy = state.dy / state.x;
                        state.form.a = state.by * state.by;
                        state.form.c = state.bx * state.bx;
                        state.t = state.bx + state.by;
                        state.form.b -= state.t * state.t;
                        state.form.b = state.form.b + state.form.a;
                        state.form.b = state.form.b + state.form.c;
                        state.form.a -= state.ay * state.dy;
                        state.form.c -= state.ax * state.dx;
                    }
#endif
                };
            }    // namespace detail
        }        // namespace vdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHIA_FUNCTIONS_HPP