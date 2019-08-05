//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CHIA_POLICY_HPP
#define CRYPTO3_CHIA_POLICY_HPP

#if defined(CRYPTO3_VDF_FLINT)

#include <flint/fmpz.h>

#elif defined(CRYPTO3_VDF_GMP)

#include <gmpxx.h>

#elif defined(CRYPTO3_VDF_MPIR)

#include <mpirxx.h>

#elif defined(CRYPTO3_VDF_BOOST)

#include <boost/multiprecision/number.hpp>

#endif

namespace nil {
    namespace crypto3 {
        namespace vdf {
#ifdef CRYPTO3_VDF_BOOST
            using namespace boost::multiprecision;
#endif

            /*!
             * @brief Defines y = ax^2 + bxy + y^2
             * @tparam NumberType
             */
            template<typename NumberType>
            struct binary_quadratic_form {
                typedef NumberType number_type;
#if defined(CRYPTO3_VDF_GMP) || defined(CRYPTO3_VDF_MPIR)

                binary_quadratic_form() {
                    mpz_inits(a, b, c, NULL);
                }

#elif defined(CRYPTO3_VDF_FLINT)

#endif

                // y = ax^2 + bxy + y^2
                number_type a;
                number_type b;
                number_type c;
                number_type d;    // discriminant
            };

            namespace detail {
                struct chia_policy {

#define LOG2(X) (63 - __builtin_clzll((X)))

                    constexpr static const int64_t threshold = 1UL << 31;
                    constexpr static const int64_t double_threshold = 1UL << 31;
                    constexpr static const int64_t exp_threshold = 63;
                    constexpr static const int64_t maxv = ((1UL << 63) - 1);

                    template<typename NumberType>
                    struct state_type {
                        typedef NumberType number_type;
                        typedef binary_quadratic_form<number_type> form_type;
#if defined(CRYPTO3_VDF_GMP) || defined(CRYPTO3_VDF_MPIR)

                        state_type() {
                            mpz_inits(D, L, NULL);
                            mpz_inits(r, ra, s, p, NULL);
                            mpz_inits(G, dx, dy, By, Dy, x, y, t1, t2, bx, by, ax, ay, q, t, Q1, NULL);
                            mpz_inits(faa, fab, fac, fba, fbb, fbc, fca, fcb, fcc, NULL);
                        }

#elif defined(CRYPTO3_VDF_FLINT)

                        state_type() {
                            fmpz_init(D);
                            fmpz_init(L);
                            fmpz_init(r);
                            fmpz_init(ra);
                            fmpz_init(s);
                            fmpz_init(p);
                            fmpz_init(G);
                            fmpz_init(dx);
                            fmpz_init(dy);
                            fmpz_init(By);
                            fmpz_init(Dy);
                            fmpz_init(x);
                            fmpz_init(y);
                            fmpz_init(t1);
                            fmpz_init(t2);
                            fmpz_init(bx);
                            fmpz_init(by);
                            fmpz_init(ax);
                            fmpz_init(ay);
                            fmpz_init(q);
                            fmpz_init(t);
                            fmpz_init(Q1);
                            fmpz_init(faa);
                            fmpz_init(fab);
                            fmpz_init(fac);
                            fmpz_init(fba);
                            fmpz_init(fbb);
                            fmpz_init(fbc);
                            fmpz_init(fca);
                            fmpz_init(fcb);
                            fmpz_init(fcc);
                        }
#endif

                        number_type D, L;
                        number_type r, ra, s, p;
                        number_type G, dx, dy, By, Dy, x, y, t1, t2, bx, by, ax, ay, q, t, Q1;

                        number_type faa, fab, fac, fba, fbb, fbc, fca, fcb, fcc;

                        form_type form;
                    };
                };
            }    // namespace detail
        }        // namespace vdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHIA_POLICY_HPP
