//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP

#include <nil/crypto3/multiprecision/detail/number_base.hpp>
#include <nil/crypto3/multiprecision/modular/modular_policy_fixed.hpp>

#include <boost/mpl/if.hpp>

#include <type_traits>
#include <utility>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                template<typename Backend>
                class modular_functions_fixed;

                //
                // the function works correctly only with consistent backend objects,
                // i.e. their limbs should not be manipulated directly
                // as it breaks backend logic of size determination
                // (or real size of such objects should be adjusted then)
                //
                template<typename Backend>
                constexpr typename std::conditional<is_trivial_cpp_int<Backend>::value,
                                                    typename trivial_limb_type<max_precision<Backend>::value>::type,
                                                    limb_type>::type
                    get_limb_value(const Backend &b, const std::size_t i) {
                    if (i < b.size()) {
                        return b.limbs()[i];
                    }
                    return 0;
                }

                //
                // function return real limb of nontrivial backend.
                //
                template<typename, typename Backend>
                constexpr typename boost::enable_if_c<!is_trivial_cpp_int<Backend>::value, limb_type>::type
                    custom_get_limb_value(const Backend &b, const std::size_t i) {
                    return b.limbs()[i];
                }

                //
                // function works with trivial backend.
                // return value of logical limb as if trivial backend consists of several logical limbs.
                //
                template<typename internal_limb_type, typename Backend>
                constexpr typename boost::enable_if_c<
                    is_trivial_cpp_int<Backend>::value &&
                        sizeof(typename trivial_limb_type<max_precision<Backend>::value>::type) >=
                            sizeof(internal_limb_type),
                    internal_limb_type>::type
                    custom_get_limb_value(const Backend &b, const std::size_t i) {
                    return static_cast<internal_limb_type>(b.limbs()[0] >> (sizeof(internal_limb_type) * CHAR_BIT * i));
                }

                //
                // function set limb value of nontrivial backend.
                //
                template<typename, typename Backend>
                constexpr typename boost::enable_if_c<!is_trivial_cpp_int<Backend>::value>::type
                    custom_set_limb_value(Backend &b, const std::size_t i, limb_type v) {
                    b.limbs()[i] = v;
                }

                //
                // WARNING: using of this function is correct in current implementation of modular adaptor
                // DO NOT USE THIS FUNCTION IN GENERAL CASE
                //
                // function works with trivial backend.
                // set value of logical limb as if trivial backend consists of several logical limbs.
                // modified logical limb is supposed to have zero value.
                //
                template<typename internal_limb_type, typename Backend>
                constexpr typename boost::enable_if_c<
                    is_trivial_cpp_int<Backend>::value &&
                    sizeof(typename trivial_limb_type<max_precision<Backend>::value>::type) >=
                        sizeof(internal_limb_type)>::type
                    custom_set_limb_value(Backend &b, const std::size_t i, internal_limb_type v) {
                    using local_limb_type = typename trivial_limb_type<max_precision<Backend>::value>::type;

                    //
                    // commented part seems to be correct in general case
                    //
                    // std::size_t upper_bytes_count = sizeof(local_limb_type) - sizeof(internal_limb_type) * (i + 1);
                    // std::size_t lower_bytes_count = sizeof(internal_limb_type) * i;
                    // unsigned char byte_mask = ~0;
                    //
                    // local_limb_type mask = 0;
                    // for (std::size_t j = 0; j < upper_bytes_count; j++)
                    // {
                    //    mask |= byte_mask;
                    //    mask <<= CHAR_BIT;
                    // }
                    // mask <<= (sizeof(internal_limb_type) - 1) * CHAR_BIT;
                    // if (lower_bytes_count)
                    // {
                    //    for (std::size_t j = 0; j < lower_bytes_count - 1; j++)
                    //    {
                    //       mask |= byte_mask;
                    //       mask <<= CHAR_BIT;
                    //    }
                    //    mask |= byte_mask;
                    // }
                    //
                    // b.limbs()[0] &= mask;
                    b.limbs()[0] |= (static_cast<local_limb_type>(v) << (sizeof(internal_limb_type) * CHAR_BIT * i));
                }

                template<typename Backend>
                constexpr typename std::enable_if<!is_trivial_cpp_int<Backend>::value>::type
                    adjust_backend_size(Backend &b, std::size_t mod_size) {
                    assert(mod_size + 1 <= Backend::internal_limb_count);
                    b.resize(b.limbs()[mod_size] != 0 ? mod_size + 1 : mod_size, 1);
                }

                template<typename Backend>
                constexpr typename std::enable_if<is_trivial_cpp_int<Backend>::value>::type
                    adjust_backend_size(Backend &b, std::size_t mod_size) {
                    assert(mod_size == 1);
                    b.resize(mod_size, 1);
                }

                template<typename Backend>
                constexpr bool check_modulus_constraints(const Backend &m) {
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    using default_ops::eval_lt;

                    return !eval_lt(m, static_cast<ui_type>(0u));
                }

                template<typename Backend>
                constexpr bool check_montgomery_constraints(const Backend &m) {
                    using default_ops::eval_bit_test;
                    // Check m % 2 == 0
                    return eval_bit_test(m, 0);
                }

                template<typename Backend>
                constexpr bool check_montgomery_constraints(const modular_functions_fixed<Backend> &mo) {
                    return check_montgomery_constraints(mo.get_mod().backend());
                }

                //
                // a little trick to prevent error in constexpr execution of eval_right_shift
                // due to non-constexpr nature of right_shift_byte
                //
                template<typename Backend>
                constexpr void custom_right_shift(Backend &b, unsigned s) {
                    using default_ops::eval_left_shift;
                    using default_ops::eval_right_shift;

                    if (!s) {
                        return;
                    }

                    limb_type byte_shift_mask = CHAR_BIT - 1;
                    if ((s & byte_shift_mask) == 0) {
                        eval_right_shift(b, s - 1u);
                        eval_right_shift(b, 1u);
                    } else {
                        eval_right_shift(b, s);
                    }
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                class modular_functions_fixed<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>> {
                protected:
                    typedef modular_fixed_cpp_int_backend<MinBits, SignType, Checked> Backend;

                public:
                    typedef modular_policy<Backend> policy_type;

                protected:
                    typedef typename policy_type::internal_limb_type internal_limb_type;
                    typedef typename policy_type::internal_double_limb_type internal_double_limb_type;

                    typedef typename policy_type::Backend_doubled_1 Backend_doubled_1;
                    typedef typename policy_type::Backend_quadruple_1 Backend_quadruple_1;
                    typedef typename policy_type::Backend_padded_limbs Backend_padded_limbs;
                    typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                    typedef typename policy_type::Backend_doubled_padded_limbs Backend_doubled_padded_limbs;

                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::number_type_u number_type_u;
                    typedef typename policy_type::dbl_lmb_number_type dbl_lmb_number_type;

                    constexpr static auto limbs_count = policy_type::limbs_count;
                    constexpr static auto limb_bits = policy_type::limb_bits;

                    constexpr void initialize_modulus(const number_type &m) {
                        BOOST_ASSERT(check_modulus_constraints(m.backend()));

                        m_mod = m;
                    }

                    constexpr void initialize_barrett_params() {
                        using default_ops::eval_bit_set;
                        using default_ops::eval_divide;
                        using default_ops::eval_msb;

                        m_barrett_mu = static_cast<limb_type>(0u);

                        eval_bit_set(m_barrett_mu, 2u * (1u + eval_msb(m_mod.backend())));
                        eval_divide(m_barrett_mu, m_mod.backend());
                    }

                    constexpr void initialize_montgomery_params() {
                        if (check_montgomery_constraints(m_mod.backend())) {
                            find_const_variables();
                        }
                    }

                    /*
                     * Compute -input^-1 mod 2^limb_bits. Throws an exception if input
                     * is even. If input is odd, then input and 2^n are relatively prime
                     * and an inverse exists.
                     */
                    constexpr internal_limb_type monty_inverse(const internal_limb_type &a) {

                        internal_limb_type b = 1;
                        internal_limb_type r = 0;

                        for (size_t i = 0; i != limb_bits; ++i) {
                            const internal_limb_type bi = b % 2;
                            r >>= 1;
                            r += bi << (limb_bits - 1);

                            b -= a * bi;
                            b >>= 1;
                        }

                        // Now invert in addition space
                        r = (~static_cast<internal_limb_type>(0) - r) + 1;

                        return r;
                    }

                    constexpr void find_const_variables() {
                        using default_ops::eval_bit_set;
                        using default_ops::eval_gt;
                        using default_ops::eval_multiply;

                        m_montgomery_p_dash = monty_inverse(m_mod.backend().limbs()[0]);

                        Backend_doubled_padded_limbs r;
                        eval_bit_set(r, 2 * m_mod.backend().size() * limb_bits);
                        barrett_reduce(r);

                        m_montgomery_r2 = static_cast<Backend>(r);
                    }

                    constexpr void initialize(const number_type &m) {
                        initialize_modulus(m);
                        initialize_barrett_params();
                        initialize_montgomery_params();
                    }

                public:
                    constexpr auto &get_mod() {
                        return m_mod;
                    }
                    constexpr auto &get_mu() {
                        return m_barrett_mu;
                    }
                    constexpr auto &get_r2() {
                        return m_montgomery_r2;
                    }
                    constexpr auto &get_p_dash() {
                        return m_montgomery_p_dash;
                    }

                    constexpr const auto &get_mod() const {
                        return m_mod;
                    }
                    constexpr const auto &get_mu() const {
                        return m_barrett_mu;
                    }
                    constexpr const auto &get_r2() const {
                        return m_montgomery_r2;
                    }
                    constexpr auto get_p_dash() const {
                        return m_montgomery_p_dash;
                    }

                    constexpr modular_functions_fixed() {
                    }

                    constexpr modular_functions_fixed(const number_type_u &m) {
                        initialize(m);
                    }

                    constexpr modular_functions_fixed(const number_type &m) {
                        initialize(m);
                    }

                    constexpr modular_functions_fixed(const modular_functions_fixed &o) {
                        m_mod = o.get_mod();
                        m_barrett_mu = o.get_mu();
                        m_montgomery_r2 = o.get_r2();
                        m_montgomery_p_dash = o.get_p_dash();
                    }

                    template<typename Backend1>
                    constexpr void barrett_reduce(Backend1 &result) const {
                        barrett_reduce(result, result);
                    }

                    //
                    // this overloaded barrett_reduce is intended to work with built-in integral types
                    //
                    template<typename Backend1, typename Backend2>
                    constexpr typename std::enable_if<std::is_integral<Backend2>::value>::type
                        barrett_reduce(Backend1 &result, Backend2 input) const {
                        using input_number_type = typename std::conditional<
                            bool(sizeof(Backend2) * CHAR_BIT > MinBits),
                            number<modular_fixed_cpp_int_backend<sizeof(Backend2) * CHAR_BIT, SignType, Checked>>,
                            number_type>::type;

                        input_number_type input_adjusted(input);
                        barrett_reduce(result, input_adjusted.backend());
                    }

                    //
                    // this overloaded barrett_reduce is intended to work with input Backend2 type of less precision
                    // than modular Backend to satisfy constraints of core barrett_reduce overloading
                    //
                    template<typename Backend1, typename Backend2,
                             typename boost::enable_if_c<
                                 max_precision<Backend2>::value<max_precision<Backend>::value, bool>::type =
                                     true> constexpr void barrett_reduce(Backend1 &result, const Backend2 &input)
                                 const {
                        Backend input_adjusted(input);
                        barrett_reduce(result, input_adjusted);
                    }

                    template<typename Backend1, typename Backend2,
                             typename = typename boost::enable_if_c<
                                 /// result should fit in the output parameter
                                 max_precision<Backend1>::value >= max_precision<Backend>::value &&
                                 /// to prevent problems with trivial cpp_int
                                 max_precision<Backend2>::value >= max_precision<Backend>::value>::type>
                    constexpr void barrett_reduce(Backend1 &result, Backend2 input) const {
                        using default_ops::eval_add;
                        using default_ops::eval_eq;
                        using default_ops::eval_lt;
                        using default_ops::eval_modulus;
                        using default_ops::eval_msb;
                        using default_ops::eval_multiply;
                        using default_ops::eval_subtract;

                        //
                        // to prevent problems with trivial cpp_int
                        //
                        Backend2 modulus(m_mod.backend());

                        if (eval_lt(input, modulus)) {
                            while (eval_lt(input, 0u)) {
                                eval_add(input, modulus);
                            }
                        } else if (eval_msb(input) < 2u * eval_msb(modulus) + 1u) {
                            Backend_quadruple_1 t1(input);

                            eval_multiply(t1, m_barrett_mu);
                            custom_right_shift(t1, 2u * (1u + eval_msb(modulus)));
                            eval_multiply(t1, modulus);
                            eval_subtract(input, t1);

                            if (!eval_lt(input, modulus)) {
                                eval_subtract(input, modulus);
                            }
                        } else {
                            eval_modulus(input, modulus);
                        }
                        result = input;
                    }

                    template<typename Backend1,
                             typename = typename boost::enable_if_c<
                                 /// result should fit in the output parameter
                                 max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
                    constexpr void montgomery_reduce(Backend1 &result) const {

                        using default_ops::eval_add;
                        using default_ops::eval_bitwise_and;
                        using default_ops::eval_left_shift;
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply;
                        using default_ops::eval_subtract;

                        Backend_doubled_padded_limbs accum(result);
                        Backend_doubled_padded_limbs prod;

                        for (size_t i = 0; i < m_mod.backend().size(); ++i) {
                            eval_multiply(prod, m_mod.backend(),
                                          static_cast<double_limb_type>(static_cast<internal_limb_type>(
                                              custom_get_limb_value<internal_limb_type>(accum, i) *
                                              /// to prevent overflow error in constexpr
                                              static_cast<double_limb_type>(m_montgomery_p_dash))));
                            eval_left_shift(prod, i * limb_bits);
                            eval_add(accum, prod);
                        }
                        custom_right_shift(accum, m_mod.backend().size() * limb_bits);
                        if (!eval_lt(accum, m_mod.backend())) {
                            eval_subtract(accum, m_mod.backend());
                        }
                        if (m_mod.backend().size() < accum.size()) {
                            accum.resize(m_mod.backend().size(), m_mod.backend().size());
                        }
                        result = accum;
                    }

                    template<typename Backend1, typename Backend2,
                             /// result should fit in the output parameter
                             typename = typename boost::enable_if_c<max_precision<Backend1>::value >=
                                                                    max_precision<Backend>::value>::type>
                    constexpr void regular_add(Backend1 &result, const Backend2 &y) const {

                        using default_ops::eval_add;
                        using default_ops::eval_lt;
                        using default_ops::eval_subtract;

                        // TODO: maybe reduce input parameters
                        /// input parameters should be lesser than modulus
                        // BOOST_ASSERT(eval_lt(x, m_mod.backend()) && eval_lt(y, m_mod.backend()));

                        using T = typename policy_type::Backend_padded_limbs_u;
                        T tmp(result), modulus(m_mod.backend());
                        eval_add(tmp, y);
                        if (!eval_lt(tmp, modulus)) {
                            eval_subtract(tmp, modulus);
                        }
                        result = tmp;
                    }

                    template<typename Backend1, typename Backend2,
                             /// result should fit in the output parameter
                             typename = typename boost::enable_if_c<max_precision<Backend1>::value >=
                                                                    max_precision<Backend>::value>::type>
                    constexpr void regular_mul(Backend1 &result, const Backend2 &y) const {
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply;

                        // TODO: maybe reduce input parameters
                        /// input parameters should be lesser than modulus
                        // BOOST_ASSERT(eval_lt(x, m_mod.backend()) && eval_lt(y, m_mod.backend()));

                        Backend_doubled_limbs tmp(result);
                        eval_multiply(tmp, y);
                        barrett_reduce(result, tmp);
                    }
                    //
                    // WARNING: could be errors here due to trivial backend -- more tests needed
                    //
                    template<typename Backend1, typename Backend2,
                             /// result should fit in the output parameter
                             typename = typename boost::enable_if_c<max_precision<Backend1>::value >=
                                                                    max_precision<Backend>::value>::type>
                    constexpr void montgomery_mul(Backend1 &result, const Backend2 &y) const {
                        using default_ops::eval_bitwise_and;
                        using default_ops::eval_lt;
                        using default_ops::eval_subtract;

                        // TODO: maybe reduce input parameters
                        /// input parameters should be lesser than modulus
                        // BOOST_ASSERT(eval_lt(x, m_mod.backend()) && eval_lt(y, m_mod.backend()));

                        Backend_padded_limbs A(internal_limb_type(0u));
                        const size_t mod_size = m_mod.backend().size();
                        auto mod_last_limb = static_cast<internal_double_limb_type>(get_limb_value(m_mod.backend(), 0));
                        auto y_last_limb = get_limb_value(y, 0);

                        for (size_t i = 0; i < mod_size; i++) {
                            auto x_i = get_limb_value(result, i);
                            auto A_0 = A.limbs()[0];
                            internal_limb_type u_i = (A_0 + x_i * y_last_limb) * m_montgomery_p_dash;

                            // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
                            internal_limb_type k = 0;
                            internal_limb_type k2 = 0;

                            internal_double_limb_type z = static_cast<internal_double_limb_type>(y_last_limb) *
                                                              static_cast<internal_double_limb_type>(x_i) +
                                                          A_0 + k;
                            internal_double_limb_type z2 = mod_last_limb * static_cast<internal_double_limb_type>(u_i) +
                                                           static_cast<internal_limb_type>(z) + k2;
                            k = static_cast<internal_limb_type>(z >> std::numeric_limits<internal_limb_type>::digits);
                            k2 = static_cast<internal_limb_type>(z2 >> std::numeric_limits<internal_limb_type>::digits);

                            for (size_t j = 1; j < mod_size; ++j) {
                                internal_double_limb_type t =
                                    static_cast<internal_double_limb_type>(get_limb_value(y, j)) *
                                        static_cast<internal_double_limb_type>(x_i) +
                                    A.limbs()[j] + k;
                                internal_double_limb_type t2 =
                                    static_cast<internal_double_limb_type>(get_limb_value(m_mod.backend(), j)) *
                                        static_cast<internal_double_limb_type>(u_i) +
                                    static_cast<internal_limb_type>(t) + k2;
                                A.limbs()[j - 1] = static_cast<internal_limb_type>(t2);
                                k = static_cast<internal_limb_type>(t >>
                                                                    std::numeric_limits<internal_limb_type>::digits);
                                k2 = static_cast<internal_limb_type>(t2 >>
                                                                     std::numeric_limits<internal_limb_type>::digits);
                            }
                            internal_double_limb_type tmp =
                                static_cast<internal_double_limb_type>(
                                    custom_get_limb_value<internal_limb_type>(A, mod_size)) +
                                k + k2;
                            custom_set_limb_value<internal_limb_type>(A, mod_size - 1,
                                                                      static_cast<internal_limb_type>(tmp));
                            custom_set_limb_value<internal_limb_type>(
                                A, mod_size,
                                static_cast<internal_limb_type>(tmp >>
                                                                std::numeric_limits<internal_limb_type>::digits));
                        }
                        //
                        // recover correct size of backend content
                        //
                        adjust_backend_size(A, mod_size);

                        if (!eval_lt(A, m_mod.backend())) {
                            eval_subtract(A, m_mod.backend());
                        }
                        result = A;
                    }

                    template<typename Backend1, typename Backend2, typename Backend3,
                             /// result should fit in the output parameter
                             typename = typename boost::enable_if_c<max_precision<Backend1>::value >=
                                                                    max_precision<Backend>::value>::type>
                    constexpr void regular_exp(Backend1 &result, Backend2 &a, Backend3 exp) const {
                        using default_ops::eval_eq;
                        using default_ops::eval_is_zero;
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply;

                        // TODO: maybe reduce input parameter
                        /// input parameter should be lesser than modulus
                        // BOOST_ASSERT(eval_lt(a, m_mod.backend()));

                        if (eval_eq(exp, static_cast<internal_limb_type>(0u))) {
                            result = static_cast<internal_limb_type>(1u);
                            return;
                        }
                        if (eval_eq(m_mod.backend(), static_cast<internal_limb_type>(1u))) {
                            result = static_cast<internal_limb_type>(0u);
                            return;
                        }

                        Backend_doubled_limbs base(a), res(static_cast<internal_limb_type>(1u));

                        while (true) {
                            internal_limb_type lsb = exp.limbs()[0] & 1u;
                            custom_right_shift(exp, static_cast<internal_limb_type>(1u));
                            if (lsb) {
                                eval_multiply(res, base);
                                barrett_reduce(res);
                                if (eval_is_zero(exp)) {
                                    break;
                                }
                            }
                            eval_multiply(base, base);
                            barrett_reduce(base);
                        }
                        result = res;
                    }

                    template<typename Backend1, typename Backend2, typename Backend3,
                             /// result should fit in the output parameter
                             typename = typename boost::enable_if_c<max_precision<Backend1>::value >=
                                                                    max_precision<Backend>::value>::type>
                    constexpr void montgomery_exp(Backend1 &result, const Backend2 &a, Backend3 exp) const {
                        using default_ops::eval_eq;
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply;

                        // TODO: maybe reduce input parameter
                        /// input parameter should be lesser than modulus
                        // BOOST_ASSERT(eval_lt(a, m_mod.backend()));

                        Backend_doubled_limbs tmp(static_cast<internal_limb_type>(1u));
                        eval_multiply(tmp, m_montgomery_r2);
                        montgomery_reduce(tmp);
                        Backend R_mod_m(tmp);

                        Backend base(a);

                        if (eval_eq(exp, static_cast<internal_limb_type>(0u))) {
                            result = static_cast<internal_limb_type>(1u);
                            //
                            // TODO: restructure code
                            // adjust_modular
                            //
                            eval_multiply(result, m_montgomery_r2);
                            montgomery_reduce(result);
                            return;
                        }
                        if (eval_eq(m_mod.backend(), static_cast<internal_limb_type>(1u))) {
                            result = static_cast<internal_limb_type>(0u);
                            return;
                        }

                        while (true) {
                            internal_limb_type lsb = exp.limbs()[0] & 1u;
                            custom_right_shift(exp, static_cast<internal_limb_type>(1u));
                            if (lsb) {
                                montgomery_mul(R_mod_m, base);
                                if (eval_eq(exp, static_cast<internal_limb_type>(0u))) {
                                    break;
                                }
                            }
                            montgomery_mul(base, base);
                        }
                        result = R_mod_m;
                    }

                    constexpr void swap(modular_functions_fixed &o) {
                        m_mod.swap(o.get_mod());
                        m_barrett_mu.swap(o.get_mu());
                        m_montgomery_r2.swap(o.get_r2());

                        auto tmp_p_dash = m_montgomery_p_dash;
                        m_montgomery_p_dash = o.get_p_dash();
                        o.get_p_dash() = tmp_p_dash;
                    }

                    constexpr modular_functions_fixed &operator=(const modular_functions_fixed &o) {
                        modular_functions_fixed tmp(o);
                        swap(tmp);

                        return *this;
                    }

                    constexpr modular_functions_fixed &operator=(const number_type &m) {
                        initialize(m);

                        return *this;
                    }

                protected:
                    // TODO: replace number_type on backend type
                    number_type m_mod;
                    Backend_doubled_1 m_barrett_mu;
                    Backend m_montgomery_r2;
                    internal_limb_type m_montgomery_p_dash = 0;
                };

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP
