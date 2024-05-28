//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP
#define CRYPTO3_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP

#include <boost/multiprecision/detail/number_base.hpp>
#include <nil/crypto3/multiprecision/modular/modular_policy_fixed.hpp>

#include <boost/mpl/if.hpp>

#include <type_traits>
#include <utility>

namespace boost {   
    namespace multiprecision {
        namespace backends {

            //
            // the function works correctly only with consistent backend objects,
            // i.e. their limbs should not be manipulated directly
            // as it breaks backend logic of size determination
            // (or real size of such objects should be adjusted then)
            //
            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename std::conditional<is_trivial_cpp_int_modular<Backend>::value,
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
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<!is_trivial_cpp_int_modular<Backend>::value, limb_type>::type
                custom_get_limb_value(const Backend &b, const std::size_t i) {
                return b.limbs()[i];
            }

            //
            // function works with trivial backend.
            // return value of logical limb as if trivial backend consists of several logical limbs.
            //
            template<typename internal_limb_type, typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<
                is_trivial_cpp_int_modular<Backend>::value &&
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
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<!is_trivial_cpp_int_modular<Backend>::value>::type
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
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<
                is_trivial_cpp_int_modular<Backend>::value &&
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

            // We will only implement this class for Backend = cpp_int_modular_backend<Bits>.
            // If any other backend is to be used please implement a specialization for each one.
            template<typename Backend>
            class modular_functions_fixed;

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR bool check_montgomery_constraints(const Backend &m) {
                // Check m % 2 == 0
                // It's important to have std::size_t on the next line,
                // otherwise a function from boost is called, which is not BOOST_MP_CXX14_CONSTEXPR on gcc.
                return eval_bit_test(m, std::size_t(0));
            }

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR bool check_montgomery_constraints(const modular_functions_fixed<Backend> &mo) {
                return check_montgomery_constraints(mo.get_mod());
            }

            //
            // a little trick to prevent error in BOOST_MP_CXX14_CONSTEXPR execution of eval_right_shift
            // due to non-BOOST_MP_CXX14_CONSTEXPR nature of right_shift_byte
            //
            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR void custom_right_shift(Backend &b, unsigned s) {
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

            // Specialization for cpp_int_modular_backend<Bits>. This is the only working specialization, if other
            // backends are needed those will need to be implemented.
            template<unsigned Bits>
            class modular_functions_fixed<cpp_int_modular_backend<Bits>> {
            protected:
                typedef cpp_int_modular_backend<Bits> Backend;

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

                // Modular adaptor must not know about the existance of class boost::mp::number.
                //typedef typename policy_type::number_type number_type;
                //typedef typename policy_type::dbl_lmb_number_type dbl_lmb_number_type;

                BOOST_MP_CXX14_CONSTEXPR static auto limbs_count = policy_type::limbs_count;
                BOOST_MP_CXX14_CONSTEXPR static auto limb_bits = policy_type::limb_bits;

                BOOST_MP_CXX14_CONSTEXPR void initialize_modulus(const Backend &m) {
                    m_mod = m;
                }

                BOOST_MP_CXX14_CONSTEXPR void initialize_barrett_params() {
                    m_barrett_mu = static_cast<limb_type>(0u);

                    size_t bit = 2u * (1u + eval_msb(m_mod));
                    eval_bit_set(m_barrett_mu, bit);

                    eval_divide(m_barrett_mu, m_mod);
                }

                BOOST_MP_CXX14_CONSTEXPR void initialize_montgomery_params() {
                    find_const_variables();
                }

                /*
                 * Compute -input^-1 mod 2^limb_bits. Throws an exception if input
                 * is even. If input is odd, then input and 2^n are relatively prime
                 * and an inverse exists.
                 */
                BOOST_MP_CXX14_CONSTEXPR internal_limb_type monty_inverse(const internal_limb_type &a) {

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

                BOOST_MP_CXX14_CONSTEXPR void find_const_variables() {
                    if (check_montgomery_constraints(m_mod)) {
                        m_montgomery_p_dash = monty_inverse(m_mod.limbs()[0]);

                        Backend_doubled_padded_limbs r;
                        eval_bit_set(r, 2 * m_mod.size() * limb_bits);
                        barrett_reduce(r);

                        // Here we are intentionally throwing away half of the bits of r, it's correct.
                        m_montgomery_r2 = static_cast<Backend>(r);
                    }

                    // Compute 2^Bits - Modulus, no matter if modulus is even or odd.
                    Backend_padded_limbs compliment = static_cast<limb_type>(1u), modulus = m_mod;
                    eval_left_shift(compliment, Bits);
                    eval_subtract(compliment, modulus);
                    m_mod_compliment = compliment; 
                }
 
                BOOST_MP_CXX14_CONSTEXPR void initialize(const Backend &m) {
                    initialize_modulus(m);
                    initialize_barrett_params();
                    initialize_montgomery_params();
                }

            public:
                BOOST_MP_CXX14_CONSTEXPR auto &get_mod() {
                    return m_mod;
                }
                BOOST_MP_CXX14_CONSTEXPR const auto &get_mod_compliment() const {
                    return m_mod_compliment;
                }
                BOOST_MP_CXX14_CONSTEXPR auto &get_mu() {
                    return m_barrett_mu;
                }
                BOOST_MP_CXX14_CONSTEXPR auto &get_r2() {
                    return m_montgomery_r2;
                }
                BOOST_MP_CXX14_CONSTEXPR auto &get_p_dash() {
                    return m_montgomery_p_dash;
                }

                BOOST_MP_CXX14_CONSTEXPR const auto &get_mod() const {
                    return m_mod;
                }
                BOOST_MP_CXX14_CONSTEXPR const auto &get_mu() const {
                    return m_barrett_mu;
                }
                BOOST_MP_CXX14_CONSTEXPR const auto &get_r2() const {
                    return m_montgomery_r2;
                }
                BOOST_MP_CXX14_CONSTEXPR auto get_p_dash() const {
                    return m_montgomery_p_dash;
                }

                BOOST_MP_CXX14_CONSTEXPR modular_functions_fixed() {
                }

                BOOST_MP_CXX14_CONSTEXPR modular_functions_fixed(const Backend &m) {
                    initialize(m);
                }

                BOOST_MP_CXX14_CONSTEXPR modular_functions_fixed(const modular_functions_fixed &o)
                    : m_mod(o.get_mod())
                    , m_mod_compliment(o.get_mod_compliment())
                    , m_barrett_mu(o.get_mu())
                    , m_montgomery_r2(o.get_r2())
                    , m_montgomery_p_dash(o.get_p_dash())
                {
                }

                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR void barrett_reduce(Backend1 &result) const {
                    barrett_reduce(result, result);
                }

                //
                // this overloaded barrett_reduce is intended to work with built-in integral types
                //
                template<typename Backend1, typename Backend2>
                BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<std::is_integral<Backend2>::value && std::is_unsigned<Backend2>::value>::type
                    barrett_reduce(Backend1 &result, Backend2 input) const {
                    using input_backend_type = typename std::conditional<
                        bool(sizeof(Backend2) * CHAR_BIT > Bits),
                        cpp_int_modular_backend<sizeof(Backend2) * CHAR_BIT>,
                        Backend>::type;

                    input_backend_type input_adjusted(input);
                    barrett_reduce(result, input_adjusted);
                }

                //
                // this overloaded barrett_reduce is intended to work with input Backend2 type of less precision
                // than modular Backend to satisfy constraints of core barrett_reduce overloading
                //
                template<typename Backend1, typename Backend2,
                         typename boost::enable_if_c<
                             boost::multiprecision::backends::max_precision<Backend2>::value < boost::multiprecision::backends::max_precision<Backend>::value, bool>::type = true> 
                BOOST_MP_CXX14_CONSTEXPR void barrett_reduce(Backend1 &result, const Backend2 &input) const {
                    Backend input_adjusted(input);
                    barrett_reduce(result, input_adjusted);
                }

                template<typename Backend1, typename Backend2,
                         typename = typename boost::enable_if_c<
                             /// result should fit in the output parameter
                             boost::multiprecision::backends::max_precision<Backend1>::value >= boost::multiprecision::backends::max_precision<Backend>::value &&
                             /// to prevent problems with trivial cpp_int
                             boost::multiprecision::backends::max_precision<Backend2>::value >= boost::multiprecision::backends::max_precision<Backend>::value>::type>
                BOOST_MP_CXX14_CONSTEXPR void barrett_reduce(Backend1 &result, Backend2 input) const {
                    //
                    // to prevent problems with trivial cpp_int
                    //
                    Backend2 modulus(m_mod);

                    if (eval_msb(input) < 2u * eval_msb(modulus) + 1u) {
                        Backend_quadruple_1 t1(input);

                        eval_multiply(t1, m_barrett_mu);
                        std::size_t shift_size = 2u * (1u + eval_msb(modulus));
                        custom_right_shift(t1, shift_size);
                        eval_multiply(t1, modulus);

                        // We do NOT allow subtracting a larger size number from a smaller one,
                        // we need to cast to Backend2 here.
                        eval_subtract(input, static_cast<Backend2>(t1));

                        if (!eval_lt(input, modulus)) {
                            eval_subtract(input, modulus);
                        }
                    } else {
                        eval_modulus(input, modulus);
                    }
                    result = input;
                }

                template<unsigned Bits1,
                         // result should fit in the output parameter
                         typename = typename boost::enable_if_c<Bits1 >= Bits>::type>
                BOOST_MP_CXX14_CONSTEXPR void montgomery_reduce(cpp_int_modular_backend<Bits1> &result) const {

                    Backend_doubled_padded_limbs accum(result);
                    Backend_doubled_padded_limbs prod;

                    for (size_t i = 0; i < m_mod.size(); ++i) {
                        internal_limb_type limb_accum = custom_get_limb_value<internal_limb_type>(accum, i);
                        double_limb_type mult_res = limb_accum *
                                          /// to prevent overflow error in constexpr
                                          static_cast<double_limb_type>(m_montgomery_p_dash);
                        internal_limb_type mult_res_limb = static_cast<internal_limb_type>(mult_res);

                        eval_multiply(prod, m_mod, mult_res_limb);
                        eval_left_shift(prod, i * limb_bits);
                        eval_add(accum, prod);
                    }
                    custom_right_shift(accum, m_mod.size() * limb_bits);
                    // We cannot use eval_subtract for numbers of difference sizes, so resizing m_mod.
                    Backend_doubled_padded_limbs large_mod = m_mod;
                    if (!eval_lt(accum, large_mod)) {
                        eval_subtract(accum, large_mod);
                    }
                    // Here only the bytes that fit in sizeof result will be copied, and that's intentional.
                    result = accum;
                }

                template<unsigned Bits1, unsigned Bits2,
                    // result should fit in the output parameter
                    typename = typename boost::enable_if_c<Bits1 >= Bits2>::type>
                BOOST_MP_CXX14_CONSTEXPR void regular_add(cpp_int_modular_backend<Bits1>& result,
                                           const cpp_int_modular_backend<Bits2>& y) const {
                    BOOST_ASSERT(eval_lt(result, m_mod) && eval_lt(y, m_mod));

                    eval_add(result, y);
                    // If we overflow and set the carry, we need to subtract the modulus, which is the same as adding
                    // 2 ^ Bits - Modulus to the remaining part of the number. After this we know for sure that the 
                    // result < Modulus, do not waste time on checking again.
                    if (result.has_carry()) {
                        eval_add(result, m_mod_compliment);
                        result.set_carry(false);
                    } else if (!eval_lt(result, m_mod))
                    {
                        eval_subtract(result, m_mod);
                    }
                }

                template<typename Backend1, typename Backend2,
                         /// result should fit in the output parameter
                         typename = typename boost::enable_if_c<boost::multiprecision::backends::max_precision<Backend1>::value >=
                                                                boost::multiprecision::backends::max_precision<Backend>::value>::type>
                BOOST_MP_CXX14_CONSTEXPR void regular_mul(Backend1 &result, const Backend2 &y) const {
                    Backend_doubled_limbs tmp(result);
                    eval_multiply(tmp, y);
                    barrett_reduce(result, tmp);
                }

                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR void montgomery_mul(Backend1 &result, const Backend1 &y) const {
                    return montgomery_mul_impl(result, y, std::integral_constant<bool, is_trivial_cpp_int_modular<Backend1>::value>());
                }

                //
                // WARNING: could be errors here due to trivial backend -- more tests needed
                // TODO(martun): optimize this function, it obviously does not need to be this long.
                //
                // A specialization for trivial cpp_int_modular types only.
                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR void montgomery_mul_impl(Backend1 &result, const Backend1 &y, std::integral_constant<bool, true> const&) const {
                    BOOST_ASSERT(eval_lt(result, m_mod) && eval_lt(y, m_mod));

                    Backend_padded_limbs A(internal_limb_type(0u));
                    const size_t mod_size = m_mod.size();
                    auto mod_last_limb = static_cast<internal_double_limb_type>(get_limb_value(m_mod, 0));
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
                                static_cast<internal_double_limb_type>(get_limb_value(m_mod, j)) *
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

                    if (!eval_lt(A, m_mod)) {
                        eval_subtract(A, m_mod);
                    }

                    result = A;
                }

                // A specialization for non-trivial cpp_int_modular types only.
                template<typename Backend1>
                BOOST_MP_CXX14_CONSTEXPR void montgomery_mul_impl(Backend1 &result, const Backend1 &y,
                        std::integral_constant<bool, false> const&) const {
                    BOOST_ASSERT(eval_lt(result, m_mod) && eval_lt(y, m_mod));

                    Backend A(internal_limb_type(0u));
                    const std::size_t mod_size = m_mod.size();
                    auto* mod_limbs = m_mod.limbs();
                    auto mod_last_limb = static_cast<internal_double_limb_type>(mod_limbs[0]);
                    auto y_last_limb = get_limb_value(y, 0);
                    auto* y_limbs = y.limbs();
                    auto* x_limbs = result.limbs();
                    auto* A_limbs = A.limbs();
                    internal_limb_type carry = 0; // This is the highest limb of 'A'.

                    internal_limb_type x_i = 0;
                    internal_limb_type A_0 = 0;
                    internal_limb_type u_i = 0;

                    // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
                    internal_limb_type k = 0;
                    internal_limb_type k2 = 0;

                    internal_double_limb_type z = 0;
                    internal_double_limb_type z2 = 0;

                    std::size_t i = 0;
                    while (i < mod_size) {
                        x_i = x_limbs[i];
                        A_0 = A_limbs[0];
                        u_i = (A_0 + x_i * y_last_limb) * m_montgomery_p_dash;

                        // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
                        k = 0;
                        k2 = 0;

                        z = static_cast<internal_double_limb_type>(y_last_limb) *
                                                          static_cast<internal_double_limb_type>(x_i) +
                                                      A_0 + k;
                        z2 = mod_last_limb * static_cast<internal_double_limb_type>(u_i) +
                                                       static_cast<internal_limb_type>(z) + k2;
                        k = static_cast<internal_limb_type>(z >> std::numeric_limits<internal_limb_type>::digits);
                        k2 = static_cast<internal_limb_type>(z2 >> std::numeric_limits<internal_limb_type>::digits);

                        std::size_t j = 1;

                        // We want to do this for every 3, because normally mod_size == 4.
                        internal_double_limb_type t = 0, t2 = 0;
                        for (; j + 3 <= mod_size; j += 3) {
                            // For j
                            t = static_cast<internal_double_limb_type>(y_limbs[j]) *
                                static_cast<internal_double_limb_type>(x_i) +
                                A_limbs[j] + k;
                            t2 = static_cast<internal_double_limb_type>(mod_limbs[j]) *
                                static_cast<internal_double_limb_type>(u_i) +
                                static_cast<internal_limb_type>(t) + k2;
                            A_limbs[j - 1] = static_cast<internal_limb_type>(t2);
                            k = static_cast<internal_limb_type>(t >> std::numeric_limits<internal_limb_type>::digits);
                            k2 = static_cast<internal_limb_type>(t2 >> std::numeric_limits<internal_limb_type>::digits);

                            // For j + 1
                            t = static_cast<internal_double_limb_type>(y_limbs[j + 1]) *
                                static_cast<internal_double_limb_type>(x_i) +
                                A_limbs[j + 1] + k;
                            t2 = static_cast<internal_double_limb_type>(mod_limbs[j + 1]) *
                                static_cast<internal_double_limb_type>(u_i) +
                                static_cast<internal_limb_type>(t) + k2;
                            A_limbs[j + 1 - 1] = static_cast<internal_limb_type>(t2);
                            k = static_cast<internal_limb_type>(t >> std::numeric_limits<internal_limb_type>::digits);
                            k2 = static_cast<internal_limb_type>(t2 >> std::numeric_limits<internal_limb_type>::digits);

                            // For j + 2
                            t = static_cast<internal_double_limb_type>(y_limbs[j + 2]) *
                                static_cast<internal_double_limb_type>(x_i) +
                                A_limbs[j + 2] + k;
                            t2 = static_cast<internal_double_limb_type>(mod_limbs[j + 2]) *
                                static_cast<internal_double_limb_type>(u_i) +
                                static_cast<internal_limb_type>(t) + k2;
                            A_limbs[j + 2 - 1] = static_cast<internal_limb_type>(t2);
                            k = static_cast<internal_limb_type>(t >> std::numeric_limits<internal_limb_type>::digits);
                            k2 = static_cast<internal_limb_type>(t2 >> std::numeric_limits<internal_limb_type>::digits);
                        }

                        for (; j < mod_size; ++j) {
                            t = static_cast<internal_double_limb_type>(y_limbs[j]) *
                                static_cast<internal_double_limb_type>(x_i) +
                                A_limbs[j] + k;
                            t2 = static_cast<internal_double_limb_type>(mod_limbs[j]) *
                                static_cast<internal_double_limb_type>(u_i) +
                                static_cast<internal_limb_type>(t) + k2;
                            A_limbs[j - 1] = static_cast<internal_limb_type>(t2);
                            k = static_cast<internal_limb_type>(t >> std::numeric_limits<internal_limb_type>::digits);
                            k2 = static_cast<internal_limb_type>(t2 >> std::numeric_limits<internal_limb_type>::digits);
                        }

                        internal_double_limb_type tmp =
                            static_cast<internal_double_limb_type>(carry) +
                            k + k2;
                        A_limbs[mod_size - 1] = static_cast<internal_limb_type>(tmp);
                        carry = static_cast<internal_limb_type>(
                            tmp >> std::numeric_limits<internal_limb_type>::digits);
                        ++i;
                    }

                    if (carry) {
                        // The value of A is actually A + 2 ^ Bits, so remove that 2 ^ Bits.
                        eval_add(A, m_mod_compliment);
                    } else if (!eval_lt(A, m_mod)) {
                        eval_subtract(A, m_mod);
                    }

                    result = A;
                }

                template<typename Backend1, typename Backend2, typename Backend3,
                         /// result should fit in the output parameter
                         typename = typename boost::enable_if_c<boost::multiprecision::backends::max_precision<Backend1>::value >=
                                                                boost::multiprecision::backends::max_precision<Backend>::value>::type>
                BOOST_MP_CXX14_CONSTEXPR void regular_exp(Backend1 &result, Backend2 &a, Backend3 exp) const {
                    BOOST_ASSERT(eval_lt(a, m_mod));

                    if (eval_eq(exp, static_cast<internal_limb_type>(0u))) {
                        result = static_cast<internal_limb_type>(1u);
                        return;
                    }
                    if (eval_eq(m_mod, static_cast<internal_limb_type>(1u))) {
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
                         typename = typename boost::enable_if_c<boost::multiprecision::backends::max_precision<Backend1>::value >=
                                                                boost::multiprecision::backends::max_precision<Backend>::value>::type>
                BOOST_MP_CXX14_CONSTEXPR void montgomery_exp(Backend1 &result, const Backend2 &a, Backend3 exp) const {
                    /// input parameter should be lesser than modulus
                    BOOST_ASSERT(eval_lt(a, m_mod));

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
                    if (eval_eq(m_mod, static_cast<internal_limb_type>(1u))) {
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

                BOOST_MP_CXX14_CONSTEXPR modular_functions_fixed &operator=(const modular_functions_fixed &o) {
                    m_mod = o.get_mod();
                    m_barrett_mu = o.get_mu();
                    m_montgomery_r2 = o.get_r2(); 
                    m_montgomery_p_dash = o.get_p_dash();
                    m_mod_compliment = o.get_mod_compliment();

                    return *this;
                }

                BOOST_MP_CXX14_CONSTEXPR modular_functions_fixed &operator=(const Backend &m) {
                    initialize(m);

                    return *this;
                }

            protected:
                Backend m_mod;
                // This is 2^Bits - m_mod, precomputed.
                Backend m_mod_compliment;
                Backend_doubled_1 m_barrett_mu;
                Backend m_montgomery_r2;
                internal_limb_type m_montgomery_p_dash = 0;
            };
        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif    // CRYPTO3_MULTIPRECISION_MODULAR_FUNCTIONS_FIXED_PRECISION_HPP
