//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP
#define BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP

#include <boost/container/vector.hpp>

#include <boost/type_traits/is_integral.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_int/cpp_int_config.hpp>
#include <nil/crypto3/multiprecision/modular/base_params.hpp>
#include <nil/crypto3/multiprecision/modular/barrett_params.hpp>

#include <type_traits>
#include <tuple>
#include <array>
#include <cstddef>    // std::size_t
#include <limits>
#include <string>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                /**
                 * Parameters for Montgomery Reduction
                 */
                template<typename Backend>
                class montgomery_params : public base_params<Backend> {
                    typedef number<Backend> number_type;

                protected:
                    template<typename Number>
                    inline void initialize_montgomery_params(const Number& p) {
                        this->initialize_base_params(p);
                        find_const_variables(p);
                    }

                    inline void initialize_montgomery_params(const montgomery_params<Backend>& p) {
                        this->initialize_base_params(p);
                        find_const_variables(p);
                    }

                    limb_type monty_inverse(limb_type a) {
                        if (a % 2 == 0) {
                            throw std::invalid_argument("Monty_inverse only valid for odd integers");
                        }

                        limb_type b = 1;
                        limb_type r = 0;

                        for (size_t i = 0; i != sizeof(limb_type) * CHAR_BIT; ++i) {
                            const limb_type bi = b % 2;
                            r >>= 1;
                            r += bi << (sizeof(limb_type) * CHAR_BIT - 1);

                            b -= a * bi;
                            b >>= 1;
                        }

                        // Now invert in addition space
                        r = (~static_cast<limb_type>(0) - r) + 1;

                        return r;
                    }

                    template<typename T>
                    void find_const_variables(const T& pp) {
                        number_type p = pp;
                        if (p <= 0 || !(p % 2)) {
                            return;
                        }

                        m_p_words = this->m_mod.backend().size();

                        m_p_dash = monty_inverse(this->m_mod.backend().limbs()[0]);

                        number_type r;

                        default_ops::eval_bit_set(r.backend(), m_p_words * sizeof(limb_type) * CHAR_BIT);

                        m_r2 = r * r;
                        barrett_params<Backend> barrettParams(this->m_mod);
                        barrettParams.barret_reduce(m_r2.backend());
                    }

                public:
                    montgomery_params() : base_params<Backend>() {
                    }

                    template<typename Number>
                    explicit montgomery_params(const Number& p) : base_params<Backend>(p) {
                        initialize_montgomery_params(p);
                    }

                    inline const number_type& r2() const {
                        return m_r2;
                    }

                    inline limb_type p_dash() const {
                        return m_p_dash;
                    }

                    inline size_t p_words() const {
                        return m_p_words;
                    }

                    template<class V>
                    montgomery_params& operator=(const V& v) {
                        initialize_montgomery_params(v);
                        return *this;
                    }

                    inline void montgomery_reduce(Backend& result) const {
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply_add;

                        typedef cpp_int_backend<sizeof(limb_type) * CHAR_BIT * 3, sizeof(limb_type) * CHAR_BIT * 3,
                                                unsigned_magnitude, unchecked, void>
                            cpp_three_int_backend;

                        const size_t p_size = m_p_words;
                        const limb_type p_dash = m_p_dash;
                        const size_t z_size = 2 * (p_words() + 1);

                        boost::container::vector<limb_type> z(
                            result.size(), 0);    // container::vector<limb_type, alloc> z(result.size(), 0);
                        for (size_t i = 0; i < result.size(); ++i) {
                            z[i] = result.limbs()[i];
                        }

                        if (result.size() < z_size) {
                            result.resize(z_size, z_size);
                            z.resize(z_size, 0);
                        }

                        cpp_three_int_backend w(z[0]);

                        result.limbs()[0] = w.limbs()[0] * p_dash;

                        eval_multiply_add(w, result.limbs()[0], this->m_mod.backend().limbs()[0]);
                        eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);

                        for (size_t i = 1; i != p_size; ++i) {
                            for (size_t j = 0; j < i; ++j) {
                                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[i - j]);
                            }

                            eval_add(w, z[i]);

                            result.limbs()[i] = w.limbs()[0] * p_dash;

                            eval_multiply_add(w, result.limbs()[i], this->m_mod.backend().limbs()[0]);

                            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
                        }

                        for (size_t i = 0; i != p_size; ++i) {
                            for (size_t j = i + 1; j != p_size; ++j) {
                                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[p_size + i - j]);
                            }

                            eval_add(w, z[p_size + i]);

                            result.limbs()[i] = w.limbs()[0];

                            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
                        }

                        eval_add(w, z[z_size - 1]);

                        result.limbs()[p_size] = w.limbs()[0];
                        result.limbs()[p_size + 1] = w.limbs()[1];

                        if (result.size() != p_size + 1) {
                            result.resize(p_size + 1, p_size + 1);
                        }
                        result.normalize();
                    }

                protected:
                    number_type m_r2;
                    limb_type m_p_dash;
                    size_t m_p_words;
                };

                // // fixed precision montgomery params type which supports compile-time execution
                // template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                // class montgomery_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
                //     : public base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
                // {
                //  protected:
                //    typedef base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>> base_type;
                //    typedef typename base_type::policy_type policy_type;
                //
                //    typedef typename policy_type::internal_limb_type internal_limb_type;
                //    typedef typename policy_type::internal_double_limb_type internal_double_limb_type;
                //    typedef typename policy_type::Backend Backend;
                //    typedef typename policy_type::Backend_padded_limbs Backend_padded_limbs;
                //    typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                //    typedef typename policy_type::Backend_doubled_padded_limbs Backend_doubled_padded_limbs;
                //    typedef typename policy_type::number_type number_type;
                //
                //    constexpr static auto limbs_count = policy_type::limbs_count;
                //    constexpr static auto limb_bits = policy_type::limb_bits;
                //
                //    constexpr void initialize_montgomery_params(const number_type& p)
                //    {
                //       this->initialize_base_params(p);
                //       find_const_variables(p);
                //       find_modulus_mask();
                //    }
                //
                //    constexpr internal_limb_type monty_inverse(internal_limb_type a)
                //    {
                //       if (a % 2 == 0)
                //       {
                //          throw std::invalid_argument("Monty_inverse only valid for odd integers");
                //       }
                //
                //       internal_limb_type b = 1;
                //       internal_limb_type r = 0;
                //
                //       for (size_t i = 0; i != limb_bits; ++i)
                //       {
                //          const internal_limb_type bi = b % 2;
                //          r >>= 1;
                //          r += bi << (limb_bits - 1);
                //
                //          b -= a * bi;
                //          b >>= 1;
                //       }
                //
                //       // Now invert in addition space
                //       r = (~static_cast<internal_limb_type>(0) - r) + 1;
                //
                //       return r;
                //    }
                //
                //    constexpr void find_const_variables(const number_type& pp)
                //    {
                //       using padded_dbl_number_type = number<Backend_doubled_padded_limbs>;
                //
                //       number_type p = pp;
                //       if (p <= 0 || !(p % 2))
                //       {
                //          return;
                //       }
                //
                //       m_p_words = this->m_mod.backend().size();
                //
                //       m_p_dash = monty_inverse(this->m_mod.backend().limbs()[0]);
                //
                //       padded_dbl_number_type r;
                //
                //       default_ops::eval_bit_set(r.backend(), m_p_words * limb_bits);
                //
                //       r = r * r;
                //       barrett_params<Backend> barrettParams(this->m_mod);
                //       barrettParams.barret_reduce(r.backend());
                //       m_r2 = static_cast<Backend>(r.backend());
                //    }
                //
                //    constexpr void find_modulus_mask()
                //    {
                //       m_modulus_mask = static_cast<internal_limb_type>(1u);
                //       eval_left_shift(m_modulus_mask, this->m_mod.backend().size() * limb_bits);
                //       eval_subtract(m_modulus_mask, static_cast<internal_limb_type>(1u));
                //    }
                //
                //  public:
                //    constexpr montgomery_params()
                //        : base_type(), m_p_dash(), m_p_words(), m_modulus_mask() {}
                //
                //    constexpr explicit montgomery_params(const number_type& p)
                //        : base_type(p), m_p_dash(), m_p_words(), m_modulus_mask()
                //    {
                //       initialize_montgomery_params(p);
                //    }
                //
                //    constexpr const auto& r2() const { return m_r2; }
                //
                //    constexpr auto p_dash() const { return m_p_dash; }
                //
                //    constexpr auto p_words() const { return m_p_words; }
                //
                //    constexpr const auto& modulus_mask() const { return m_modulus_mask; }
                //
                //    constexpr montgomery_params& operator=(const number_type& p)
                //    {
                //       initialize_montgomery_params(p);
                //       return *this;
                //    }
                //
                //    template<typename BackendT,
                //        typename = typename boost::enable_if<
                //            /// result should fit in the output parameter
                //            max_precision<BackendT>::value >= max_precision<Backend>::value>::type>
                //    constexpr void montgomery_reduce(BackendT& result) const
                //    {
                //       BackendT input(result);
                //       montgomery_reduce(result, input);
                //    }
                //
                //    template<typename Backend1, typename Backend2,
                //        typename = typename boost::enable_if<
                //            /// result should fit in the output parameter
                //            max_precision<Backend1>::value >= max_precision<Backend>::value &&
                //            /// input number should be represented by backend of appropriate size
                //            max_precision<Backend2>::value <= max_precision<Backend_doubled_limbs>::value>::type>
                //    constexpr void montgomery_reduce(Backend1& result, const Backend2& input) const
                //    {
                //       Backend_doubled_padded_limbs accum(input);
                //       Backend_doubled_padded_limbs prod;
                //
                //       for (auto i = 0; i < this->m_mod.backend().size(); ++i)
                //       {
                //          eval_multiply(prod, this->m_mod.backend(), accum.limbs()[i] * p_dash());
                //          eval_left_shift(prod, i * limb_bits);
                //          eval_add(accum, prod);
                //       }
                //
                //       eval_right_shift(accum, this->m_mod.backend().size() * limb_bits);
                //
                //       if (accum.compare(this->m_mod.backend()) >= 0)
                //       {
                //          eval_subtract(accum, this->m_mod.backend());
                //       }
                //       eval_bitwise_and(accum, m_modulus_mask);
                //       result = accum;
                //    }
                //
                //    template<typename Backend1, typename Backend2,
                //        typename = typename boost::enable_if<
                //            /// result should fit in the output parameter
                //            max_precision<Backend1>::value >= max_precision<Backend>::value &&
                //            /// multiplier should fit in input parameter type
                //            max_precision<Backend2>::value >= max_precision<Backend1>::value>::type>
                //    constexpr void montgomery_mul(Backend1& result, const Backend2& y) const
                //    {
                //       Backend2 x(result);
                //       montgomery_mul(result, x, y);
                //    }
                //
                //    template<typename Backend1, typename Backend2,
                //             typename = typename boost::enable_if<
                //                 /// result should fit in the output parameter
                //                 max_precision<Backend1>::value >= max_precision<Backend>::value &&
                //                 /// multipliers should consist of the same number of limbs as modulus
                //                 max_precision<Backend2>::value >= max_precision<Backend>::value>::type>
                //    constexpr void montgomery_mul(Backend1& result, const Backend2& x, const Backend2& y) const
                //    {
                //       using default_ops::eval_lt;
                //
                //       /// input parameters should be lesser than modulus
                //       BOOST_ASSERT(eval_lt(x, this->m_mod.backend()) && eval_lt(y, this->m_mod.backend()));
                //
                //       Backend_padded_limbs A(internal_limb_type(0u));
                //
                //       for (auto i = 0; i < this->m_mod.backend().size(); i++)
                //       {
                //          internal_limb_type u_i = (A.limbs()[0] + get_limb_value(x, i) * get_limb_value(y, 0)) *
                //          p_dash();
                //
                //          // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
                //          internal_limb_type k = 0;
                //          internal_limb_type k2 = 0;
                //
                //          internal_double_limb_type z = static_cast<internal_double_limb_type>(get_limb_value(y, 0)) *
                //                                        static_cast<internal_double_limb_type>(get_limb_value(x, i)) +
                //                                        A.limbs()[0] + k;
                //          // TODO: maybe error here in static_cast<internal_limb_type>(z) if internal_double_limb_type
                //          is nil::crypto3::multiprecision::number internal_double_limb_type z2 =
                //          static_cast<internal_double_limb_type>(get_limb_value(this->m_mod.backend(), 0)) *
                //                                         static_cast<internal_double_limb_type>(u_i) +
                //                                         static_cast<internal_limb_type>(z) + k2;
                //          k = z >> std::numeric_limits<internal_limb_type>::digits;
                //          k2 = z2 >> std::numeric_limits<internal_limb_type>::digits;
                //
                //          for (auto j = 1; j < this->m_mod.backend().size(); ++j)
                //          {
                //             internal_double_limb_type t = static_cast<internal_double_limb_type>(get_limb_value(y,
                //             j)) *
                //                                           static_cast<internal_double_limb_type>(get_limb_value(x,
                //                                           i)) + A.limbs()[j] + k;
                //             // TODO: maybe error here in static_cast<internal_limb_type>(t) if
                //             internal_double_limb_type is nil::crypto3::multiprecision::number
                //             internal_double_limb_type t2 =
                //             static_cast<internal_double_limb_type>(get_limb_value(this->m_mod.backend(), j)) *
                //                                            static_cast<internal_double_limb_type>(u_i) +
                //                                            static_cast<internal_limb_type>(t) + k2;
                //             A.limbs()[j-1] = t2;
                //             k = t >> std::numeric_limits<internal_limb_type>::digits;
                //             k2 = t2 >> std::numeric_limits<internal_limb_type>::digits;
                //          }
                //          internal_double_limb_type tmp =
                //          static_cast<internal_double_limb_type>(A.limbs()[this->m_mod.backend().size()]) + k + k2;
                //          A.limbs()[this->m_mod.backend().size()-1] = tmp;
                //          A.limbs()[this->m_mod.backend().size()] = tmp >>
                //          std::numeric_limits<internal_limb_type>::digits;
                //       }
                //       A.resize(this->m_mod.backend().size(), 1);
                //
                //       if (A.compare(this->m_mod.backend()) >= 0)
                //       {
                //          eval_subtract(A, this->m_mod.backend());
                //       }
                //       eval_bitwise_and(A, m_modulus_mask);
                //       result = A;
                //    }
                //
                //    // TODO: replace in modular_params - need to refactor modular_adaptor structure
                //    template<typename Backend1, typename Backend2,
                //        typename = typename boost::enable_if<
                //            /// result should fit in the output parameter
                //            max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
                //    constexpr void mont_exp(Backend1& result, const Backend2& exp) const
                //    {
                //       Backend1 a(result);
                //       mont_exp(result, a, exp);
                //    }
                //
                //    // TODO: replace in modular_params - need to refactor modular_adaptor structure
                //    template<typename Backend1, typename Backend2, typename Backend3,
                //             typename = typename boost::enable_if<
                //                 /// result should fit in the output parameter
                //                 max_precision<Backend1>::value >= max_precision<Backend>::value &&
                //                 /// input number should fit modulus
                //                 max_precision<Backend2>::value >= max_precision<Backend>::value>::type>
                //    constexpr void mont_exp(Backend1& result, const Backend2& a, Backend3 exp) const
                //    {
                //       using default_ops::eval_eq;
                //       using default_ops::eval_right_shift;
                //       using default_ops::eval_left_shift;
                //       using default_ops::eval_modulus;
                //
                //       Backend_doubled_limbs tmp(static_cast<internal_limb_type>(1u));
                //       eval_multiply(tmp, r2().backend());
                //       montgomery_reduce(tmp);
                //       Backend R_mod_m(tmp);
                //
                //       Backend base(a);
                //
                //       Backend3 zero(static_cast<internal_limb_type>(0u));
                //       if (eval_eq(exp, zero))
                //       {
                //          result = static_cast<internal_limb_type>(1u);
                //          return;
                //       }
                //       if (eval_eq(this->m_mod.backend(), static_cast<internal_limb_type>(1u)))
                //       {
                //          result = static_cast<internal_limb_type>(0u);
                //          return;
                //       }
                //
                //       while (true)
                //       {
                //          internal_limb_type lsb = exp.limbs()[0] & 1u;
                //          eval_right_shift(exp, static_cast<internal_limb_type>(1u));
                //          if (lsb)
                //          {
                //             montgomery_mul(R_mod_m, base);
                //             if (eval_eq(exp, zero))
                //             {
                //                break;
                //             }
                //          }
                //          montgomery_mul(base, base);
                //       }
                //       result = R_mod_m;
                //    }
                //
                //  protected:
                //    number_type m_r2;
                //    internal_limb_type m_p_dash;
                //    size_t m_p_words;
                //    Backend_padded_limbs m_modulus_mask;
                // };
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
