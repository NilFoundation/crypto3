//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_OPS_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_OPS_FIXED_PRECISION_HPP

#include <boost/multiprecision/modular/modular_policy_fixed.hpp>

#include <boost/mpl/if.hpp>

#include <type_traits>
#include <utility>

namespace boost {
namespace multiprecision {
namespace backends {

template <typename Backend>
class modular_ops;

//
// the function works correctly only with consistent backend objects,
// i.e. their limbs should not be manipulated directly
// as it breaks backend logic of size determination
// (or real size of such objects should be adjusted then)
//
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr typename mpl::if_c<
    is_trivial_cpp_int<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >::value,
    typename trivial_limb_type<MinBits>::type,
    limb_type>::type
get_limb_value(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void>& b, const std::size_t i)
{
   if (i < b.size())
   {
      return b.limbs()[i];
   }
   return 0;
}

// template <typename Backend>
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr bool check_modulus_constraints(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void>& m)
{
   using Backend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   typedef typename mpl::front<typename Backend::unsigned_types>::type ui_type;

   using default_ops::eval_lt;

   return !eval_lt(m, static_cast<ui_type>(0u));
}

// template <typename Backend>
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr bool check_montgomery_constraints(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void>& m)
{
   using Backend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   typedef typename mpl::front<typename Backend::unsigned_types>::type ui_type;

   using default_ops::eval_eq;
   using default_ops::eval_modulus;

   Backend tmp;
   eval_modulus(tmp, m, static_cast<ui_type>(2u));
   return !eval_eq(tmp, static_cast<ui_type>(0u));
}

// template <typename Backend>
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr bool check_montgomery_constraints(const modular_ops<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>& mo)
{
   return check_montgomery_constraints(mo.get_mod().backend());
}

template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class modular_ops<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >
{
 protected:
   typedef cpp_int_backend<MinBits, MinBits, SignType, Checked, void> TemplateBackend;
   typedef modular_ops<TemplateBackend>                               self_type;
 public:
   typedef modular_policy<TemplateBackend>                            policy_type;

 protected:
   typedef typename policy_type::internal_limb_type        internal_limb_type;
   typedef typename policy_type::internal_double_limb_type internal_double_limb_type;

   typedef typename policy_type::Backend                      Backend;
   typedef typename policy_type::Backend_doubled_1            Backend_doubled_1;
   typedef typename policy_type::Backend_quadruple_1          Backend_quadruple_1;
   typedef typename policy_type::Backend_padded_limbs         Backend_padded_limbs;
   typedef typename policy_type::Backend_doubled_limbs        Backend_doubled_limbs;
   typedef typename policy_type::Backend_doubled_padded_limbs Backend_doubled_padded_limbs;

   typedef typename policy_type::number_type         number_type;
   typedef typename policy_type::dbl_lmb_number_type dbl_lmb_number_type;

   constexpr static auto limb_bits = policy_type::limb_bits;

   constexpr void initialize_modulus(const number_type& m)
   {
      BOOST_ASSERT(check_modulus_constraints(m.backend()));

      get_mod() = m;
   }

   constexpr void initialize_barrett_params()
   {
      using default_ops::eval_bit_set;
      using default_ops::eval_divide;
      using default_ops::eval_msb;

      get_mu() = static_cast<internal_limb_type>(0u);

      eval_bit_set(get_mu(), 2u * (1u + eval_msb(get_mod().backend())));
      eval_divide(get_mu(), get_mod().backend());
   }

   constexpr void initialize_montgomery_params()
   {
      if (check_montgomery_constraints(get_mod().backend()))
      {
         find_const_variables();
         find_modulus_mask();
      }
   }

   constexpr internal_limb_type monty_inverse(internal_limb_type a)
   {
      BOOST_ASSERT(check_montgomery_constraints(get_mod().backend()));

      internal_limb_type b = 1;
      internal_limb_type r = 0;

      for (size_t i = 0; i != limb_bits; ++i)
      {
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

   constexpr void find_const_variables()
   {
      using default_ops::eval_bit_set;
      using default_ops::eval_gt;
      using default_ops::eval_multiply;

      BOOST_ASSERT(check_montgomery_constraints(get_mod().backend()) && check_modulus_constraints(get_mod().backend()));

      get_p_dash()  = monty_inverse(get_mod().backend().limbs()[0]);

      Backend_doubled_padded_limbs r;
      eval_bit_set(r, get_mod().backend().size() * limb_bits);
      eval_multiply(r, r);
      barrett_reduce(r);

      get_r2() = static_cast<Backend>(r);
   }

   constexpr void find_modulus_mask()
   {
      get_modulus_mask() = static_cast<internal_limb_type>(1u);
      eval_left_shift(get_modulus_mask(), get_mod().backend().size() * limb_bits);
      eval_subtract(get_modulus_mask(), static_cast<internal_limb_type>(1u));
   }

   constexpr void initialize(const number_type& m)
   {
      initialize_modulus(m);
      initialize_barrett_params();
      initialize_montgomery_params();
   }

 public:
   constexpr auto& get_mod() { return m_mod; }
   constexpr auto& get_mu() { return m_barrett_mu; }
   constexpr auto& get_r2() { return m_montgomery_r2; }
   constexpr auto& get_p_dash() { return m_montgomery_p_dash; }
   constexpr auto& get_modulus_mask() { return m_modulus_mask; }

   constexpr const auto& get_mod() const { return m_mod; }
   constexpr const auto& get_mu() const { return m_barrett_mu; }
   constexpr const auto& get_r2() const { return m_montgomery_r2; }
   constexpr const auto& get_p_dash() const { return m_montgomery_p_dash; }
   constexpr const auto& get_modulus_mask() const { return m_modulus_mask; }

   constexpr explicit modular_ops() {}

   constexpr explicit modular_ops(const number_type& m)
   {
      initialize(m);
   }

   constexpr explicit modular_ops(const self_type& o)
   {
      get_mod() = o.get_mod();

      get_mu() = o.get_mu();

      get_r2() = o.get_r2();
      get_p_dash() = o.get_p_dash();

      get_modulus_mask() = o.get_modulus_mask();
   }

   // template <typename BackendT>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1>
   constexpr void barrett_reduce(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result) const
   {
      using default_ops::eval_add;
      using default_ops::eval_eq;
      using default_ops::eval_lt;
      using default_ops::eval_msb;
      using default_ops::eval_multiply;
      using default_ops::eval_subtract;

      if (eval_lt(result, get_mod().backend()))
      {
         while (eval_lt(result, 0))
         {
            eval_add(result, get_mod().backend());
         }
      }
      else if (eval_msb(result) < 2 * eval_msb(get_mod().backend()) + 1u)
      {
         Backend_quadruple_1 t1(result);

         eval_multiply(t1, get_mu());
         eval_right_shift(t1, 2 * (1 + eval_msb(get_mod().backend())));
         eval_multiply(t1, get_mod().backend());
         eval_subtract(result, t1);

         // if (eval_lt(get_mod().backend(), result) || (eval_eq(result, get_mod().backend()) == 0))
         if (!eval_lt(result, get_mod().backend()))
         {
            eval_subtract(result, get_mod().backend());
         }
      }
      else
      {
         eval_modulus(result, get_mod().backend());
      }
   }

   // template <typename BackendT,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<BackendT>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1>
   constexpr void montgomery_reduce(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result) const
   {
      montgomery_reduce(result, result);
   }

   // template <typename Backend1, typename Backend2,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<Backend1>::value >= max_precision<Backend>::value &&
   //               /// input number should be represented by backend of appropriate size
   //               max_precision<Backend2>::value <= max_precision<Backend_doubled_limbs>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             typename = typename std::enable_if<
                 /// result should fit in the output parameter
                 MinBits1 >= max_precision<Backend>::value &&
                 /// input number should be represented by backend of appropriate size
                 max_precision<Backend_doubled_limbs>::value >= MinBits2>::type>
   constexpr void montgomery_reduce(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                    const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& input) const
   {
      using default_ops::eval_lt;
      using default_ops::eval_add;
      using default_ops::eval_subtract;
      using default_ops::eval_multiply;
      using default_ops::eval_left_shift;
      using default_ops::eval_right_shift;
      using default_ops::eval_bitwise_and;

      Backend_doubled_padded_limbs accum(input);
      Backend_doubled_padded_limbs prod;

      for (auto i = 0; i < get_mod().backend().size(); ++i)
      {
         eval_multiply(prod, get_mod().backend(), accum.limbs()[i] * get_p_dash());
         eval_left_shift(prod, i * limb_bits);
         eval_add(accum, prod);
      }

      eval_right_shift(accum, get_mod().backend().size() * limb_bits);

      if (!eval_lt(accum, get_mod().backend()))
      {
         eval_subtract(accum, get_mod().backend());
      }
      eval_bitwise_and(accum, m_modulus_mask);
      result = accum;
   }

   // template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
   //           unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2>
   // constexpr void regular_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
   //                            const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& y) const
   // {
   //    regular_mul(result, result, y);
   // }
   //
   // template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
   //           unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
   //           unsigned MinBits3, cpp_integer_type SignType3, cpp_int_check_type Checked3,
   //           /// result should fit in the output parameter
   //           typename = typename std::enable_if<MinBits1 >= max_precision<Backend>::value>::type>
   // constexpr void regular_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
   //                               const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& x,
   //                               const cpp_int_backend<MinBits3, MinBits3, SignType3, Checked3, void>& y) const
   // {
   //    using BackendT = cpp_int_backend<MinBits2 + MinBits3, MinBits2 + MinBits3, SignType1, Checked1, void>;
   //
   //    BackendT tmp;
   //    eval_multiply(tmp, x, y);
   //    barrett_reduce(tmp);
   //
   //    result = tmp;
   // }

   // template <typename Backend1, typename Backend2,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<Backend1>::value >= max_precision<Backend>::value &&
   //               /// multiplier should fit in input parameter type
   //               max_precision<Backend2>::value >= max_precision<Backend1>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2>
   constexpr void montgomery_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& y) const
   {
      montgomery_mul(result, result, y);
   }

   // template <typename Backend1, typename Backend2,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             unsigned MinBits3, cpp_integer_type SignType3, cpp_int_check_type Checked3,
             /// result should fit in the output parameter
             typename = typename std::enable_if<MinBits1 >= max_precision<Backend>::value>::type>
   constexpr void montgomery_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& x,
                                 const cpp_int_backend<MinBits3, MinBits3, SignType3, Checked3, void>& y) const
   {
      using default_ops::eval_lt;
      using default_ops::eval_subtract;
      using default_ops::eval_bitwise_and;

      // TODO: maybe reduce input parameters
      /// input parameters should be lesser than modulus
      BOOST_ASSERT(eval_lt(x, get_mod().backend()) && eval_lt(y, get_mod().backend()));

      Backend_padded_limbs A(internal_limb_type(0u));

      for (auto i = 0; i < get_mod().backend().size(); i++)
      {
         internal_limb_type u_i = (A.limbs()[0] + get_limb_value(x, i) * get_limb_value(y, 0)) * get_p_dash();

         // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
         internal_limb_type k  = 0;
         internal_limb_type k2 = 0;

         internal_double_limb_type z = static_cast<internal_double_limb_type>(get_limb_value(y, 0)) *
                                           static_cast<internal_double_limb_type>(get_limb_value(x, i)) +
                                       A.limbs()[0] + k;
         // TODO: maybe error here in static_cast<internal_limb_type>(z) if internal_double_limb_type is multiprecision::number
         internal_double_limb_type z2 = static_cast<internal_double_limb_type>(get_limb_value(get_mod().backend(), 0)) *
                                            static_cast<internal_double_limb_type>(u_i) +
                                        static_cast<internal_limb_type>(z) + k2;
         k  = z >> std::numeric_limits<internal_limb_type>::digits;
         k2 = z2 >> std::numeric_limits<internal_limb_type>::digits;

         for (auto j = 1; j < get_mod().backend().size(); ++j)
         {
            internal_double_limb_type t = static_cast<internal_double_limb_type>(get_limb_value(y, j)) *
                                              static_cast<internal_double_limb_type>(get_limb_value(x, i)) +
                                          A.limbs()[j] + k;
            // TODO: maybe error here in static_cast<internal_limb_type>(t) if internal_double_limb_type is multiprecision::number
            internal_double_limb_type t2 = static_cast<internal_double_limb_type>(get_limb_value(get_mod().backend(), j)) *
                                               static_cast<internal_double_limb_type>(u_i) +
                                           static_cast<internal_limb_type>(t) + k2;
            A.limbs()[j - 1] = t2;
            k                = t >> std::numeric_limits<internal_limb_type>::digits;
            k2               = t2 >> std::numeric_limits<internal_limb_type>::digits;
         }
         internal_double_limb_type tmp               = static_cast<internal_double_limb_type>(A.limbs()[get_mod().backend().size()]) + k + k2;
         A.limbs()[get_mod().backend().size() - 1] = tmp;
         A.limbs()[get_mod().backend().size()]     = tmp >> std::numeric_limits<internal_limb_type>::digits;
      }
      A.resize(get_mod().backend().size(), 1);

      if (!eval_lt(A, get_mod().backend()))
      {
         eval_subtract(A, get_mod().backend());
      }
      eval_bitwise_and(A, get_modulus_mask());
      result = A;
   }

   // template <typename Backend1, typename Backend2,
   //     typename = typename std::enable_if<
   //         /// result should fit in the output parameter
   //         max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             typename BackendT>
   constexpr void regular_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                              const BackendT& exp) const
   {
      regular_exp(result, result, exp);
   }

   // template <typename Backend1, typename Backend2, typename Backend3,
   //     typename = typename std::enable_if<
   //         /// result should fit in the output parameter
   //         max_precision<Backend1>::value >= max_precision<Backend>::value &&
   //         /// input number should fit modulus
   //         max_precision<Backend2>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             typename BackendT,
             /// result should fit in the output parameter
             typename = typename std::enable_if<MinBits1 >= max_precision<Backend>::value>::type>
   constexpr void regular_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                              const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& a,
                              BackendT exp) const
   {
      using default_ops::eval_eq;
      using default_ops::eval_lt;
      using default_ops::eval_multiply;
      using default_ops::eval_right_shift;

      // TODO: maybe reduce input parameter
      /// input parameter should be lesser than modulus
      BOOST_ASSERT(eval_lt(a, get_mod().backend()));

      // BackendT zero(static_cast<internal_limb_type>(0u));
      if (eval_eq(exp, static_cast<internal_limb_type>(0u)))
      {
         result = static_cast<internal_limb_type>(1u);
         return;
      }
      if (eval_eq(get_mod().backend(), static_cast<internal_limb_type>(1u)))
      {
         result = static_cast<internal_limb_type>(0u);
         return;
      }

      Backend_doubled_limbs base(a), res(static_cast<internal_limb_type>(1u));

      while (true)
      {
         internal_limb_type lsb = exp.limbs()[0] & 1u;
         eval_right_shift(exp, static_cast<internal_limb_type>(1u));
         if (lsb)
         {
            eval_multiply(res, base);
            barrett_reduce(res);
            if (eval_eq(exp, static_cast<internal_limb_type>(0u)))
            {
               break;
            }
         }
         eval_multiply(base, base);
         barrett_reduce(base);
      }
      result = res;
   }

   // template <typename Backend1, typename Backend2,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             typename BackendT>
   constexpr void montgomery_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 const BackendT& exp) const
   {
      montgomery_exp(result, result, exp);
   }

   // template <typename Backend1, typename Backend2, typename Backend3,
   //           typename = typename std::enable_if<
   //               /// result should fit in the output parameter
   //               max_precision<Backend1>::value >= max_precision<Backend>::value>::type>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             typename BackendT,
             /// result should fit in the output parameter
             typename = typename std::enable_if<MinBits1 >= max_precision<Backend>::value>::type>
   constexpr void montgomery_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& a,
                                 BackendT exp) const
   {
      using default_ops::eval_eq;
      using default_ops::eval_lt;
      using default_ops::eval_multiply;
      using default_ops::eval_right_shift;

      // TODO: maybe reduce input parameter
      /// input parameter should be lesser than modulus
      BOOST_ASSERT(eval_lt(a, get_mod().backend()));

      Backend_doubled_limbs tmp(static_cast<internal_limb_type>(1u));
      eval_multiply(tmp, get_r2());
      montgomery_reduce(tmp);
      Backend R_mod_m(tmp);

      Backend base(a);

      // BackendT zero(static_cast<internal_limb_type>(0u));
      if (eval_eq(exp, static_cast<internal_limb_type>(0u)))
      {
         result = static_cast<internal_limb_type>(1u);
         return;
      }
      if (eval_eq(get_mod().backend(), static_cast<internal_limb_type>(1u)))
      {
         result = static_cast<internal_limb_type>(0u);
         return;
      }

      while (true)
      {
         internal_limb_type lsb = exp.limbs()[0] & 1u;
         eval_right_shift(exp, static_cast<internal_limb_type>(1u));
         if (lsb)
         {
            montgomery_mul(R_mod_m, base);
            if (eval_eq(exp, static_cast<internal_limb_type>(0u)))
            {
               break;
            }
         }
         montgomery_mul(base, base);
      }
      result = R_mod_m;
   }

   constexpr void swap(self_type& o)
   {
      get_mod().swap(o.get_mod());

      get_mu().swap(o.get_mu());

      get_r2().swap(o.get_r2());
      std::swap(get_p_dash(), o.get_p_dash());

      get_modulus_mask().swap(o.get_modulus_mask());
   }

   constexpr self_type& operator=(const self_type& o)
   {
      self_type tmp(o);
      swap(tmp);

      return *this;
   }

   constexpr self_type& operator=(const number_type& m)
   {
      initialize(m);

      return *this;
   }

protected:
   // TODO: replace number_type on backend type
   number_type /*Backend*/ m_mod;

   /*dbl_lmb_number_type*/ Backend_doubled_1 m_barrett_mu;

   /*number_type*/ Backend m_montgomery_r2;
   internal_limb_type      m_montgomery_p_dash;

   Backend_padded_limbs m_modulus_mask;
};

}
}
} // namespace boost::multiprecision::backend

#endif // BOOST_MULTIPRECISION_MODULAR_OPS_FIXED_PRECISION_HPP
