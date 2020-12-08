//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP

#include <boost/multiprecision/modular/modular_params_fixed.hpp>

namespace boost {
namespace multiprecision {
namespace backends {

template <typename Backend>
class modular_adaptor;

// fixed precision modular backend which supports compile-time execution
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >
{
 protected:
   typedef cpp_int_backend<MinBits, MinBits, SignType, Checked, void> TemplateBackend;
   typedef modular_adaptor<TemplateBackend>                           self_type;

 public:
   typedef modular_params<TemplateBackend> modulus_type;

 protected:
   typedef typename modulus_type::policy_type          policy_type;
   typedef typename policy_type::Backend               Backend;
   typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
   typedef typename policy_type::number_type           number_type;

 public:
   typedef Backend_doubled_limbs value_type;

   typedef typename Backend::signed_types   signed_types;
   typedef typename Backend::unsigned_types unsigned_types;

   constexpr value_type& base_data() { return m_base; }
   constexpr const value_type& base_data() const { return m_base; }
   constexpr modulus_type& mod_data() { return m_mod; }
   constexpr const modulus_type& mod_data() const { return m_mod; }

   constexpr modular_adaptor() {}

   constexpr modular_adaptor(const self_type& o)
       : m_base(o.base_data()), m_mod(o.mod_data())
   {}

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
   constexpr modular_adaptor(self_type&& o)
       : m_base(std::move(o.base_data())), m_mod(std::move(o.mod_data()))
   {}
#endif

   template <typename T1, typename T2>
   constexpr modular_adaptor(const T1& b, const T2& m) : m_base(b), m_mod(m)
   {
      mod_data().adjust_modular(base_data());
   }

   template <typename T>
   constexpr modular_adaptor(const T& m) : m_base(static_cast<typename mpl::front<unsigned_types>::type>(0u)), m_mod(m)
   {
      mod_data().adjust_modular(base_data());
   }

   // TODO: check correctness of the method
   self_type& operator=(const char* s)
   {
      // TODO: why default modulus value equals 0
      typedef typename mpl::front<unsigned_types>::type ui_type;
      ui_type                                           zero = 0u;

      using default_ops::eval_fpclassify;

      if (s && (*s == '('))
      {
         std::string part;
         const char* p = ++s;
         while (*p && (*p != ',') && (*p != ')'))
            ++p;
         part.assign(s, p);
         if (!part.empty())
            m_base() = part.c_str();
         else
            m_base() = zero;
         s = p;
         if (*p && (*p != ')'))
         {
            ++p;
            while (*p && (*p != ')'))
               ++p;
            part.assign(s + 1, p);
         }
         else
            part.erase();
         if (!part.empty())
            m_mod() = part.c_str();
         else
            m_mod() = zero;
      }
      else
      {
         base_data() = s;
         m_mod()     = zero;
      }
      return *this;
   }

   constexpr int compare(const self_type& o) const
   {
      //
      // modulus values should be the same
      //
      BOOST_ASSERT(!mod_data().compare(o.mod_data()));

      value_type tmp1 = base_data();
      value_type tmp2 = o.base_data();
      mod_data().adjust_regular(tmp1, base_data());
      mod_data().adjust_regular(tmp2, o.base_data());
      return tmp1.compare(tmp2);
   }

   template <typename T>
   constexpr int compare(const T& a) const
   {
      self_type tmp(a, mod_data());
      return compare(tmp);
   }

   constexpr void swap(self_type& o)
   {
      base_data().swap(o.base_data());
      // TODO: add swap to modulus_type
      mod_data().swap(o.mod_data());
   }

   constexpr self_type& operator=(const self_type& o)
   {
      self_type tmp(o);
      swap(tmp);

      return *this;
   }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
   constexpr self_type& operator=(self_type&& o) BOOST_NOEXCEPT
   {
      self_type tmp(o);
      swap(tmp);

      return *this;
   }
#endif

   inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const
   {
      value_type tmp;
      mod_data().adjust_regular(tmp, base_data());
      return tmp.str(dig, f);
   }

   constexpr void negate()
   {
      base_data().negate();
      eval_add(base_data(), mod_data().get_mod().backend());
   }

   // TODO: for what purpose implicit conversion to number is necessary
   template <typename BackendT, expression_template_option ExpressionTemplates>
   constexpr operator number<BackendT, ExpressionTemplates>()
   {
      return static_cast<BackendT>(base_data());
   };

 protected:
   value_type   m_base;
   modulus_type m_mod;
};

// template <class Result, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_convert_to(Result* result, const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& val)
// {
//    using default_ops::eval_convert_to;
//    eval_convert_to(result, val.base_data());
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, class T>
// constexpr typename enable_if<is_arithmetic<T>, bool>::type
// eval_eq(const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& a,
//         const T&                                                                            b)
// {
//    return a.compare(b) == 0;
// }
//
// // template <class Backend, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// // constexpr void eval_redc(Backend& result,
// //                          const modular_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>& mod)
// // {
// //    mod.reduce(result);
// //    eval_modulus(result, mod.get_mod());
// // }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_add(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                         const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& o)
// {
//    using default_ops::eval_lt;
//
//    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
//
//    eval_add(result.base_data(), o.base_data());
//    if (!eval_lt(result.base_data(), result.mod_data().get_mod()))
//    {
//       eval_subtract(result.base_data(), result.mod_data().get_mod().backend());
//    }
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_subtract(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                              const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& o)
// {
//    using TemplateBackend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
//    typedef typename mpl::front<typename TemplateBackend::unsigned_types>::type ui_type;
//
//    using default_ops::eval_lt;
//
//    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
//
//    eval_subtract(result.base_data(), o.base_data());
//    if (eval_lt(result.base_data(), static_cast<ui_type>(0u)))
//    {
//       eval_add(result.base_data(), result.mod_data().get_mod().backend());
//    }
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_multiply(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                              const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& o)
// {
//    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
//
//    result.mod_data().mod_mul(result.base_data(), o.base_data());
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_divide(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                            const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& o)
// {
//    using TemplateBackend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
//
//    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
//
//    typename modular_adaptor<TemplateBackend>::value_type tmp1, tmp2;
//    result.mod_data().adjust_regular(tmp1, result.base_data());
//    result.mod_data().adjust_regular(tmp2, o.base_data());
//    eval_divide(tmp1, tmp2);
//    result.base_data() = tmp1;
//    result.mod_data().adjust_modular(result.base_data());
//    // result.mod_data().adjust_regular(tmp2, result.base_data());
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_modulus(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                             const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& o)
// {
//    using TemplateBackend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
//
//    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
//
//    typename modular_adaptor<TemplateBackend>::value_type tmp1, tmp2;
//    result.mod_data().adjust_regular(tmp1, result.base_data());
//    result.mod_data().adjust_regular(tmp2, o.base_data());
//    eval_modulus(tmp1, tmp2);
//    result.base_data() = tmp1;
//    result.mod_data().adjust_modular(result.base_data());
//    // result.mod_data().adjust_regular(tmp2, result.base_data());
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr bool eval_is_zero(const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& val)
// {
//    using default_ops::eval_is_zero;
//    return eval_is_zero(val.base_data());
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr int eval_get_sign(const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& val)
// {
//    using TemplateBackend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
//    typedef typename mpl::front<typename TemplateBackend::unsigned_types>::type ui_type;
//    using default_ops::eval_lt;
//
//    BOOST_ASSERT(!eval_lt(val.base_data(), static_cast<ui_type>(0u)));
//
//    return 1;
// }
//
// template <class Result, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr typename disable_if_c<boost::is_complex<Result>::value>::type
// eval_convert_to(Result*                                                                             result,
//                 const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& val)
// {
//    using default_ops::eval_convert_to;
//    eval_convert_to(result, val.base_data());
// }
//
// template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
//           unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
//           unsigned MinBits3, cpp_integer_type SignType3, cpp_int_check_type Checked3>
// constexpr void assign_components(modular_adaptor<cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void> >& result,
//                                  const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>&             a,
//                                  const cpp_int_backend<MinBits3, MinBits3, SignType3, Checked3, void>&             b)
// {
//    result.mod_data() = b;
//    result.mod_data().adjust_modular(result.base_data(), a);
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_sqrt(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                          const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& val)
// {
//    eval_sqrt(result.base_data(), val.base_data());
// }
//
// template <class Backend>
// constexpr void eval_abs(modular_adaptor<Backend>& result, const modular_adaptor<Backend>& val)
// {
//    result = val;
// }
//
// size_t window_bits(size_t exp_bits)
// {
//    BOOST_STATIC_CONSTEXPR size_t wsize_count           = 6;
//    BOOST_STATIC_CONSTEXPR size_t wsize[wsize_count][2] = {
//        {1434, 7},
//        {539, 6},
//        {197, 4},
//        {70, 3},
//        {17, 2},
//        {0, 0}};
//
//    size_t window_bits = 1;
//
//    size_t j = wsize_count - 1;
//    while (wsize[j][0] > exp_bits)
//    {
//       --j;
//    }
//    window_bits += wsize[j][1];
//
//    return window_bits;
// };
//
// template <class Backend>
// inline void find_modular_pow(modular_adaptor<Backend>&       result,
//                              const modular_adaptor<Backend>& b,
//                              const Backend&                  exp)
// {
//    using default_ops::eval_bit_set;
//    using default_ops::eval_decrement;
//    using default_ops::eval_multiply;
//    using default_ops::eval_convert_to;
//
//    typedef number<modular_adaptor<Backend> > modular_type;
//    modular_params<Backend>                   mod = b.mod_data();
//    size_t                                    m_window_bits;
//    unsigned long                             cur_exp_index;
//    size_t                                    exp_bits = eval_msb(exp);
//    m_window_bits                                      = window_bits(exp_bits + 1);
//
//    std::vector<modular_type> m_g(1U << m_window_bits);
//    modular_type*             p_g = m_g.data();
//    modular_type              x(1, mod);
//    Backend                   nibble = exp;
//    Backend                   mask;
//    eval_bit_set(mask, m_window_bits);
//    eval_decrement(mask);
//    *p_g = x;
//    ++p_g;
//    *p_g = b;
//    ++p_g;
//    for (size_t i = 2; i < (1U << m_window_bits); i++)
//    {
//       eval_multiply((*p_g).backend(), m_g[i - 1].backend(), b);
//       ++p_g;
//    }
//    size_t              exp_nibbles = (exp_bits + 1 + m_window_bits - 1) / m_window_bits;
//    std::vector<size_t> exp_index;
//
//    for (size_t i = 0; i < exp_nibbles; ++i)
//    {
//       Backend tmp = nibble;
//       eval_bitwise_and(tmp, mask);
//       eval_convert_to(&cur_exp_index, tmp);
//       eval_right_shift(nibble, m_window_bits);
//       exp_index.push_back(cur_exp_index);
//    }
//
//    x = x * m_g[exp_index[exp_nibbles - 1]];
//    for (size_t i = exp_nibbles - 1; i > 0; --i)
//    {
//
//       for (size_t j = 0; j != m_window_bits; ++j)
//       {
//          x = x * x;
//       }
//
//       x = x * m_g[exp_index[i - 1]];
//    }
//    result = x.backend();
// }
//
// template <class Backend>
// constexpr void eval_pow(modular_adaptor<Backend>&       result,
//                         const modular_adaptor<Backend>& b,
//                         const modular_adaptor<Backend>& e)
// {
//    typename modular_adaptor<Backend>::value_type exp;
//    e.mod_data().adjust_regular(exp, e.base_data());
//    find_modular_pow(result, b, exp);
// }
//
// template <class Backend1, typename Backend2>
// constexpr void eval_pow(modular_adaptor<Backend1>&       result,
//                         const modular_adaptor<Backend1>& b,
//                         const Backend2&                  e)
// {
//    find_modular_pow(result, b, e);
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend>
// constexpr void eval_pow(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                         const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& b,
//                         const Backend&                                                                      e)
// {
//    // BOOST_ASSERT(result.mod_data().get_mod() == b.mod_data().get_mod());
//    result.mod_data() = b.mod_data();
//    b.mod_data().mod_exp(result.base_data(), b.base_data(), e);
// }
//
// template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
// constexpr void eval_pow(modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >&       result,
//                         const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& b,
//                         const modular_adaptor<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >& e)
// {
//    using Backend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
//
//    typename modular_adaptor<Backend>::value_type exp;
//    e.mod_data().adjust_regular(exp, e.base_data());
//    eval_pow(result, b, exp);
// }
//
// template <class Backend, class UI>
// constexpr void eval_left_shift(modular_adaptor<Backend>& t, UI i)
// {
//    using default_ops::eval_left_shift;
//    typename modular_adaptor<Backend>::value_type tmp;
//    t.mod_data().adjust_regular(tmp, t.base_data());
//    eval_left_shift(tmp, i);
//    t.base_data() = tmp;
//    t.mod_data().adjust_modular(t.base_data());
// }
//
// template <class Backend, class UI>
// constexpr void eval_right_shift(modular_adaptor<Backend>& t, UI i)
// {
//    using default_ops::eval_right_shift;
//    typename modular_adaptor<Backend>::value_type tmp;
//    t.mod_data().adjust_regular(tmp, t.base_data());
//    eval_right_shift(tmp, i);
//    t.base_data() = tmp;
//    t.mod_data().adjust_modular(t.base_data());
// }
//
// template <class Backend, class UI>
// constexpr void eval_left_shift(modular_adaptor<Backend>& t, const modular_adaptor<Backend>& v, UI i)
// {
//    using default_ops::eval_left_shift;
//    typename modular_adaptor<Backend>::value_type tmp1, tmp2;
//    t.mod_data().adjust_regular(tmp1, t.base_data());
//    t.mod_data().adjust_regular(tmp2, v.base_data());
//    eval_left_shift(tmp1, tmp2, static_cast<unsigned long>(i));
//    t.base_data() = tmp1;
//    t.mod_data().adjust_modular(t.base_data());
// }
//
// template <class Backend, class UI>
// constexpr void eval_right_shift(modular_adaptor<Backend>& t, const modular_adaptor<Backend>& v, UI i)
// {
//    using default_ops::eval_right_shift;
//    typename modular_adaptor<Backend>::value_type tmp1, tmp2;
//    t.mod_data().adjust_regular(tmp1, t.base_data());
//    t.mod_data().adjust_regular(tmp2, v.base_data());
//    eval_right_shift(tmp1, tmp2, static_cast<unsigned long>(i));
//    t.base_data() = tmp1;
//    t.mod_data().adjust_modular(t.base_data());
// }
//
// template <class Backend>
// constexpr void eval_bitwise_and(modular_adaptor<Backend>& result, const modular_adaptor<Backend>& v)
// {
//    using default_ops::eval_bitwise_and;
//    typename modular_adaptor<Backend>::value_type tmp1, tmp2;
//    result.mod_data().adjust_regular(tmp1, result.base_data());
//    result.mod_data().adjust_regular(tmp2, v.base_data());
//    eval_bitwise_and(tmp1, tmp1, tmp2);
//    result.base_data() = tmp1;
//    result.mod_data().adjust_modular(result.base_data());
// }
//
// template <class Backend>
// constexpr void eval_bitwise_or(modular_adaptor<Backend>& result, const modular_adaptor<Backend>& v)
// {
//    using default_ops::eval_bitwise_or;
//    typename modular_adaptor<Backend>::value_type tmp1, tmp2;
//    result.mod_data().adjust_regular(tmp1, result.base_data());
//    result.mod_data().adjust_regular(tmp2, v.base_data());
//    eval_bitwise_or(tmp1, tmp1, tmp2);
//    result.base_data() = tmp1;
//    result.mod_data().adjust_modular(result.base_data());
// }
//
// template <class Backend>
// constexpr void eval_bitwise_xor(modular_adaptor<Backend>& result, const modular_adaptor<Backend>& v)
// {
//    using default_ops::eval_bitwise_xor;
//    typename modular_adaptor<Backend>::value_type tmp1, tmp2;
//    result.mod_data().adjust_regular(tmp1, result.base_data());
//    result.mod_data().adjust_regular(tmp2, v.base_data());
//    eval_bitwise_xor(tmp1, tmp1, tmp2);
//    result.base_data() = tmp1;
//    result.mod_data().adjust_modular(result.base_data());
// }
//
// } // namespace backends
//
// using boost::multiprecision::backends::modular_adaptor;
//
// template <class Backend>
// struct number_category<modular_adaptor<Backend> > : public boost::mpl::int_<boost::multiprecision::number_kind_modular>
// {};
//
// template <class Backend, expression_template_option ExpressionTemplates>
// struct component_type<number<modular_adaptor<Backend>, ExpressionTemplates> >
// {
//    typedef number<Backend, ExpressionTemplates> type;
// };

}
}
} // namespace boost::multiprecision::backends

#endif // BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
