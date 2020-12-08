//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP

#include <boost/multiprecision/modular/modular_ops.hpp>

namespace boost {
namespace multiprecision {

// fixed precision modular params type which supports compile-time execution
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class modular_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void> >
{
 protected:
   typedef cpp_int_backend<MinBits, MinBits, SignType, Checked, void> TemplateBackend;
   typedef modular_params<TemplateBackend>                            self_type;
   typedef backends::modular_ops<TemplateBackend>                               modular_logic;

 public:
   typedef typename modular_logic::policy_type policy_type;

 protected:
   typedef typename policy_type::internal_limb_type        internal_limb_type;
   typedef typename policy_type::Backend               Backend;
   typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
   typedef typename policy_type::number_type           number_type;

 public:
   constexpr auto& get_mod_obj() { return m_mod_obj; }
   constexpr const auto& get_mod_obj() const { return m_mod_obj; }
   constexpr auto get_mod() const { return get_mod_obj().get_mod(); }

   // TODO: add universal ref constructor
   constexpr modular_params() {}

   // // template <typename BackendT>
   // template <typename T>
   // constexpr explicit modular_params(const T& m) : m_mod_obj(m) {}

   constexpr explicit modular_params(const number_type& m) : m_mod_obj(m.backend()) {}

   constexpr explicit modular_params(const self_type& o) : m_mod_obj(o.get_mod_obj()) {}

   // template <typename BackendT>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1>
   constexpr void reduce(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result) const
   {
      if (check_montgomery_constraints(get_mod_obj()))
      {
         get_mod_obj().montgomery_reduce(result);
      }
      else
      {
         get_mod_obj().barrett_reduce(result);
      }
   }

   // template <typename BackendT>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1>
   constexpr void adjust_modular(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result)
   {
      // TODO: maybe overflow here
      // get_mod_obj().barret_reduce(result);
      // if (check_montgomery_constraints(get_mod_obj()))
      // {
      //    eval_multiply(result, get_mod_obj().get_r2());
      //    get_mod_obj().montgomery_reduce(result);
      // }
      adjust_modular(result, result);
   }

   // template <typename Backend1, typename Backend2>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2>
   constexpr void adjust_modular(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void> input)
   {
      get_mod_obj().barrett_reduce(input);
      Backend_doubled_limbs tmp(input);
      if (check_montgomery_constraints(get_mod_obj()))
      {
         eval_multiply(tmp, get_mod_obj().get_r2());
         get_mod_obj().montgomery_reduce(tmp);
      }
      result = tmp;
   }

   // template <typename BackendT>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             /// input number should fit in result
             typename = typename std::enable_if<MinBits1 >= MinBits2>::type>
   constexpr void adjust_regular(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                                 const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& input) const
   {
      result = input;
      if (check_montgomery_constraints(get_mod_obj()))
      {
         get_mod_obj().montgomery_reduce(result);
      }
   }

   // template <typename Backend1, typename Backend2>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1, typename BackendT>
   constexpr void mod_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                          const BackendT& exp) const
   {
      if (check_montgomery_constraints(get_mod_obj()))
      {
         get_mod_obj().montgomery_exp(result, exp);
      }
      else
      {
         get_mod_obj().regular_exp(result, exp);
      }
   }

   // template <typename Backend1, typename Backend2, typename Backend3>
   template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
             unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
             typename BackendT>
   constexpr void mod_exp(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
                          const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& a,
                          const BackendT& exp) const
   {
      if (check_montgomery_constraints(get_mod_obj()))
      {
         get_mod_obj().montgomery_exp(result, a, exp);
      }
      else
      {
         get_mod_obj().regular_exp(result, a, exp);
      }
   }

   // // template <typename Backend1, typename Backend2>
   // template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
   //           unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2>
   // constexpr void mod_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
   //                        const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& y) const
   // {
   //    if (check_montgomery_constraints(get_mod_obj()))
   //    {
   //       get_mod_obj().montgomery_mul(result, y);
   //    }
   //    else
   //    {
   //       get_mod_obj().regular_mul(result, y);
   //    }
   // }
   //
   // template <unsigned MinBits1, cpp_integer_type SignType1, cpp_int_check_type Checked1,
   //           unsigned MinBits2, cpp_integer_type SignType2, cpp_int_check_type Checked2,
   //           unsigned MinBits3, cpp_integer_type SignType3, cpp_int_check_type Checked3>
   // constexpr void mod_mul(cpp_int_backend<MinBits1, MinBits1, SignType1, Checked1, void>& result,
   //                        const cpp_int_backend<MinBits2, MinBits2, SignType2, Checked2, void>& x,
   //                        const cpp_int_backend<MinBits3, MinBits3, SignType3, Checked3, void>& y) const
   // {
   //    if (check_montgomery_constraints(get_mod_obj()))
   //    {
   //       get_mod_obj().montgomery_mul(result, x, y);
   //    }
   //    else
   //    {
   //       get_mod_obj().regular_mul(result, x, y);
   //    }
   // }

   template <typename BackendT, expression_template_option ExpressionTemplates>
   constexpr operator number<BackendT, ExpressionTemplates>()
   {
      return get_mod();
   };

   constexpr int compare(const self_type& o) const
   {
      // They are either equal or not:
      return get_mod().compare(o.get_mod());
   }

   constexpr void swap(self_type& o)
   {
      get_mod_obj().swap(o.get_mod_obj());
   }

   constexpr self_type& operator=(const self_type& o)
   {
      self_type tmp(o);
      swap(tmp);

      return *this;
   }

   constexpr self_type& operator=(const number_type& m)
   {
      m_mod_obj = m;

      return *this;
   }

   // TODO: check function correctness
   constexpr friend std::ostream& operator<<(std::ostream& o, const self_type& a)
   {
      o << a.get_mod();
      return o;
   }

 protected:
   modular_logic m_mod_obj;
};

}
} // namespace boost::multiprecision

#endif // BOOST_MULTIPRECISION_MODULAR_PARAMS_FIXED_PRECISION_HPP
