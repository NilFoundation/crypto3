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

 public:
   typedef modular_params<TemplateBackend> modulus_type;

 protected:
   typedef typename modulus_type::policy_type          policy_type;
   typedef typename policy_type::Backend               Backend;
   typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
   typedef typename policy_type::number_type           number_type;

 public:
   typedef Backend_doubled_limbs value_type;

   constexpr value_type& base_data() { return m_base; }
   constexpr const value_type& base_data() const { return m_base; }
   constexpr modulus_type& mod_data() { return m_mod; }
   constexpr const modulus_type& mod_data() const { return m_mod; }

   typedef typename Backend::signed_types   signed_types;
   typedef typename Backend::unsigned_types unsigned_types;

   constexpr modular_adaptor() {}

   constexpr modular_adaptor(const modular_adaptor& o)
       : m_base(o.base_data()), m_mod(o.mod_data())
   {}

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
   constexpr modular_adaptor(modular_adaptor&& o)
       : m_base(std::move(o.base_data())), m_mod(std::move(o.mod_data()))
   {}
#endif

   template <typename Backend1, typename Backend2>
   constexpr modular_adaptor(const Backend1& b, const Backend2& m) : m_base(b), m_mod(m)
   {
      mod_data().adjust_modular(base_data());
   }

   constexpr explicit modular_adaptor(const Backend& m)
       : m_base(static_cast<typename mpl::front<unsigned_types>::type>(0u)), m_mod(number_type(m))
   {
      mod_data().adjust_modular(base_data());
   }

   constexpr explicit modular_adaptor(const number_type& m)
       : m_base(static_cast<typename mpl::front<unsigned_types>::type>(0u)), m_mod(m)
   {
      mod_data().adjust_modular(base_data());
   }

   // TODO: check correctness of the method
   modular_adaptor& operator=(const char* s)
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

   constexpr int compare(const modular_adaptor& o) const
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
      modular_adaptor tmp(a, mod_data());
      return compare(tmp);
   }

   constexpr void swap(modular_adaptor& o)
   {
      base_data().swap(o.base_data());
      // TODO: add swap to modulus_type
      mod_data().swap(o.mod_data());
   }

   constexpr modular_adaptor& operator=(const modular_adaptor& o)
   {
      modular_adaptor tmp(o);
      swap(tmp);

      return *this;
   }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
   constexpr modular_adaptor& operator=(modular_adaptor&& o) BOOST_NOEXCEPT
   {
      modular_adaptor tmp(o);
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

   template <typename BackendT, expression_template_option ExpressionTemplates>
   constexpr operator number<BackendT, ExpressionTemplates>()
   {
      return static_cast<BackendT>(base_data());
   };

 protected:
   value_type   m_base;
   modulus_type m_mod;
};

}

using boost::multiprecision::backends::modular_adaptor;
using boost::multiprecision::backends::cpp_int_backend;

template <unsigned MinBits, unsigned MaxBits, cpp_integer_type SignType, cpp_int_check_type Checked>
struct expression_template_default<modular_adaptor<cpp_int_backend<MinBits, MaxBits, SignType, Checked, void> > >
{
   static const expression_template_option value = et_off;
};

}
} // namespace boost::multiprecision::backends

#endif // BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
