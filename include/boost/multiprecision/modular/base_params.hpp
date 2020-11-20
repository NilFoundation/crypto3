//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_BASE_PARAMS_HPP
#define BOOST_MULTIPRECISION_BASE_PARAMS_HPP

#include <boost/multiprecision/cpp_int.hpp>

namespace boost {
namespace multiprecision {
namespace backends {

template <typename Backend>
class base_params
{
   typedef number<Backend> number_type;

 protected:
   template <typename Number>
   inline void initialize_base_params(const Number& mod)
   {
      m_mod = mod;
   }

 public:
   base_params() {}

   template <typename Number>
   explicit base_params(const Number& p)
   {
      initialize_base_params(p);
   }

   inline const number_type& mod() const { return m_mod; }

 protected:
   number_type m_mod;
};

// fixed precision barrett params type which supports compile-time execution
template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
{
   static_assert(MinBits, "number of bits should be defined");
   typedef cpp_int_backend<MinBits, MinBits, SignType, Checked, void> Backend;
   typedef number<Backend> number_type;

 protected:
   template <typename Number>
   constexpr void initialize_base_params(const Number& mod)
   {
      m_mod = mod;
   }

 public:
   constexpr base_params() {}

   template <typename Number>
   constexpr explicit base_params(const Number& p)
   {
      initialize_base_params(p);
   }

   constexpr const number_type& mod() const { return m_mod; }

 protected:
   number_type m_mod;
};
}
}
} // namespace boost::multiprecision::backends
#endif //BOOST_MULTIPRECISION_BASE_PARAMS_HPP
