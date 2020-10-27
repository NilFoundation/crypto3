//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_WNAF_HPP
#define BOOST_MULTIPRECISION_WNAF_HPP

#include <boost/multiprecision/detail/default_ops.hpp>

namespace boost {
namespace multiprecision {

template <typename Backend>
std::vector<long> eval_find_wnaf(const size_t window_size, const Backend& scalar)
{
   typedef typename mpl::front<typename Backend::unsigned_types>::type ui_type;

   using default_ops::eval_add;
   using default_ops::eval_right_shift;
   using default_ops::eval_subtract;

   const std::size_t length = scalar.limbs().size() * std::numeric_limits<ui_type>::digits; // upper bound
   std::vector<long> res(length + 1);
   Backend           c = scalar;
   ui_type           j = 0;
   while (!c.is_zero())
   {
      long u;
      if ((c.limbs()[0] & 1) == 1)
      {
         u = c.limbs()[0] % (1u << (window_size + 1));
         if (u > (1 << window_size))
         {
            u = u - (1 << (window_size + 1));
         }

         if (u > 0)
         {
            eval_subtract(c, c, u);
         }
         else
         {
            eval_add(c, c, -u);
         }
      }
      else
      {
         u = 0;
      }
      res[j] = u;
      ++j;

      eval_right_shift(c, c, 1); // c = c/2
   }

   return res;
}

template <typename Backend, expression_template_option ExpressionTemplates>
std::vector<long> find_wnaf(const size_t window_size, const number<Backend, ExpressionTemplates>& scalar)
{
   return eval_find_wnaf(window_size, scalar.backend());
}
}
} // namespace boost::multiprecision

#endif //BOOST_MULTIPRECISION_WNAF_HPP
