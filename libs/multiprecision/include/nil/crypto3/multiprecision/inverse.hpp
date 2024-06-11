//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_INVERSE_HPP
#define BOOST_MULTIPRECISION_INVERSE_HPP

#include <boost/container/vector.hpp>

#include <boost/type_traits/is_integral.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/cpp_int/cpp_int_config.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor_fixed.hpp>
#include <nil/crypto3/multiprecision/modular/inverse.hpp>

namespace boost {
    namespace multiprecision {

       template<typename Backend, boost::multiprecision::expression_template_option ExpressionTemplates>
       BOOST_MP_CXX14_CONSTEXPR boost::multiprecision::number<Backend, ExpressionTemplates>
           inverse_extended_euclidean_algorithm(const boost::multiprecision::number<Backend, ExpressionTemplates> &n,
                                                const boost::multiprecision::number<Backend, ExpressionTemplates> &mod) {
           boost::multiprecision::number<Backend, ExpressionTemplates> result;
           backends::eval_inverse_extended_euclidean_algorithm(result.backend(), n.backend(), mod.backend());
           return result;
       }

       template<typename Backend, typename StorageType, boost::multiprecision::expression_template_option ExpressionTemplates>
       BOOST_MP_CXX14_CONSTEXPR boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates>
           inverse_extended_euclidean_algorithm(
               const boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates> &modular) {
           boost::multiprecision::number<Backend, ExpressionTemplates> new_base, res;
           boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates> res_mod;

           modular.backend().mod_data().adjust_regular(new_base.backend(), modular.backend().base_data());
           backends::eval_inverse_extended_euclidean_algorithm(
               res.backend(), new_base.backend(), modular.backend().mod_data().get_mod());
           assign_components(res_mod.backend(), res.backend(), modular.backend().mod_data().get_mod());

           return res_mod;
       }

       template<typename Backend, boost::multiprecision::expression_template_option ExpressionTemplates>
       BOOST_MP_CXX14_CONSTEXPR boost::multiprecision::number<Backend, ExpressionTemplates>
           monty_inverse(const boost::multiprecision::number<Backend, ExpressionTemplates> &a,
                         const boost::multiprecision::number<Backend, ExpressionTemplates> &p,
                         const boost::multiprecision::number<Backend, ExpressionTemplates> &k) {
           boost::multiprecision::number<Backend, ExpressionTemplates> res;
           backends::eval_monty_inverse(res.backend(), a.backend(), p.backend(), k.backend());
           return res;
       }

       template<typename Backend, boost::multiprecision::expression_template_option ExpressionTemplates>
       BOOST_MP_CXX14_CONSTEXPR boost::multiprecision::number<Backend, ExpressionTemplates> inverse_mod(const boost::multiprecision::number<Backend, ExpressionTemplates> &a,
                                                                  const boost::multiprecision::number<Backend, ExpressionTemplates> &p) {
           boost::multiprecision::number<Backend, ExpressionTemplates> res;
           backends::eval_inverse_mod(res.backend(), a.backend(), p.backend());
           return res;
       }

       template<typename Backend, typename StorageType, boost::multiprecision::expression_template_option ExpressionTemplates>
       BOOST_MP_CXX14_CONSTEXPR boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates>
           inverse_mod(const boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates> &modular) {
           boost::multiprecision::number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates> res;
           backends::eval_inverse_mod(res.backend(), modular.backend());
           return res;
       }

    }   // namespace multiprecision
}   // namespace boost

#endif
