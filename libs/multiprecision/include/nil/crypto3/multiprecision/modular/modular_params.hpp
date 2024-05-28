//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Alexey Moskvin
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_PARAMS_HPP
#define BOOST_MULTIPRECISION_MODULAR_PARAMS_HPP

#include <nil/crypto3/multiprecision/modular/montgomery_params.hpp>
#include <nil/crypto3/multiprecision/modular/barrett_params.hpp>

namespace boost {   
    namespace multiprecision {
        namespace backends {

            template<typename Backend>
            class modular_params : public backends::montgomery_params<Backend>,
                                   public backends::barrett_params<Backend> {
            public:
                modular_params() : backends::montgomery_params<Backend>(), backends::barrett_params<Backend>() {
                }

                template<typename Number>
                explicit modular_params(const Backend& p)
                    : backends::montgomery_params<Backend>(p),
                      backends::barrett_params<Backend>(p) {
                }

                modular_params& operator=(const modular_params<Backend>& v) {
                    this->m_mod = v.get_mod();

                    this->m_mu = v.mu();

                    this->m_r2 = v.r2();
                    this->m_p_dash = v.p_dash();
                    this->m_p_words = v.p_words();

                    return *this;
                }

                template<typename Number>
                modular_params& operator=(const Number& v) {
                    Backend tmp(v);
                    this->initialize_barrett_params(tmp);
                    this->initialize_montgomery_params(tmp);
                    return *this;
                }

                void reduce(Backend& result) const {
                    if (get_mod() % 2 == 0) {
                        this->barrett_reduce(result);
                    } else {
                        this->montgomery_reduce(result);
                    }
                }

                /* Conversion from the regular number A into Montgomery form r*A:
                   Montgomery_reduce((A mod N)*(r^2 mod N)) = Montgomery_reduce(A*r^2 mod N) = A*r mod N,
                   where result is A and get_mod() is N.
                   */
                void adjust_modular(Backend& result) {
                    this->barrett_reduce(result);
                    if (get_mod() % 2 != 0) {
                        eval_multiply(result, this->r2());
                        this->montgomery_reduce(result);
                    }
                }
                /* Conversion from the number r*A (in the Montgomery form) into regular number A:
                   Montgomery_reduce(A * r mod N) = A mod N,
                   where result is A and get_mod() is N.
                   */
                void adjust_regular(Backend& result, const Backend& input) const {
                    result = input;
                    if (get_mod() % 2 != 0) {
                        this->montgomery_reduce(result);
                    }
                }

                Backend get_mod() const {
                    return this->m_mod;
                }

                template<typename BackendT, boost::multiprecision::expression_template_option ExpressionTemplates>
                operator boost::multiprecision::number<BackendT, ExpressionTemplates>() {
                    return get_mod();
                };

                int compare(const modular_params<Backend>& o) const {
                    // They are either equal or not:
                    return (get_mod().compare(o.get_mod()));
                }

                friend std::ostream& operator<<(std::ostream& o, modular_params<Backend> const& a) {
                    o << a.get_mod();
                    return o;
                }
            };
        }  // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif    //_MULTIPRECISION_MODULAR_PARAMS_HPP
