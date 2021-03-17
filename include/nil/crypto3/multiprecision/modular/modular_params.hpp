//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
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

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            template<typename Backend>
            class modular_params : public backends::montgomery_params<Backend>,
                                   public backends::barrett_params<Backend> {
                typedef number<Backend> number_type;

            public:
                modular_params() : backends::montgomery_params<Backend>(), backends::barrett_params<Backend>() {
                }

                template<typename Number>
                explicit modular_params(const Number& p) :
                    backends::montgomery_params<Backend>(number_type(p)), backends::barrett_params<Backend>(
                                                                              number_type(p)) {
                }

                modular_params& operator=(const modular_params<Backend>& v) {
                    backends::montgomery_params<Backend>::m_mod = v.get_mod();
                    backends::barrett_params<Backend>::m_mod = v.get_mod();

                    this->m_mu = v.mu();

                    this->m_r2 = v.r2();
                    this->m_p_dash = v.p_dash();
                    this->m_p_words = v.p_words();

                    return *this;
                }

                template<typename Number>
                modular_params& operator=(const Number& v) {
                    number_type tmp(v);
                    this->initialize_barrett_params(tmp);
                    this->initialize_montgomery_params(tmp);
                    return *this;
                }

                void reduce(Backend& result) const {
                    if (get_mod() % 2 == 0) {
                        this->barret_reduce(result);
                    } else {
                        this->montgomery_reduce(result);
                    }
                }

                /* Conversion from the regular number A into Montgomery form r*A:
                Montgomery_reduce((A mod N)*(r^2 mod N)) = Montgomery_reduce(A*r^2 mod N) = A*r mod N,
                where result is A and get_mod() is N.

                */
                void adjust_modular(Backend& result) {
                    this->barret_reduce(result);
                    if (get_mod() % 2 != 0) {
                        eval_multiply(result, this->r2().backend());
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

                number_type get_mod() const {
                    return backends::montgomery_params<Backend>::mod() | backends::barrett_params<Backend>::mod();
                }

                template<typename BackendT, expression_template_option ExpressionTemplates>
                operator number<BackendT, ExpressionTemplates>() {
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

            // // fixed precision modular params type which supports compile-time execution
            // template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
            // class modular_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
            //     : public backends::montgomery_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>,
            //       public backends::barrett_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
            // {
            //    typedef backends::montgomery_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
            //    montgomery_policy; typedef backends::barrett_params<cpp_int_backend<MinBits, MinBits, SignType,
            //    Checked, void>> barrett_policy; typedef modular_params<cpp_int_backend<MinBits, MinBits, SignType,
            //    Checked, void>> self_type;
            //
            //    typedef typename montgomery_policy::policy_type policy_type;
            //
            //    typedef typename policy_type::Backend Backend;
            //    typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
            //    typedef typename policy_type::number_type number_type;
            //
            //  public:
            //    constexpr modular_params() : montgomery_policy(), barrett_policy() {}
            //
            //    constexpr explicit modular_params(const Backend& v) : montgomery_policy(number_type(v)),
            //    barrett_policy(number_type(v)) {}
            //
            //    constexpr explicit modular_params(const number_type& v) : montgomery_policy(v), barrett_policy(v) {}
            //
            //    constexpr self_type& operator=(const self_type& o)
            //    {
            //       montgomery_policy::m_mod = o.get_mod();
            //       barrett_policy::m_mod    = o.get_mod();
            //
            //       this->m_mu = o.mu();
            //
            //       this->m_r2           = o.r2();
            //       this->m_p_dash       = o.p_dash();
            //       this->m_p_words      = o.p_words();
            //       this->m_modulus_mask = o.modulus_mask();
            //
            //       return *this;
            //    }
            //
            //    constexpr self_type& operator=(const number_type& v)
            //    {
            //       this->initialize_barrett_params(v);
            //       this->initialize_montgomery_params(v);
            //       return *this;
            //    }
            //
            //    template<typename BackendT>
            //    constexpr void reduce(BackendT& result) const
            //    {
            //
            //       if (get_mod() % 2 == 0)
            //       {
            //          this->barret_reduce(result);
            //       }
            //       else
            //       {
            //          this->montgomery_reduce(result);
            //       }
            //    }
            //
            //    template<typename BackendT>
            //    constexpr void adjust_modular(BackendT& result)
            //    {
            //       this->barret_reduce(result);
            //       if (get_mod() % 2 != 0)
            //       {
            //          eval_multiply(result, this->r2().backend());
            //          this->montgomery_reduce(result);
            //       }
            //    }
            //
            //    template<typename Backend1, typename Backend2>
            //    constexpr void adjust_modular(Backend1& result, Backend2 input)
            //    {
            //       this->barret_reduce(input);
            //       Backend_doubled_limbs tmp(input);
            //       if (get_mod() % 2 != 0)
            //       {
            //          eval_multiply(tmp, this->r2().backend());
            //          this->montgomery_reduce(tmp);
            //       }
            //       result = tmp;
            //    }
            //
            //    template<typename BackendT>
            //    constexpr void adjust_regular(BackendT& result, const BackendT& input) const
            //    {
            //       result = input;
            //       if (get_mod() % 2 != 0)
            //       {
            //          this->montgomery_reduce(result);
            //       }
            //    }
            //
            //    constexpr number_type get_mod() const
            //    {
            //       return montgomery_policy::mod() | barrett_policy::mod();
            //    }
            //
            //    template<typename Backend1, typename Backend2>
            //    constexpr void mod_exp(Backend1& result, const Backend2& exp) const
            //    {
            //       this->mont_exp(result, exp);
            //    }
            //
            //    template<typename Backend1, typename Backend2, typename Backend3>
            //    constexpr void mod_exp(Backend1& result, const Backend2& a, const Backend3& exp) const
            //    {
            //       this->mont_exp(result, a, exp);
            //    }
            //
            //    template<typename Backend1, typename Backend2>
            //    constexpr void mod_mul(Backend1& result, const Backend2& y) const
            //    {
            //       this->montgomery_mul(result, y);
            //    }
            //
            //    template <typename BackendT, expression_template_option ExpressionTemplates>
            //    constexpr operator number<BackendT, ExpressionTemplates>()
            //    {
            //       return get_mod();
            //    };
            //
            //    template<typename BackendT>
            //    constexpr int compare(const modular_params<BackendT>& o) const
            //    {
            //       // They are either equal or not:
            //       return (get_mod().compare(o.get_mod()));
            //    }
            //
            //    // TODO: check function correctness
            //    constexpr friend std::ostream& operator<<(std::ostream& o, modular_params<Backend> const& a)
            //    {
            //       o << a.get_mod();
            //       return o;
            //    }
            // };
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    //_MULTIPRECISION_MODULAR_PARAMS_HPP
