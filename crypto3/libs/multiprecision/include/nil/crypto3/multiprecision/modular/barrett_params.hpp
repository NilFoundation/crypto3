//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Alexey Moskvin
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_BARRETT_PARAMS_HPP
#define BOOST_MULTIPRECISION_BARRETT_PARAMS_HPP

#include <nil/crypto3/multiprecision/modular/base_params.hpp>

namespace boost {   
    namespace multiprecision {
        namespace backends {
            /**
             * Parameters for Barrett Reduction
             * https://en.wikipedia.org/wiki/Barrett_reduction
             */
            template<typename Backend>
            class barrett_params : virtual public base_params<Backend> {
            protected:
                template<typename Number>
                inline void initialize_barrett_params(const Number& p) {
                    using boost::multiprecision::default_ops::eval_bit_set;
                    using boost::multiprecision::default_ops::eval_divide;

                    this->initialize_base_params(p);

                    m_mu = 0;

                    eval_bit_set(m_mu.backend(), 2 * (1 + msb(p)));
                    eval_divide(m_mu.backend(), this->m_mod.backend());
                }

            public:
                barrett_params() : base_params<Backend>() {
                }

                template<typename Number>
                explicit barrett_params(const Number& p) : base_params<Backend>(p) {
                    initialize_barrett_params(p);
                }

                inline const Backend& mu() const {
                    return m_mu;
                }

                template<class V>
                barrett_params& operator=(const V& v) {
                    initialize_barrett_params(v);
                    return *this;
                }

                inline void barrett_reduce(Backend& result) const {
                    using boost::multiprecision::default_ops::eval_add;
                    using boost::multiprecision::default_ops::eval_bit_set;
                    using boost::multiprecision::default_ops::eval_decrement;
                    using boost::multiprecision::default_ops::eval_lt;
                    using boost::multiprecision::default_ops::eval_msb;
                    using boost::multiprecision::default_ops::eval_multiply;
                    using boost::multiprecision::default_ops::eval_subtract;

                    if (eval_lt(result, this->m_mod.backend())) {
                        return;
                    } else if (eval_msb(result) < 2 * msb(this->m_mod)) {
                        Backend t1(result);

                        eval_multiply(t1, m_mu.backend());
                        eval_right_shift(t1, 2 * (1 + msb(this->mod())));
                        eval_multiply(t1, this->m_mod.backend());
                        eval_subtract(result, result, t1);

                        if (eval_lt(this->m_mod.backend(), result) ||
                            (result.compare(this->m_mod.backend()) == 0)) {
                            eval_subtract(result, result, this->m_mod.backend());
                        }

                        return;
                    } else {
                        eval_modulus(result, this->m_mod.backend());
                        return;
                    }
                }

            protected:
                Backend m_mu;
            };
        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost


#endif    //_MULTIPRECISION_BARRETT_PARAMS_HPP
