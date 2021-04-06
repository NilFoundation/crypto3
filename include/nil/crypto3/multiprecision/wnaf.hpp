//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_WNAF_HPP
#define BOOST_MULTIPRECISION_WNAF_HPP

#include <nil/crypto3/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            template<typename Backend>
            std::vector<long> eval_find_wnaf(const size_t window_size, const Backend& scalar) {
                typedef typename boost::mpl::front<typename Backend::unsigned_types>::type ui_type;

                using default_ops::eval_add;
                using default_ops::eval_right_shift;
                using default_ops::eval_subtract;

                const std::size_t length = scalar.size() * std::numeric_limits<ui_type>::digits;    // upper bound
                std::vector<long> res(length + 1);

                Backend c(scalar);
                ui_type j = 0;

                while (!(eval_is_zero(c))) {
                    long u;
                    if ((c.limbs()[0] & 1) == 1) {
                        u = c.limbs()[0] % (1u << (window_size + 1));
                        if (u > (1 << window_size)) {
                            u = u - (1 << (window_size + 1));
                        }

                        if (u > 0) {
                            eval_subtract(c, c, ui_type(u));
                        } else {
                            eval_add(c, c, ui_type(-u));
                        }
                    } else {
                        u = 0;
                    }
                    res[j] = u;
                    ++j;

                    eval_right_shift(c, c, 1);    // c = c/2
                }

                return res;
            }

            template<typename Backend, expression_template_option ExpressionTemplates>
            std::vector<long> find_wnaf(const size_t window_size, const number<Backend, ExpressionTemplates>& scalar) {
                return eval_find_wnaf(window_size, scalar.backend());
            }
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil
#endif    // BOOST_MULTIPRECISION_WNAF_HPP
