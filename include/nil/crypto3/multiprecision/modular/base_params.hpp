//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_BASE_PARAMS_HPP
#define BOOST_MULTIPRECISION_BASE_PARAMS_HPP

#include <nil/crypto3/multiprecision/modular/modular_policy_fixed.hpp>

namespace boost {   
    namespace multiprecision {
        namespace backends {
            template<typename Backend>
            class base_params {
            protected:
                template<typename Number>
                inline void initialize_base_params(const Number& mod) {
                    m_mod = mod;
                }

            public:
                base_params() {
                }

                template<typename Number>
                explicit base_params(const Number& p) {
                    initialize_base_params(p);
                }

                inline const Backend& mod() const {
                    return m_mod;
                }

            protected:
                Backend m_mod;
            };

        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif    // BOOST_MULTIPRECISION_BASE_PARAMS_HPP
