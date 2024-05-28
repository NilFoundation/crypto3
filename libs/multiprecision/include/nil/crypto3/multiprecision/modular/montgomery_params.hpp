//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP
#define BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP

#include <boost/container/vector.hpp>

#include <boost/type_traits/is_integral.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/cpp_int/cpp_int_config.hpp>
#include <nil/crypto3/multiprecision/modular/base_params.hpp>
#include <nil/crypto3/multiprecision/modular/barrett_params.hpp>

#include <type_traits>
#include <tuple>
#include <array>
#include <cstddef>    // std::size_t
#include <limits>
#include <string>

namespace boost {
    namespace multiprecision {
        namespace backends {
            /**
             * Parameters for Montgomery Reduction
             */
            template<typename Backend>
            class montgomery_params : virtual public base_params<Backend> {
            public:
                montgomery_params() : base_params<Backend>() {
                }

                template<typename Number>
                explicit montgomery_params(const Number& p) : base_params<Backend>(p) {
                }

            protected:
                size_t m_p_words;

            };
        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif
