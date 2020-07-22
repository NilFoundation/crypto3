//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FIELD_UTILS_HPP
#define ALGEBRA_FF_FIELD_UTILS_HPP

#include <cstdint>

#include <complex>
#include <stdexcept>

#include <nil/algebra/fields/bigint.hpp>
#include <nil/algebra/common/double.hpp>

#include <boost/multiprecision/modular/base_params.hpp>
#include <boost/multiprecision/detail/functions/constants.hpp>
#include <boost/multiprecision/detail/digits2.hpp>

namespace nil {
    namespace algebra {

        template<typename FieldT>
        FieldT coset_shift() {
            return FieldT::multiplicative_generator.squared();
        }

        // returns root of unity of order n (for n a power of 2), if one exists
        template<typename FieldT>
        typename std::enable_if<std::is_same<FieldT, Double>::value, FieldT>::type get_root_of_unity(const size_t n) {
            FiledT PI = get_constant_pi<FieldT>();
            return FieldT(cos(2 * PI / n), sin(2 * PI / n));
        }

        template<typename FieldT>
        typename std::enable_if<!std::is_same<FieldT, Double>::value, FieldT>::type get_root_of_unity(const size_t n) {
            const size_t logn = get_constant_ln2(n);
            if (n != (1u << logn))
                throw std::invalid_argument("get_root_of_unity: expected n == (1u << logn)");
            if (logn > FieldT::s)
                throw std::invalid_argument("get_root_of_unity: expected logn <= FieldT::s");

            FieldT omega = FieldT::root_of_unity;
            for (size_t i = FieldT::s; i > logn; --i) {
                omega *= omega;
            }

            return omega;
        }

        template<typename FieldT>
        void batch_invert(std::vector<FieldT> &vec) {
            std::vector<FieldT> prod;
            prod.reserve(vec.size());

            FieldT acc = FieldT::one();

            for (auto el : vec) {
                assert(!el.is_zero());
                prod.emplace_back(acc);
                acc = acc * el;
            }

            FieldT acc_inverse = acc.inverse();

            for (long i = static_cast<long>(vec.size() - 1); i >= 0; --i) {
                const FieldT old_el = vec[i];
                vec[i] = acc_inverse * prod[i];
                acc_inverse = acc_inverse * old_el;
            }
        }
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FIELD_UTILS_HPP
