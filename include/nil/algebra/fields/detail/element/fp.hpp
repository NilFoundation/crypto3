//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP_HPP

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp{
                private:
                    typedef FieldParams policy_type;
                public:

                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    using value_type = number_type;

                    value_type data;

                    element_fp() : data(value_type(0, modulus)){};

                    element_fp(value_type data) : data(data){};

                    element_fp(modulus_type data) : data(data, modulus){};

                    inline static element_fp zero() {
                        return element_fp(0);
                    }

                    inline static element_fp one() {
                        return element_fp(1);
                    }

                    bool is_zero() const {
                        return data == value_type(0, modulus);
                    }

                    bool is_one() const {
                        return data == value_type(1, modulus);
                    }

                    bool operator==(const element_fp &B) const {
                        return data == B.data;
                    }

                    bool operator!=(const element_fp &B) const {
                        return data != B.data;
                    }

                    element_fp& operator=(const element_fp &B) const {
                        data = B.data;

                        return *this;
                    }

                    element_fp operator+(const element_fp &B) const {
                        return element_fp(data + B.data);
                    }

                    element_fp operator-(const element_fp &B) const {
                        return element_fp(data - B.data);
                    }

                    element_fp operator-() const {
                        return element_fp(-data);
                    }

                    element_fp operator*(const element_fp &B) const {
                        return element_fp(data * B.data);
                    }

                    element_fp dbl() const {
                        return element_fp(data + data);
                    }

                    element_fp sqrt() const {
                        return element_fp(sqrt(data));
                    }

                    element_fp _2z_add_3x() {
                        
                    }

                    element_fp square() const {
                        return element_fp(data * data);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp pow(const PowerType &power) const {
                        return element_fp(power(data, power));
                    }

                    element_fp inverse() const {
                        return element_fp(invert(data));
                    }
                };

                template<typename FieldParams>
                constexpr typename element_fp<FieldParams>::modulus_type const element_fp<FieldParams>::modulus;

            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP_HPP
