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

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_int/cpp_int_config.hpp>
#include <nil/crypto3/multiprecision/modular/base_params.hpp>
#include <nil/crypto3/multiprecision/modular/barrett_params.hpp>

#include <type_traits>
#include <tuple>
#include <array>
#include <cstddef>    // std::size_t
#include <limits>
#include <string>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                /**
                 * Parameters for Montgomery Reduction
                 */
                template<typename Backend>
                class montgomery_params : virtual public base_params<Backend> {
                    typedef number<Backend> number_type;

                protected:
                    template<typename Number>
                    inline void initialize_montgomery_params(const Number& p) {
                        this->initialize_base_params(p);
                        find_const_variables(p);
                    }

                    inline void initialize_montgomery_params(const montgomery_params<Backend>& p) {
                        this->initialize_base_params(p);
                        find_const_variables(p);
                    }

                    /*
                    * Compute -input^-1 mod 2^limb_bits. Throws an exception if input
                    * is even. If input is odd, then input and 2^n are relatively prime
                    * and an inverse exists.
                    */
                    limb_type monty_inverse(limb_type a) {
                        if (a % 2 == 0) {
                            NIL_THROW(std::invalid_argument("Monty_inverse only valid for odd integers"));
                        }

                        limb_type b = 1;
                        limb_type r = 0;

                        for (size_t i = 0; i != sizeof(limb_type) * CHAR_BIT; ++i) {
                            const limb_type bi = b % 2;
                            r >>= 1;
                            r += bi << (sizeof(limb_type) * CHAR_BIT - 1);

                            b -= a * bi;
                            b >>= 1;
                        }

                        // Now invert in addition space
                        r = (~static_cast<limb_type>(0) - r) + 1;

                        return r;
                    }

                    template<typename T>
                    void find_const_variables(const T& pp) {
                        number_type p = pp;
                        if (p <= 0 || !(p % 2)) {
                            return;
                        }

                        m_p_words = this->m_mod.backend().size();

                        m_p_dash = monty_inverse(this->m_mod.backend().limbs()[0]);

                        number_type r;

                        default_ops::eval_bit_set(r.backend(), m_p_words * sizeof(limb_type) * CHAR_BIT);

                        m_r2 = r * r;
                        barrett_params<Backend> barrettParams(this->m_mod);
                        barrettParams.barrett_reduce(m_r2.backend());
                    }

                public:
                    montgomery_params() : base_params<Backend>() {
                    }

                    template<typename Number>
                    explicit montgomery_params(const Number& p) : base_params<Backend>(p) {
                        initialize_montgomery_params(p);
                    }

                    inline const number_type& r2() const {
                        return m_r2;
                    }

                    inline limb_type p_dash() const {
                        return m_p_dash;
                    }

                    inline size_t p_words() const {
                        return m_p_words;
                    }

                    template<class V>
                    montgomery_params& operator=(const V& v) {
                        initialize_montgomery_params(v);
                        return *this;
                    }

                    inline void montgomery_reduce(Backend& result) const {
                        using default_ops::eval_lt;
                        using default_ops::eval_multiply_add;

                        typedef cpp_int_backend<sizeof(limb_type) * CHAR_BIT * 3, sizeof(limb_type) * CHAR_BIT * 3,
                                                unsigned_magnitude, unchecked, void>
                            cpp_three_int_backend;

                        const size_t p_size = m_p_words;
                        const limb_type p_dash = m_p_dash;
                        const size_t z_size = 2 * (p_words() + 1);

                        boost::container::vector<limb_type> z(
                            result.size(), 0);    // container::vector<limb_type, alloc> z(result.size(), 0);
                        for (size_t i = 0; i < result.size(); ++i) {
                            z[i] = result.limbs()[i];
                        }

                        if (result.size() < z_size) {
                            result.resize(z_size, z_size);
                            z.resize(z_size, 0);
                        }

                        cpp_three_int_backend w(z[0]);

                        result.limbs()[0] = w.limbs()[0] * p_dash;

                        eval_multiply_add(w, result.limbs()[0], this->m_mod.backend().limbs()[0]);
                        eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);

                        for (size_t i = 1; i != p_size; ++i) {
                            for (size_t j = 0; j < i; ++j) {
                                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[i - j]);
                            }

                            eval_add(w, z[i]);

                            result.limbs()[i] = w.limbs()[0] * p_dash;

                            eval_multiply_add(w, result.limbs()[i], this->m_mod.backend().limbs()[0]);

                            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
                        }

                        for (size_t i = 0; i != p_size; ++i) {
                            for (size_t j = i + 1; j != p_size; ++j) {
                                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[p_size + i - j]);
                            }

                            eval_add(w, z[p_size + i]);

                            result.limbs()[i] = w.limbs()[0];

                            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
                        }

                        eval_add(w, z[z_size - 1]);

                        result.limbs()[p_size] = w.limbs()[0];
                        result.limbs()[p_size + 1] = w.limbs()[1];

                        if (result.size() != p_size + 1) {
                            result.resize(p_size + 1, p_size + 1);
                        }
                        result.normalize();
                    }

                protected:
                    number_type m_r2;
                    limb_type m_p_dash;
                    size_t m_p_words;
                };
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
