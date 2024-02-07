//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
#define BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP

#include <nil/crypto3/multiprecision/modular/modular_params_fixed.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                template<typename Backend, typename StorageType>
                class modular_adaptor;

                // fixed precision modular backend which supports compile-time execution
                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StateType>
                class modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StateType>
                    : public StateType {
                protected:
                    typedef modular_fixed_cpp_int_backend<MinBits, SignType, Checked> Backend;

                public:
                    typedef modular_params<Backend> modular_type;
                    typedef Backend backend_type;

                protected:
                    typedef typename modular_type::policy_type policy_type;
                    typedef typename policy_type::Backend_padded_limbs Backend_padded_limbs;
                    typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                    typedef typename policy_type::number_type number_type;

                public:
                    constexpr Backend &base_data() {
                        return m_base;
                    }
                    constexpr const Backend &base_data() const {
                        return m_base;
                    }

                    typedef typename Backend::signed_types signed_types;
                    typedef typename Backend::unsigned_types unsigned_types;

                    constexpr modular_adaptor() {
                    }

                    constexpr modular_adaptor(const modular_adaptor &o) : m_base(o.base_data()) {
                        this->set_modular_params(o.mod_data());
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                    constexpr modular_adaptor(modular_adaptor &&o) : m_base(std::move(o.base_data())) {
                        this->set_modular_params(std::move(o.mod_data()));
                    }
#endif

                    template<typename Backend1, typename Backend2>
                    constexpr modular_adaptor(const Backend1 &b, const Backend2 &m) {
                        this->mod_data().adjust_modular(m_base, b);
                        this->set_modular_params(m);
                    }

                    constexpr explicit modular_adaptor(const Backend &m) :
                        m_base(static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u)) {
                        this->mod_data().adjust_modular(m_base);
                        this->set_modular_params(number_type(m));
                    }

                    constexpr explicit modular_adaptor(const number_type &m) :
                        m_base(static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u)) {
                        this->mod_data().adjust_modular(m_base);
                        this->set_modular_params(m);
                    }

                    // TODO: check correctness of the method
                    modular_adaptor &operator=(const char *s) {
                        // TODO: why default modulus value equals 0
                        using ui_type = typename std::tuple_element<0, unsigned_types>::type;
                        ui_type zero = 0u;

                        using default_ops::eval_fpclassify;

                        if (s && (*s == '(')) {
                            std::string part;
                            const char *p = ++s;
                            while (*p && (*p != ',') && (*p != ')'))
                                ++p;
                            part.assign(s, p);
                            if (!part.empty())
                                m_base = part.c_str();
                            else
                                m_base = zero;
                            s = p;
                            if (*p && (*p != ')')) {
                                ++p;
                                while (*p && (*p != ')'))
                                    ++p;
                                part.assign(s + 1, p);
                            } else
                                part.erase();
                            if (!part.empty())
                                this->set_modular_params(part.c_str());
                            else
                                this->set_modular_params(zero);
                        } else {
                            m_base = s;
                            this->set_modular_params(zero);
                        }
                        return *this;
                    }

                    constexpr bool compare_eq(const modular_adaptor &o) const {
                        return !(this->mod_data()).compare(o.mod_data()) && !base_data().compare(o.base_data());
                    }

                    template<class T>
                    constexpr int compare_eq(const T &val) const {
                        return !base_data().compare(val);
                    }

                    constexpr int compare(const modular_adaptor &o) const {
                        //
                        // modulus values should be the same
                        //
                        BOOST_ASSERT(!this->mod_data().compare(o.mod_data()));

                        Backend tmp1 = m_base;
                        Backend tmp2 = o.base_data();
                        this->mod_data().adjust_regular(tmp1, m_base);
                        this->mod_data().adjust_regular(tmp2, o.base_data());
                        return tmp1.compare(tmp2);
                    }

                    template<typename T>
                    constexpr int compare(const T &a) const {
                        Backend tmp1 = m_base;
                        this->mod_data().adjust_regular(tmp1, m_base);

                        return tmp1.compare(a);
                    }

                    constexpr void swap(modular_adaptor &o) {
                        m_base.swap(o.base_data());
                        // TODO: add swap to modular_type
                        //                        this->mod_data().swap(o.mod_data());
                        auto t = this->mod_data();
                        this->set_modular_params(o.mod_data());
                        this->set_modular_params(t);
                    }

                    constexpr modular_adaptor &operator=(const modular_adaptor &o) {
                        m_base = o.base_data();
                        this->set_modular_params(o.mod_data());

                        return *this;
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                    constexpr modular_adaptor &operator=(modular_adaptor &&o) BOOST_NOEXCEPT {
                        m_base = o.base_data();
                        this->set_modular_params(o.mod_data());

                        return *this;
                    }
#endif

                    inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const {
                        Backend tmp;
                        this->mod_data().adjust_regular(tmp, m_base);
                        return tmp.str(dig, f);
                    }

                    constexpr void negate() {
                        m_base.negate();
                        if (m_base.compare(m_zero) != 0) {
                            eval_add(m_base, this->mod_data().get_mod().backend());
                        }
                    }

                protected:
                    Backend m_base;
                    static constexpr Backend m_zero = static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u);
                };

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend1,
                         typename Backend2, typename StorageType>
                constexpr void assign_components(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const Backend1 &a, const Backend2 &b) {
                    // BOOST_ASSERT_MSG(MinBits == eval_msb(b) + 1, "modulus precision should match used backend");
                    result.set_modular_params(b);
                    result.mod_data().adjust_modular(result.base_data(), a);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StorageType>
                constexpr void eval_add(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend,
                         typename StorageType>
                constexpr void eval_add(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<typename Backend, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked,
                         typename StorageType>
                constexpr void eval_add(
                    modular_adaptor<Backend, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    o.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StorageType>
                constexpr void eval_multiply(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &o) {
                    //                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend,
                         typename StorageType>
                constexpr void eval_multiply(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<typename Backend, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked,
                         typename StorageType>
                constexpr void eval_multiply(
                    modular_adaptor<Backend, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    o.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename T,
                         typename StorageType>
                constexpr void eval_pow(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &b,
                    const T &e) {
                    result.set_modular_params(b.mod_data());
                    result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StorageType>
                constexpr void eval_pow(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &b,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &e) {
                    using Backend = modular_fixed_cpp_int_backend<MinBits, SignType, Checked>;

                    Backend exp;
                    e.mod_data().adjust_regular(exp, e.base_data());
                    eval_pow(result, b, exp);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend,
                         typename T, typename StorageType>
                constexpr void eval_powm(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<Backend, StorageType> &b, const T &e) {
                    BOOST_ASSERT(MinBits >= msb(b.mod_data().get_mod()) + 1);
                    result.set_modular_params(b.mod_data());
                    result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend1,
                         typename Backend2, typename StorageType>
                constexpr void eval_powm(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<Backend1, StorageType> &b, const modular_adaptor<Backend2, StorageType> &e) {
                    using Backend = modular_fixed_cpp_int_backend<MinBits, SignType, Checked>;

                    Backend exp;
                    e.mod_data().adjust_regular(exp, e.base_data());
                    eval_powm(result, b, exp);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StorageType>
                constexpr void eval_inverse_mod(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType> &input) {
                    using Backend = modular_fixed_cpp_int_backend<MinBits, SignType, Checked>;
                    using Backend_padded_limbs = typename modular_params<Backend>::policy_type::Backend_padded_limbs;

                    Backend_padded_limbs new_base, res, tmp = input.mod_data().get_mod().backend();

                    input.mod_data().adjust_regular(new_base, input.base_data());
                    eval_inverse_mod(res, new_base, tmp);
                    assign_components(result, res, input.mod_data().get_mod().backend());
                }

            }    // namespace backends

            using backends::cpp_int_backend;
            using backends::modular_adaptor;
            using backends::modular_fixed_cpp_int_backend;

            template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename StorageType>
            struct expression_template_default<
                modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>, StorageType>> {
                static const expression_template_option value = et_off;
            };
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
