//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

                template<typename Backend>
                class modular_adaptor;

                // fixed precision modular backend which supports compile-time execution
                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                class modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>> {
                protected:
                    typedef modular_fixed_cpp_int_backend<MinBits, SignType, Checked> Backend;

                public:
                    typedef modular_params<Backend> modulus_type;
                    typedef Backend backend_type;

                protected:
                    typedef typename modulus_type::policy_type policy_type;
                    typedef typename policy_type::Backend_padded_limbs Backend_padded_limbs;
                    typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;
                    typedef typename policy_type::number_type number_type;

                public:
                    constexpr Backend& base_data() {
                        return m_base;
                    }
                    constexpr const Backend& base_data() const {
                        return m_base;
                    }
                    constexpr modulus_type& mod_data() {
                        return m_mod;
                    }
                    constexpr const modulus_type& mod_data() const {
                        return m_mod;
                    }

                    typedef typename Backend::signed_types signed_types;
                    typedef typename Backend::unsigned_types unsigned_types;

                    constexpr modular_adaptor() {
                    }

                    constexpr modular_adaptor(const modular_adaptor& o) : m_base(o.base_data()), m_mod(o.mod_data()) {
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                    constexpr modular_adaptor(modular_adaptor&& o) :
                        m_base(std::move(o.base_data())), m_mod(std::move(o.mod_data())) {
                    }
#endif

                    template<typename Backend1, typename Backend2>
                    constexpr modular_adaptor(const Backend1& b, const Backend2& m) : m_base(b), m_mod(m) {
                        mod_data().adjust_modular(base_data());
                    }

                    constexpr explicit modular_adaptor(const Backend& m) :
                        m_base(static_cast<typename boost::mpl::front<unsigned_types>::type>(0u)), m_mod(number_type(m)) {
                        mod_data().adjust_modular(base_data());
                    }

                    constexpr explicit modular_adaptor(const number_type& m) :
                        m_base(static_cast<typename boost::mpl::front<unsigned_types>::type>(0u)), m_mod(m) {
                        mod_data().adjust_modular(base_data());
                    }

                    // TODO: check correctness of the method
                    modular_adaptor& operator=(const char* s) {
                        // TODO: why default modulus value equals 0
                        typedef typename boost::mpl::front<unsigned_types>::type ui_type;
                        ui_type zero = 0u;

                        using default_ops::eval_fpclassify;

                        if (s && (*s == '(')) {
                            std::string part;
                            const char* p = ++s;
                            while (*p && (*p != ',') && (*p != ')'))
                                ++p;
                            part.assign(s, p);
                            if (!part.empty())
                                m_base() = part.c_str();
                            else
                                m_base() = zero;
                            s = p;
                            if (*p && (*p != ')')) {
                                ++p;
                                while (*p && (*p != ')'))
                                    ++p;
                                part.assign(s + 1, p);
                            } else
                                part.erase();
                            if (!part.empty())
                                m_mod() = part.c_str();
                            else
                                m_mod() = zero;
                        } else {
                            base_data() = s;
                            m_mod() = zero;
                        }
                        return *this;
                    }

                    constexpr int compare(const modular_adaptor& o) const {
                        //
                        // modulus values should be the same
                        //
                        BOOST_ASSERT(!mod_data().compare(o.mod_data()));

                        Backend tmp1 = base_data();
                        Backend tmp2 = o.base_data();
                        mod_data().adjust_regular(tmp1, base_data());
                        mod_data().adjust_regular(tmp2, o.base_data());
                        return tmp1.compare(tmp2);
                    }

                    template<typename T>
                    constexpr int compare(const T& a) const {
                        modular_adaptor tmp(a, mod_data());
                        return compare(tmp);
                    }

                    constexpr void swap(modular_adaptor& o) {
                        base_data().swap(o.base_data());
                        // TODO: add swap to modulus_type
                        mod_data().swap(o.mod_data());
                    }

                    constexpr modular_adaptor& operator=(const modular_adaptor& o) {
                        modular_adaptor tmp(o);
                        swap(tmp);

                        return *this;
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                    constexpr modular_adaptor& operator=(modular_adaptor&& o) BOOST_NOEXCEPT {
                        modular_adaptor tmp(o);
                        swap(tmp);

                        return *this;
                    }
#endif

                    inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const {
                        Backend tmp;
                        mod_data().adjust_regular(tmp, base_data());
                        return tmp.str(dig, f);
                    }

                    constexpr void negate() {
                        base_data().negate();
                        eval_add(base_data(), mod_data().get_mod().backend());
                    }

                    template<typename BackendT, expression_template_option ExpressionTemplates>
                    constexpr operator number<BackendT, ExpressionTemplates>() {
                        return static_cast<BackendT>(base_data());
                    };

                protected:
                    Backend m_base;
                    modulus_type m_mod;
                };

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend1,
                         typename Backend2>
                constexpr void assign_components(
                    modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                    const Backend1& a, const Backend2& b) {
                    // BOOST_ASSERT_MSG(MinBits == eval_msb(b) + 1, "modulus precision should match used backend");
                    // result.base_data() = a;
                    result.mod_data() = b;
                    result.mod_data().adjust_modular(result.base_data(), a);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr void
                    eval_add(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                             const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend>
                constexpr void
                    eval_add(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                             const modular_adaptor<Backend>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<typename Backend, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr void
                    eval_add(modular_adaptor<Backend>& result,
                             const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    o.mod_data().mod_add(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr void
                    eval_multiply(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                                  const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend>
                constexpr void
                    eval_multiply(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                                  const modular_adaptor<Backend>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    result.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<typename Backend, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr void
                    eval_multiply(modular_adaptor<Backend>& result,
                                  const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    o.mod_data().mod_mul(result.base_data(), o.base_data());
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename T>
                constexpr void
                    eval_pow(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                             const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& b,
                             const T& e) {
                    result.mod_data() = b.mod_data();
                    result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                constexpr void
                    eval_pow(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                             const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& b,
                             const modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& e) {
                    using Backend = modular_fixed_cpp_int_backend<MinBits, SignType, Checked>;

                    Backend exp;
                    e.mod_data().adjust_regular(exp, e.base_data());
                    eval_pow(result, b, exp);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend,
                         typename T>
                constexpr void
                    eval_powm(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                              const modular_adaptor<Backend>& b, const T& e) {
                    BOOST_ASSERT(MinBits >= msb(b.mod_data().get_mod()) + 1);
                    result.mod_data() = b.mod_data();
                    result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
                }

                template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked, typename Backend1,
                         typename Backend2>
                constexpr void
                    eval_powm(modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>& result,
                              const modular_adaptor<Backend1>& b, const modular_adaptor<Backend2>& e) {
                    using Backend = modular_fixed_cpp_int_backend<MinBits, SignType, Checked>;

                    Backend exp;
                    e.mod_data().adjust_regular(exp, e.base_data());
                    eval_powm(result, b, exp);
                }

            }    // namespace backends

            using backends::cpp_int_backend;
            using backends::modular_adaptor;
            using backends::modular_fixed_cpp_int_backend;

            template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
            struct expression_template_default<
                modular_adaptor<modular_fixed_cpp_int_backend<MinBits, SignType, Checked>>> {
                static const expression_template_option value = et_off;
            };
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
