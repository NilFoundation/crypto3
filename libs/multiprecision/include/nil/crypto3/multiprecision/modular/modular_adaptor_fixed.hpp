//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
#define CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP

#include <nil/crypto3/multiprecision/modular/modular_params_fixed.hpp>
#include <nil/crypto3/multiprecision/traits/is_backend.hpp>

namespace boost {
    namespace multiprecision {
        namespace backends {
            template<typename Backend, typename StorageType>
            class modular_adaptor;

            // fixed precision modular backend which supports compile-time execution
            template<unsigned Bits, typename StorageType>
            class modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> : public StorageType {
            protected:
                typedef cpp_int_modular_backend<Bits> Backend;

            public:
                typedef modular_params<Backend> modular_type;
                typedef Backend backend_type;

            protected:
                typedef typename modular_type::policy_type policy_type;
                typedef typename policy_type::Backend_padded_limbs Backend_padded_limbs;
                typedef typename policy_type::Backend_doubled_limbs Backend_doubled_limbs;

            public:

                // This version of conversion
                BOOST_MP_CXX14_CONSTEXPR typename Backend::cpp_int_type convert_to_cpp_int() const {
                    Backend tmp;
                    this->mod_data().adjust_regular(tmp, this->base_data());
                    return tmp.to_cpp_int();
                }

                BOOST_MP_CXX14_CONSTEXPR Backend &base_data() {
                    return m_base;
                }
                BOOST_MP_CXX14_CONSTEXPR const Backend &base_data() const {
                    return m_base;
                }

                typedef typename Backend::unsigned_types unsigned_types;
                // We will allow signed types to be assigned to number<modular_adaptor<>> ...
#ifdef TVM
                using signed_types = std::tuple<int, signed_limb_type, signed_double_limb_type>;
#else
                using signed_types = typename std::conditional<
                    is_trivial_cpp_int_modular<Backend>::value,
                    std::tuple<signed char, short, int, long, boost::long_long_type, signed_double_limb_type>,
                    std::tuple<signed_limb_type, signed_double_limb_type>>::type;
#endif

                BOOST_MP_CXX14_CONSTEXPR modular_adaptor() {
                }

                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(const modular_adaptor &o) : m_base(o.base_data()) {
                    this->set_modular_params(o.mod_data());
                }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(modular_adaptor &&o) : m_base(std::move(o.base_data())) {
                    this->set_modular_params(std::move(o.mod_data()));
                }
#endif

                template<typename UI,
                         typename std::enable_if_t<std::is_integral<UI>::value && std::is_unsigned<UI>::value> const * = nullptr>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(UI b, const Backend &m)
                        : m_base(limb_type(b)) {
                    this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base);
                }

                // A method for converting a signed integer to a modular adaptor. We are not supposed to have this,
                // but in the code we already have conversion for an 'int' into modular type.
                // In the future we must remove.
                template<typename SI,
                         typename std::enable_if_t<std::is_integral<SI>::value && std::is_signed<SI>::value> const * = nullptr>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(SI b)
                        : m_base(limb_type(0u)) {

                    if (b >= 0) {
                        m_base = static_cast<limb_type>(b);
                    } else {
                        m_base = this->mod_data().get_mod();
                        eval_subtract(m_base, static_cast<limb_type>(-b) );
                    }

                    // This method must be called only for compile time modular params.
                    // this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base);
                }

                template<typename UI,
                         typename std::enable_if_t<std::is_integral<UI>::value && std::is_unsigned<UI>::value> const * = nullptr>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(UI b)
                        : m_base(static_cast<limb_type>(b)) {
                    // This method must be called only for compile time modular params.
                    // this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base);
                }

                template<typename SI,
                         typename std::enable_if_t<std::is_integral<SI>::value && std::is_signed<SI>::value> const * = nullptr>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(SI b, const modular_type &m)
                        : m_base(limb_type(0u)) {

                    if (b >= 0) {
                        m_base = static_cast<limb_type>(b);
                    } else {
                        m_base = this->mod_data().get_mod();
                        eval_subtract(m_base, static_cast<limb_type>(-b));
                    }

                    this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base);
                }

                template<typename UI,
                         typename std::enable_if_t<std::is_integral<UI>::value && std::is_unsigned<UI>::value> const * = nullptr>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(UI b, const modular_type &m)
                        : m_base(static_cast<limb_type>(b)) {
                    this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base);
                }
                
                // We may consider to remove this constructor later, and set Bits2 to Bits only,
                // but we need it for use cases from h2f/h2c,
                // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
                template<unsigned Bits2>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(
                        const number<cpp_int_modular_backend<Bits2>> &b, const number<Backend> &m) {
                    this->set_modular_params(m.backend());
                    this->mod_data().adjust_modular(m_base, b.backend());
                }

                // We may consider to remove this constructor later, and set Bits2 to Bits only,
                // but we need it for use cases from h2f/h2c,
                // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
                template<unsigned Bits2>
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor(const cpp_int_modular_backend<Bits2> &b, const modular_type &m) {
                    this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base, b);
                }

                // We may consider to remove this constructor later, and set Bits2 to Bits only,
                // but we need it for use cases from h2f/h2c,
                // where a larger number of 512 or 256 bits is passed to a field of 255 or 254 bits.
                template<unsigned Bits2>
                BOOST_MP_CXX14_CONSTEXPR explicit modular_adaptor(const cpp_int_modular_backend<Bits2> &b) {
                    // This method must be called only for compile time modular params.
                    // this->set_modular_params(m);
                    this->mod_data().adjust_modular(m_base, b);
                }

                // This function sets default modulus value to zero to make sure it fails if not used with
                // compile-time fixed modulus.
                modular_adaptor &operator=(const char *s) {
                    using ui_type = typename std::tuple_element<0, unsigned_types>::type;
                    ui_type zero = 0u;

                    using boost::multiprecision::default_ops::eval_fpclassify;

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

                BOOST_MP_CXX14_CONSTEXPR bool compare_eq(const modular_adaptor &o) const {
                    return !(this->mod_data()).compare(o.mod_data()) && !base_data().compare(o.base_data());
                }

                template<class T>
                BOOST_MP_CXX14_CONSTEXPR int compare_eq(const T &val) const {
                    return !base_data().compare(val);
                }

                BOOST_MP_CXX14_CONSTEXPR int compare(const modular_adaptor &o) const {
                    //
                    // modulus values should be the same
                    //
                    Backend tmp1 = m_base;
                    Backend tmp2 = o.base_data();
                    this->mod_data().adjust_regular(tmp1, m_base);
                    this->mod_data().adjust_regular(tmp2, o.base_data());
                    return tmp1.compare(tmp2);
                }

                template<typename T>
                BOOST_MP_CXX14_CONSTEXPR int compare(const T &a) const {
                    Backend tmp1 = m_base;
                    this->mod_data().adjust_regular(tmp1, m_base);

                    return tmp1.compare(a);
                }

                BOOST_MP_CXX14_CONSTEXPR modular_adaptor &operator=(const modular_adaptor &o) {
                    m_base = o.base_data();
                    this->set_modular_params(o.mod_data());

                    return *this;
                }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES
                BOOST_MP_CXX14_CONSTEXPR modular_adaptor &operator=(modular_adaptor &&o) BOOST_NOEXCEPT {
                    m_base = o.base_data();
                    this->set_modular_params(o.mod_data());

                    return *this;
                }
#endif

                // If we want to print a value, we must first convert it back to normal form.
                inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const {
                    Backend tmp;
                    this->mod_data().adjust_regular(tmp, m_base);
                    return tmp.str(dig, f);
                }

                BOOST_MP_CXX14_CONSTEXPR inline void negate() {
                    if (m_base.compare(m_zero) != 0) {
                        auto initial_m_base = m_base;
                        m_base = this->mod_data().get_mod();
                        eval_subtract(m_base, initial_m_base);
                    }
                }

            protected:
                Backend m_base;
                static BOOST_MP_CXX14_CONSTEXPR Backend m_zero = static_cast<typename std::tuple_element<0, unsigned_types>::type>(0u);;
            };

            template<unsigned Bits, typename Backend1,
                     typename Backend2, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void assign_components(
                modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                const Backend1 &a, const Backend2 &b) {
                BOOST_ASSERT_MSG(Bits == eval_msb(b) + 1, "modulus precision should match used backend");

                result.set_modular_params(b);
                result.mod_data().adjust_modular(result.base_data(), a);
            }

            template<unsigned Bits, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_add(
                modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &o) {
                BOOST_ASSERT(eval_eq(result.mod_data().get_mod(), o.mod_data().get_mod()));
                result.mod_data().mod_add(result.base_data(), o.base_data());
            }

            template<unsigned Bits, typename Backend,
                     typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_add(
                modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                const modular_adaptor<Backend, StorageType> &o) {
                result.mod_data().mod_add(result.base_data(), o.base_data());
            }

            template<typename Backend, unsigned Bits, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_add(
                modular_adaptor<Backend, StorageType> &result,
                const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &o) {
                o.mod_data().mod_add(result.base_data(), o.base_data());
            }

            template<unsigned Bits, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_multiply(
                    modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                    const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &o) {
                result.mod_data().mod_mul(result.base_data(), o.base_data());
            }

            template<unsigned Bits, typename Backend, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_multiply(
                    modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                    const modular_adaptor<Backend, StorageType> &o) {
                result.mod_data().mod_mul(result.base_data(), o.base_data());
            }

            template<typename Backend, unsigned Bits, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_multiply(
                    modular_adaptor<Backend, StorageType> &result,
                    const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &o) {
                o.mod_data().mod_mul(result.base_data(), o.base_data());
            }

            template<unsigned Bits, typename Backend, typename T, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_powm(
                    modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                    const modular_adaptor<Backend, StorageType> &b, const T &e) {
                result.set_modular_params(b.mod_data());
                result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
            }

            template<unsigned Bits, typename Backend1, typename Backend2, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_powm(
                    modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                    const modular_adaptor<Backend1, StorageType> &b,
                    const modular_adaptor<Backend2, StorageType> &e) {
                using Backend = cpp_int_modular_backend<Bits>;

                Backend exp;
                e.mod_data().adjust_regular(exp, e.base_data());
                eval_powm(result, b, exp);
            }

            template<unsigned Bits, typename StorageType>
            BOOST_MP_CXX14_CONSTEXPR void eval_inverse_mod(
                modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &result,
                const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType> &input) {
                using Backend = cpp_int_modular_backend<Bits>;
                using Backend_padded_limbs = typename modular_params<Backend>::policy_type::Backend_padded_limbs;

                Backend_padded_limbs new_base, res, tmp = input.mod_data().get_mod();

                input.mod_data().adjust_regular(new_base, input.base_data());
                eval_inverse_mod(res, new_base, tmp);
                assign_components(result, res, input.mod_data().get_mod());
            }

            template<unsigned Bits, typename StorageType>
            std::ostream& operator<<(std::ostream& os, const modular_adaptor<cpp_int_modular_backend<Bits>, StorageType>& value) {
                // Conver to number and print.
                os << std::hex << boost::multiprecision::number<cpp_int_modular_backend<Bits>>(value.base_data()) << std::endl;
                return os;
            }

        }    // namespace backends

        template<unsigned Bits, typename StorageType>
        struct expression_template_default<
            backends::modular_adaptor<backends::cpp_int_modular_backend<Bits>, StorageType>> {
            static const expression_template_option value = boost::multiprecision::et_off;
        };

        // We need to specialize this function, because default boost implementation is "return a.compare(b) == 0;", which is waay slower.    
        template<unsigned Bits, typename StorageType, expression_template_option ExpressionTemplates>
            inline BOOST_MP_CXX14_CONSTEXPR bool operator==(
                const number<backends::modular_adaptor<backends::cpp_int_modular_backend<Bits>, StorageType>, ExpressionTemplates>& a,
                const number<backends::modular_adaptor<backends::cpp_int_modular_backend<Bits>, StorageType>, ExpressionTemplates>& b) {
            return a.backend().compare_eq(b.backend());
        }

        // We need to specialize this function, because default boost implementation is "return a.compare(b) == 0;", which is waay slower.    
        template<unsigned Bits, typename StorageType, expression_template_option ExpressionTemplates>
            inline BOOST_MP_CXX14_CONSTEXPR bool operator!=(
                const number<backends::modular_adaptor<backends::cpp_int_modular_backend<Bits>, StorageType>, ExpressionTemplates>& a,
                const number<backends::modular_adaptor<backends::cpp_int_modular_backend<Bits>, StorageType>, ExpressionTemplates>& b) {
            return !a.backend().compare_eq(b.backend());
        }

    }   // namespace multiprecision
}   // namespace boost

// We want our integer_ops to be included only AFTER modular_adaptor is fully defined. This way
// all integer operations over modular numbers will 'see' the overloaded versions of eval_* functions.
// Moving this include to the start of this file will break the compilation.

#include <nil/crypto3/multiprecision/detail/integer_ops.hpp> // for powm over modular_adaptor

#endif    // CRYPTO3_MULTIPRECISION_MODULAR_ADAPTOR_FIXED_PRECISION_HPP
