//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_DOUBLE_HPP
#define ALGEBRA_FF_DOUBLE_HPP

#include <complex>
#include <boost/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace algebra {

        class Double {
        public:
            std::complex<double> val;

            Double();

            Double(double real);

            Double(double real, double imag);

            Double(std::complex<double> num);

            static unsigned add_cnt;
            static unsigned sub_cnt;
            static unsigned mul_cnt;
            static unsigned inv_cnt;

            Double operator+(const Double &other) const;
            Double operator-(const Double &other) const;
            Double operator*(const Double &other) const;
            Double operator-() const;

            Double &operator+=(const Double &other);
            Double &operator-=(const Double &other);
            Double &operator*=(const Double &other);

            bool operator==(const Double &other) const;
            bool operator!=(const Double &other) const;

            bool operator<(const Double &other) const;
            bool operator>(const Double &other) const;

            template<typename NumberType>
            Double operator^(const NumberType power) const;
            Double operator^(const size_t power) const;

            template<typename NumberType>
            NumberType as_bigint() const;
            unsigned long as_ulong() const;
            Double inverse() const;
            Double squared() const;

            static Double one();
            static Double zero();

            static Double multiplicative_generator;
            static Double root_of_unity;    // See get_root_of_unity() in field_utils
            static size_t s;
        };

        Double::Double() {
            val = std::complex<double>(0, 0);
        }

        Double::Double(double real) {
            val = std::complex<double>(real, 0);
        }

        Double::Double(double real, double imag) {
            val = std::complex<double>(real, imag);
        }

        Double::Double(std::complex<double> num) {
            val = num;
        }

        unsigned Double::add_cnt = 0;
        unsigned Double::sub_cnt = 0;
        unsigned Double::mul_cnt = 0;
        unsigned Double::inv_cnt = 0;

        Double Double::operator+(const Double &other) const {

            return Double(val + other.val);
        }

        Double Double::operator-(const Double &other) const {

            return Double(val - other.val);
        }

        Double Double::operator*(const Double &other) const {

            return Double(val * other.val);
        }

        Double Double::operator-() const {
            if (val.imag() == 0)
                return Double(-val.real());

            return Double(-val.real(), -val.imag());
        }

        Double &Double::operator+=(const Double &other) {

            this->val = std::complex<double>(val + other.val);
            return *this;
        }

        Double &Double::operator-=(const Double &other) {

            this->val = std::complex<double>(val - other.val);
            return *this;
        }

        Double &Double::operator*=(const Double &other) {

            this->val *= std::complex<double>(other.val);
            return *this;
        }

        bool Double::operator==(const Double &other) const {
            return (std::abs(val.real() - other.val.real()) < 0.000001) &&
                   (std::abs(val.imag() - other.val.imag()) < 0.000001);
        }

        bool Double::operator!=(const Double &other) const {
            return Double(val) == other ? 0 : 1;
        }

        bool Double::operator<(const Double &other) const {
            return (val.real() < other.val.real());
        }

        bool Double::operator>(const Double &other) const {
            return (val.real() > other.val.real());
        }

        template<typename NumberType>
        Double Double::operator^(const NumberType power) const {
            return Double(pow(val, power.as_ulong()));
        }

        Double Double::operator^(const size_t power) const {
            return Double(pow(val, power));
        }

        Double Double::inverse() const {

            return Double(std::complex<double>(1) / val);
        }

        template<typename NumberType>
        NumberType Double::as_bigint() const {
            return NumberType(val.real());
        }

        unsigned long Double::as_ulong() const {
            return round(val.real());
        }

        Double Double::squared() const {
            return Double(val * val);
        }

        Double Double::one() {
            return Double(1);
        }

        Double Double::zero() {
            return Double(0);
        }

        Double Double::multiplicative_generator = Double(2);
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_DOUBLE_HPP
