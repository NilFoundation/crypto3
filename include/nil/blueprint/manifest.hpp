//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENT_MANIFEST_HPP
#define CRYPTO3_BLUEPRINT_COMPONENT_MANIFEST_HPP

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <set>
#include <memory>
#include <type_traits>
#include <functional>
#include <limits>
#include <map>
#include <ostream>
#include <typeinfo>

#include <boost/integer/extended_euclidean.hpp>
#include <boost/assert.hpp>
#include <boost/variant.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t ConstantAmount, std::uint32_t PublicInputAmount>
            class plonk_component;
        }    // namespace components

        struct manifest_lookup_type {
            enum class type {
                NONE,
                UNSAT,
                REQUIRED,
                OPTIONAL,
            } t;

            manifest_lookup_type(type t_) : t(t_) {}
            manifest_lookup_type() : t(type::NONE) {}

            bool operator==(manifest_lookup_type lt) const {
                return t == lt.t;
            }

            bool operator!=(manifest_lookup_type lt) const {
                return t != lt.t;
            }

            bool operator<(manifest_lookup_type lt) const {
                return t < lt.t;
            }

            manifest_lookup_type intersect(manifest_lookup_type lt) const {
                if (t == manifest_lookup_type::type::UNSAT ||
                    lt == manifest_lookup_type::type::UNSAT) {

                    return manifest_lookup_type::type::UNSAT;
                } else if (t == manifest_lookup_type::type::REQUIRED) {
                    if (lt == manifest_lookup_type::type::NONE) {
                        return manifest_lookup_type::type::UNSAT;
                    } else {
                        return manifest_lookup_type::type::REQUIRED;
                    }
                } else if (lt == manifest_lookup_type::type::REQUIRED) {
                    if (t == manifest_lookup_type::type::NONE) {
                        return manifest_lookup_type::type::UNSAT;
                    } else {
                        return manifest_lookup_type::type::REQUIRED;
                    }
                } else if (t == manifest_lookup_type::type::NONE ||
                           lt == manifest_lookup_type::type::NONE) {
                    return manifest_lookup_type::type::NONE;
                } else if (t == manifest_lookup_type::type::OPTIONAL) {
                    return lt;
                }
                return manifest_lookup_type::type::UNSAT;
            }

            manifest_lookup_type merge_with(manifest_lookup_type lt) const {
                if (t == manifest_lookup_type::type::UNSAT ||
                    lt == manifest_lookup_type::type::UNSAT) {

                    return manifest_lookup_type::type::UNSAT;
                } else if (t == manifest_lookup_type::type::REQUIRED ||
                           lt == manifest_lookup_type::type::REQUIRED) {
                    return manifest_lookup_type::type::REQUIRED;
                } else if (t == manifest_lookup_type::type::NONE) {
                    return lt;
                } else if (t == manifest_lookup_type::type::OPTIONAL) {
                    return manifest_lookup_type::type::OPTIONAL;
                }
                return manifest_lookup_type::type::NONE;
            }
        };

        std::ostream& operator<<(std::ostream &os, const manifest_lookup_type& t) {
            switch (t.t) {
                case manifest_lookup_type::type::NONE:
                    os << "NONE";
                    break;
                case manifest_lookup_type::type::UNSAT:
                    os << "UNSAT";
                    break;
                case manifest_lookup_type::type::REQUIRED:
                    os << "REQUIRED";
                    break;
                case manifest_lookup_type::type::OPTIONAL:
                    os << "OPTIONAL";
                    break;
            }
            return os;
        }

        struct manifest_constant_type {
            enum class type {
                NONE,
                UNSAT,
                REQUIRED,
            } t;

            manifest_constant_type(type t_) : t(t_) {}
            manifest_constant_type() : t(type::NONE) {}
            manifest_constant_type(bool b) : t(b ? type::REQUIRED : type::NONE) {}

            bool operator==(manifest_constant_type lt) const {
                return t == lt.t;
            }

            bool operator!=(manifest_constant_type lt) const {
                return t != lt.t;
            }

            bool operator<(manifest_constant_type lt) const {
                return t < lt.t;
            }

            manifest_constant_type intersect(manifest_constant_type lt) const {
                if (t == manifest_constant_type::type::UNSAT ||
                    lt == manifest_constant_type::type::UNSAT) {

                    return manifest_constant_type::type::UNSAT;
                } else if (t == manifest_constant_type::type::NONE &&
                           lt == manifest_constant_type::type::REQUIRED ||
                           t == manifest_constant_type::type::REQUIRED &&
                           lt == manifest_constant_type::type::NONE) {
                    return manifest_constant_type::type::UNSAT;
                } else if (t == manifest_constant_type::type::REQUIRED ||
                           lt == manifest_constant_type::type::REQUIRED) {
                    return manifest_constant_type::type::REQUIRED;
                } else if (t == manifest_constant_type::type::NONE ||
                           lt == manifest_constant_type::type::NONE) {
                    return manifest_constant_type::type::NONE;
                }
                return manifest_constant_type::type::UNSAT;
            }

            manifest_constant_type merge_with(manifest_constant_type lt) const {
                if (t == manifest_constant_type::type::UNSAT ||
                    lt == manifest_constant_type::type::UNSAT) {

                    return manifest_constant_type::type::UNSAT;
                } else if (t == manifest_constant_type::type::REQUIRED ||
                           lt == manifest_constant_type::type::REQUIRED) {
                    return manifest_constant_type::type::REQUIRED;
                }
                return manifest_constant_type::type::NONE;
            }
        };

        std::ostream& operator<<(std::ostream &os, const manifest_constant_type& t) {
            switch (t.t) {
                case manifest_constant_type::type::NONE:
                    os << "NONE";
                    break;
                case manifest_constant_type::type::UNSAT:
                    os << "UNSAT";
                    break;
                case manifest_constant_type::type::REQUIRED:
                    os << "REQUIRED";
                    break;
            }
            return os;
        }

        class manifest_param_iterator;

        class manifest_param {
        public:
            // We need this because having just a value does not enable const-time next operation for set type.
            using it_type = boost::variant<std::uint32_t, std::set<std::uint32_t>::const_iterator>;

            virtual bool check_manifest_param(std::uint32_t value, bool strict = true) = 0;
            virtual bool is_satisfiable() = 0;
            virtual std::shared_ptr<manifest_param> intersect(std::shared_ptr<manifest_param> other) = 0;
            virtual std::shared_ptr<manifest_param> subtract(std::set<std::uint32_t> values) = 0;
            virtual std::shared_ptr<manifest_param> merge_with(std::shared_ptr<manifest_param> other) = 0;
            virtual ~manifest_param() = default;

            virtual std::ostream& operator<<(std::ostream &os) const = 0;

            virtual manifest_param_iterator begin() const = 0;
            virtual manifest_param_iterator end() const = 0;
            virtual it_type next(it_type prev) const = 0;
            // Valid only if is_satisfiable() == true
            virtual std::uint32_t max_value_if_sat() const = 0;

            enum class type {
                UNSAT,
                SINGLE_VALUE,
                RANGE,
                SET
            };
        };

        std::ostream& operator<<(std::ostream &os, const manifest_param& p) {
            return p.operator<<(os);
        }

        // Iterates over all valid params in a manifest.
        // We still need a custom iterator type for each component, but at least some boilerplate is encapsulated here.
        // Please do NOT change the underlying object while iteration is going on, this leads to undefined behavior.
        class manifest_param_iterator {
        public:
            using it_type = manifest_param::it_type;

            using iterator_category = std::forward_iterator_tag;
            using value_type = std::uint32_t;
            using difference_type = std::ptrdiff_t;
            using pointer = std::uint32_t*;
            using reference = std::uint32_t&;

            const manifest_param* obj;
            it_type value;

            manifest_param_iterator(const manifest_param* param, it_type value_) : obj(param), value(value_) {}

            value_type operator*() const {
                if (value.type() == typeid(std::uint32_t)) {
                    return boost::get<std::uint32_t>(value);
                } else {
                    return *boost::get<std::set<std::uint32_t>::const_iterator>(value);
                }
            }

            manifest_param_iterator& operator++() {
                value = obj->next(value);
                return *this;
            }

            manifest_param_iterator operator++(int) {
                manifest_param_iterator tmp(obj, value);
                ++(*this);
                return tmp;
            }

            bool operator!=(const manifest_param_iterator& other) const {
                return value != other.value || obj != other.obj;
            }

            bool operator==(const manifest_param_iterator& other) const {
                return value == other.value && obj == other.obj;
            }
        };

        // In order to correctly handle intersection, we need to know the type of the manifest parameter,
        // and to use a specific implementation of intersect for each type.
        // This funciton returns the type of the manifest parameter.
        manifest_param::type get_manifest_param_type(std::shared_ptr<manifest_param> a);

        class manifest_unsat_param : public manifest_param {
        public:
            using it_type = manifest_param::it_type;

            bool check_manifest_param(std::uint32_t value, bool strict = true) override {
                return false;
            }

            bool is_satisfiable() override {
                return false;
            }

            std::shared_ptr<manifest_param> intersect(std::shared_ptr<manifest_param> other) override {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            }

            std::shared_ptr<manifest_param> subtract(std::set<std::uint32_t> values) override {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            }

            std::shared_ptr<manifest_param> merge_with(std::shared_ptr<manifest_param> other) override {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            }

            std::ostream& operator<<(std::ostream &os) const override {
                os << "UNSAT";
                return os;
            }

            manifest_param_iterator begin() const override {
                return manifest_param_iterator(this, 0);
            }

            manifest_param_iterator end() const override {
                return manifest_param_iterator(this, 0);
            }

            it_type next(it_type prev) const override {
                return 0;
            }

            std::uint32_t max_value_if_sat() const override {
                return 0;
            }

            bool operator==(const manifest_unsat_param& other) const {
                return true;
            }
        };

        class manifest_single_value_param : public manifest_param {
        public:
            using it_type = manifest_param::it_type;

            std::uint32_t value;

            manifest_single_value_param(std::uint32_t value) : value(value) {}

            bool check_manifest_param(std::uint32_t value, bool strict = true) override {
                if (strict) {
                    return this->value == value;
                } else {
                    return this->value <= value;
                }
            }

            bool is_satisfiable() override {
                return true;
            }

            std::shared_ptr<manifest_param> intersect(std::shared_ptr<manifest_param> other) override {
                if (other->check_manifest_param(this->value)) {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(this->value));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
            }

            std::shared_ptr<manifest_param> subtract(std::set<std::uint32_t> values) override {
                if (values.find(this->value) != values.end()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(this->value));
                }
            }

            std::shared_ptr<manifest_param> merge_with(std::shared_ptr<manifest_param> other) override;

            std::ostream& operator<<(std::ostream &os) const override {
                os << "VALUE(" << value << ")";
                return os;
            }

            manifest_param_iterator begin() const override {
                return manifest_param_iterator(this, value);
            }

            manifest_param_iterator end() const override {
                return manifest_param_iterator(this, value + 1);
            }

            it_type next(it_type prev) const override {
                return value + 1;
            }

            std::uint32_t max_value_if_sat() const override {
                return value;
            }

            bool operator==(const manifest_single_value_param& other) const {
                return value == other.value;
            }
        };

        class manifest_range_param : public manifest_param {
        public:
            // We don't use unsigned types for start/finish because of overflow leading to undefined behavior
            // Should probably also move step to std::int32_t? Unsure.
            std::int32_t start;
            std::int32_t finish;
            std::uint32_t step;

            // please do not make finish too large
            // save the optimizers
            manifest_range_param(std::int32_t start, std::int32_t finish_, std::uint32_t step = 1)
                : start(start), finish(finish_), step(step) {}

            bool is_satisfiable() override {
                return start < finish && std::abs(start - finish) >= (start % step);
            }

            bool check_manifest_param(std::uint32_t value, bool strict = true) override {
                std::int32_t value_signed = static_cast<std::int32_t>(value);
                if (strict) {
                    return (value_signed >= start) && (value_signed < finish) && ((value_signed - start) % step == 0);
                } else {
                    return (value_signed >= start) && is_satisfiable();
                }
            }

            std::shared_ptr<manifest_param> intersect(std::shared_ptr<manifest_param> other) override;
            std::shared_ptr<manifest_param> subtract(std::set<std::uint32_t> values) override;
            std::shared_ptr<manifest_param> merge_with(std::shared_ptr<manifest_param> other) override;

            std::ostream& operator<<(std::ostream &os) const override {
                os << "RANGE(" << start << ", " << finish << ", " << step << ")";
                return os;
            }

            manifest_param_iterator begin() const override {
                return manifest_param_iterator(this, start);
            }

            manifest_param_iterator end() const override {
                return manifest_param_iterator(this, finish);
            }

            it_type next(it_type prev) const override {
                std::uint32_t prev_value = boost::get<std::uint32_t>(prev);
                return (prev_value + step < finish) ? (prev_value + step) : finish;
            }

            std::uint32_t max_value_if_sat() const override {
                return finish - ((finish % step) ? (finish % step) : step);
            }

            // Isn't strict equality: some ranges are isomorphic, and we don't check that.
            bool operator==(const manifest_range_param& other) const {
                return start == other.start && finish == other.finish && step == other.step;
            }
        };

        class manifest_set_param : public manifest_param {
        public:
            using it_type = manifest_param::it_type;

            std::set<std::uint32_t> set;

            manifest_set_param(std::set<std::uint32_t> set_) : set(std::move(set_)) {}

            void add_value(std::uint32_t value) {
                set.insert(value);
            }

            bool check_manifest_param(std::uint32_t value, bool strict = true) override {
                if (strict) {
                    return set.find(value) != set.end();
                } else {
                    return set.lower_bound(value) != set.end();
                }
            }

            bool is_satisfiable() override {
                return !set.empty();
            }

            std::shared_ptr<manifest_param> intersect(std::shared_ptr<manifest_param> other) override;
            std::shared_ptr<manifest_param> subtract(std::set<std::uint32_t> values) override {
                std::set<std::uint32_t> new_set;
                std::set_difference(set.begin(), set.end(), values.begin(), values.end(),
                                    std::inserter(new_set, new_set.begin()));
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            }

            std::shared_ptr<manifest_param> merge_with(std::shared_ptr<manifest_param> other) override;

            std::ostream& operator<<(std::ostream &os) const override {
                os << "SET(";
                for (auto it = set.begin(); it != set.end(); ++it) {
                    os << *it;
                    if (std::next(it) != set.end()) {
                        os << ", ";
                    }
                }
                os << ")";
                return os;
            }

            manifest_param_iterator begin() const override {
                return manifest_param_iterator(this, set.begin());
            }

            manifest_param_iterator end() const override {
                return manifest_param_iterator(this, set.end());
            }

            it_type next(it_type prev) const override {
                auto prev_it = boost::get<std::set<std::uint32_t>::const_iterator>(prev);
                return ++prev_it;
            }

            std::uint32_t max_value_if_sat() const override {
                return *set.rbegin();
            }

            bool operator==(const manifest_set_param& other) const {
                return set == other.set;
            }
        };

        manifest_param::type get_manifest_param_type(manifest_param* a) {
            using type = manifest_param::type;
             if (dynamic_cast<manifest_unsat_param*>(a)) {
                return type::UNSAT;
            } else if (dynamic_cast<manifest_single_value_param*>(a)) {
                return type::SINGLE_VALUE;
            } else if (dynamic_cast<manifest_range_param*>(a)) {
                return type::RANGE;
            } else if (dynamic_cast<manifest_set_param*>(a)) {
                return type::SET;
            } else {
                BOOST_ASSERT_MSG(false, "Unknown manifest param type");
                return type::UNSAT;
            }
        }

        manifest_param::type get_manifest_param_type(std::shared_ptr<manifest_param> a) {
            return get_manifest_param_type(a.get());
        }

        std::shared_ptr<manifest_param> manifest_single_value_param::merge_with(
                                std::shared_ptr<manifest_param> other) {
            using type = manifest_param::type;
            type other_type = get_manifest_param_type(other);
            if (other_type == type::UNSAT) {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            } else if (other_type == type::SINGLE_VALUE) {
                auto other_value = dynamic_cast<manifest_single_value_param*>(other.get())->value;
                if (other_value == this->value) {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(this->value));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(
                        std::max(this->value, other_value)));
                }
            } else if (other_type == type::SET) {
                const std::set<std::uint32_t> &other_set = dynamic_cast<manifest_set_param*>(other.get())->set;
                std::set<std::uint32_t> new_set;
                for (auto it = other_set.lower_bound(this->value); it != other_set.end(); it++) {
                    new_set.insert(*it);
                }
                if (new_set.empty()) {
                    new_set.insert(this->value);
                }
                return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
            } if (other_type == type::RANGE) {
                auto range = dynamic_cast<manifest_range_param*>(other.get());
                std::uint32_t new_start = std::max<std::int32_t>(
                    this->value + (range->step - (this->value % range->step)) % range->step,
                    range->start);
                if (new_start < range->finish) {
                    return std::shared_ptr<manifest_param>(
                            new manifest_range_param(new_start, range->finish, range->step));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(this->value));
                }
            }
            return std::shared_ptr<manifest_param>(new manifest_unsat_param());
        }

        std::shared_ptr<manifest_param> manifest_set_param::merge_with(std::shared_ptr<manifest_param> other) {
            using type = manifest_param::type;
            type other_type = get_manifest_param_type(other);
            if (other_type == type::UNSAT) {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            } else if (other_type == type::SINGLE_VALUE) {
                auto other_value = dynamic_cast<manifest_single_value_param*>(other.get())->value;
                std::set<std::uint32_t> new_set;
                for (auto it = set.lower_bound(other_value); it != set.end(); it++) {
                    new_set.insert(*it);
                }
                if (new_set.empty()) {
                    new_set.insert(other_value);
                }
                return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
            } else if (other_type == type::SET) {
                auto other_set = dynamic_cast<manifest_set_param*>(other.get())->set;
                if (other_set.empty() || set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
                std::uint32_t min_1 = *set.begin(),
                              min_2 = *other_set.begin();
                std::uint32_t max_min = std::max(min_1, min_2);
                std::set<std::uint32_t> new_set;
                for (auto it = set.lower_bound(max_min); it != set.end(); it++) {
                    new_set.insert(*it);
                }
                for (auto it = other_set.lower_bound(max_min); it != other_set.end(); it++) {
                    new_set.insert(*it);
                }
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            } if (other_type == type::RANGE) {
                auto range = dynamic_cast<manifest_range_param*>(other.get());
                std::uint32_t new_start = std::max<std::int32_t>(
                    *set.lower_bound(range->start),
                    range->start);
                std::set<std::uint32_t> new_set = {new_start};
                for (auto it = set.lower_bound(new_start); it != set.end(); it++) {
                    new_set.insert(*it);
                }
                std::uint32_t step = range->step;
                for (auto it = new_start + (step - new_start % step) % step; it < range->finish; it += step) {
                    new_set.insert(it);
                }
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            }
            return std::shared_ptr<manifest_param>(new manifest_unsat_param());
        }

        std::shared_ptr<manifest_param> manifest_range_param::merge_with(std::shared_ptr<manifest_param> other) {
            using type = manifest_param::type;
            type other_type = get_manifest_param_type(other);
            if (other_type == type::UNSAT) {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            } else if (other_type == type::SINGLE_VALUE) {
                std::uint32_t other_value = dynamic_cast<manifest_single_value_param*>(other.get())->value;
                std::uint32_t new_start = std::max<std::int32_t>(
                    other_value + (step - (other_value % step)) % step,
                    start);
                if (new_start < finish) {
                    return std::shared_ptr<manifest_param>(
                            new manifest_range_param(new_start, finish, step));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(other_value));
                }
            } else if (other_type == type::SET) {
                auto other_set = dynamic_cast<manifest_set_param*>(other.get());
                std::uint32_t new_start = std::max<std::int32_t>(
                    *other_set->set.lower_bound(start),
                    start);
                std::set<std::uint32_t> new_set = {new_start};
                for (auto it = other_set->set.lower_bound(new_start); it !=  other_set->set.end(); it++) {
                    new_set.insert(*it);
                }
                for (auto it = new_start + (step - new_start % step) % step; it < finish; it += step) {
                    new_set.insert(it);
                }
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            } if (other_type == type::RANGE) {
                auto other_range = dynamic_cast<manifest_range_param*>(other.get());
                std::uint32_t new_start = std::max<std::int32_t>(
                    start,
                    other_range->start);
                // technically, there are some other cases there this might be resolved as range
                // this might be good enough though
                if (step == other_range->step) {
                    std::uint32_t new_finish = std::max(finish, other_range->finish);
                    if (new_start < new_finish) {
                        return std::shared_ptr<manifest_param>(
                                new manifest_range_param(new_start, new_finish, step));
                    } else {
                        return std::shared_ptr<manifest_param>(new manifest_single_value_param(new_start));
                    }
                } else if (new_start >= other_range->finish) {
                    return std::shared_ptr<manifest_param>(new manifest_range_param(start, finish, step));
                } else if (new_start >= finish) {
                    return std::shared_ptr<manifest_param>(new manifest_range_param(other_range->start, other_range->finish, other_range->step));
                }
                std::set<std::uint32_t> new_set = {new_start};
                for (auto value : *this) {
                    if (value > new_start) {
                        new_set.insert(value);
                    }
                }
                for (auto value : *other_range) {
                    if (value > new_start) {
                        new_set.insert(value);
                    }
                }
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            }
            return std::shared_ptr<manifest_param>(new manifest_unsat_param());
        }

        std::shared_ptr<manifest_param> manifest_range_param::intersect(
                            std::shared_ptr<manifest_param> other) {
            using type = manifest_param::type;
            type other_type = get_manifest_param_type(other);
            if (other_type == type::UNSAT) {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            } else if (other_type == type::SINGLE_VALUE) {
                if (check_manifest_param(dynamic_cast<manifest_single_value_param*>(other.get())->value)) {
                    return other;
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
            } else if (other_type == type::RANGE) {
                if (!is_satisfiable() || !other->is_satisfiable()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
                manifest_range_param* other_range = dynamic_cast<manifest_range_param*>(other.get());
                std::int32_t other_start = other_range->start;
                std::int32_t other_finish = other_range->finish;
                std::uint32_t other_step = other_range->step;
                std::int32_t new_start, new_finish, new_step;
                if (step == other_step) {
                    new_start = std::max(start, other_start);
                    new_finish = std::min(finish, other_finish);
                    new_step = step;
                } else {
                    auto [step_gcd, m, n] =
                        boost::integer::extended_euclidean<std::int32_t>(step, other_step);
                    if (start % step_gcd != other_start % step_gcd) {
                        return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                    }
                    new_step = step * (other_step / step_gcd);
                    std::int32_t modulo_new_step =
                        (new_step + (other_start * int(step) * m + start * int(other_step) * n) /
                                    step_gcd % new_step) % new_step;
                    new_start = std::max(start, other_start);
                    new_start = new_start + (new_step + int(modulo_new_step - new_start) % new_step) % new_step;
                    new_finish = std::min(finish, other_finish);
                }
                if (new_start >= new_finish) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else if (new_start == new_finish - 1) {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(new_start));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_range_param(new_start, new_finish, new_step));
                }
            } else if (other_type == type::SET) {
                std::set<std::uint32_t> new_set;
                manifest_set_param* other_set = dynamic_cast<manifest_set_param*>(other.get());
                for (std::uint32_t value : other_set->set) {
                    if (check_manifest_param(value)) {
                        new_set.insert(value);
                    }
                }
                return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
            } else {
                BOOST_ASSERT_MSG(false, "Unknown manifest param type");
            }
            return std::shared_ptr<manifest_param>(new manifest_unsat_param());
        }

        std::shared_ptr<manifest_param> manifest_range_param::subtract(std::set<std::uint32_t> values) {
            std::set<std::uint32_t> filtered_set;
            for (std::uint32_t value : values) {
                if (check_manifest_param(value)) {
                    filtered_set.insert(value);
                }
            }
            if (filtered_set.empty()) {
                return std::shared_ptr<manifest_param>(new manifest_range_param(start, finish, step));
            } else {
                // Three distict cases:
                // 1) contigious values at range start
                // 2) contigious values at range end
                // 3) values in the middle -- have to return set
                bool start_contigious = false;

                std::uint32_t count = 0;
                std::uint32_t curr_value = start;
                for (auto value : filtered_set) {
                    if (value != curr_value) {
                        break;
                    } else {
                        curr_value += step;
                    }
                    count++;
                }
                start_contigious = count == filtered_set.size();
                if (start_contigious) {
                    if (curr_value < finish) {
                        return std::shared_ptr<manifest_param>(new manifest_range_param(curr_value, finish, step));
                    } else {
                        return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                    }
                }

                bool end_contigious = false;
                count = 0;
                curr_value = finish - finish % step;
                for (auto it = filtered_set.rbegin(); it != filtered_set.rend(); it++) {
                    if (*it != curr_value) {
                        break;
                    } else {
                        curr_value -= step;
                    }
                    count++;
                }
                end_contigious = count == filtered_set.size();
                if (end_contigious) {
                    if (curr_value > start) {
                        return std::shared_ptr<manifest_param>(new manifest_range_param(start, curr_value, step));
                    } else if (curr_value == start) {
                        return std::shared_ptr<manifest_param>(new manifest_single_value_param(start));
                    } else {
                        return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                    }
                }

                std::set<std::uint32_t> new_set;
                for (std::uint32_t i = start; i < finish; i += step) {
                    if (filtered_set.find(i) == filtered_set.end()) {
                        new_set.insert(i);
                    }
                }
                if (new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                } else if (new_set.size() == 1) {
                    return std::shared_ptr<manifest_param>(new manifest_single_value_param(*new_set.begin()));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                }
            }
        }

        std::shared_ptr<manifest_param> manifest_set_param::intersect(
                            std::shared_ptr<manifest_param> other) {
            using type = manifest_param::type;
            type other_type = get_manifest_param_type(other);
            if (other_type == type::UNSAT) {
                return std::shared_ptr<manifest_param>(new manifest_unsat_param());
            } else if (other_type == type::SINGLE_VALUE) {
                if (check_manifest_param(dynamic_cast<manifest_single_value_param*>(other.get())->value)) {
                    return other;
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
            } else if (other_type == type::RANGE) {
                std::set<std::uint32_t> new_set;
                for (std::uint32_t value : set) {
                    if (other->check_manifest_param(value)) {
                        new_set.insert(value);
                    }
                }
                if (!new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
            } else if (other_type == type::SET) {
                std::set<std::uint32_t> new_set;
                manifest_set_param* other_set = dynamic_cast<manifest_set_param*>(other.get());
                for (std::uint32_t value : other_set->set) {
                    if (check_manifest_param(value)) {
                        new_set.insert(value);
                    }
                }
                if (!new_set.empty()) {
                    return std::shared_ptr<manifest_param>(new manifest_set_param(new_set));
                } else {
                    return std::shared_ptr<manifest_param>(new manifest_unsat_param());
                }
            } else {
                BOOST_ASSERT_MSG(false, "Unknown manifest param type");
            }
            return std::shared_ptr<manifest_param>(new manifest_unsat_param());
        }

        // Describes the set of parameters (e.g. amount of witness columns, lookup columns etc.)
        // which are suitable for a component.
        // Almost all parameters are assumed to be independent of each other:
        // e.g. there can be no dependency between witness column amount and lookup column amount.
        // The one and only exception is: lookup size can depend on lookup column amount.
        class plonk_component_manifest {
        public:
            using param_type = manifest_param;
            using param_ptr_type = std::shared_ptr<param_type>;
            using lookup_size_func_type = std::function<std::uint32_t(std::uint32_t)>;

            static std::uint32_t empty_lookup_size_for_column_amount(std::uint32_t) {
                return 0;
            }

            param_ptr_type witness_amount;
            manifest_constant_type constant_required;
            manifest_lookup_type lookup_usage;
            param_ptr_type lookup_column_amount;
            lookup_size_func_type lookup_size_for_column_amount;

            plonk_component_manifest(param_ptr_type witness_params, manifest_constant_type constant_required)
                : witness_amount(witness_params),
                  constant_required(constant_required),
                  lookup_usage(manifest_lookup_type::type::NONE),
                  lookup_column_amount(param_ptr_type(new manifest_single_value_param(0))),
                  lookup_size_for_column_amount(empty_lookup_size_for_column_amount) {}

            plonk_component_manifest(param_ptr_type witness_params, manifest_constant_type constant_required,
                                     manifest_lookup_type lookup_usage,
                                     param_ptr_type lookup_column_amount,
                                     const lookup_size_func_type
                                        &lookup_size_for_column_amount)
                : witness_amount(witness_params),
                    constant_required(constant_required),
                    lookup_usage(lookup_usage),
                    lookup_column_amount(lookup_column_amount),
                    lookup_size_for_column_amount(lookup_size_for_column_amount) {}

            plonk_component_manifest(const plonk_component_manifest &other) {
                witness_amount = other.witness_amount;
                constant_required = other.constant_required;
                lookup_usage = other.lookup_usage;
                lookup_column_amount = other.lookup_column_amount;
                lookup_size_for_column_amount = other.lookup_size_for_column_amount;
            }

            // Checks if the manifest would be satisfied for passed params.
            bool check_manifest(std::uint32_t witness_amount, std::uint32_t constant_amount,
                                std::uint32_t lookup_column_amount,
                                const std::vector<std::uint32_t> &lookup_size_for_column,
                                bool strict = false) const {
                if (!this->witness_amount->check_manifest_param(witness_amount, strict)) {
                    return false;
                }
                if (constant_required == manifest_constant_type::type::UNSAT ||
                    constant_required == manifest_constant_type::type::REQUIRED && constant_amount == 0) {
                    return false;
                }
                // We do not check what happens to lookups if they are unused.
                if (lookup_usage == manifest_lookup_type::type::NONE) {
                    return true;
                } else if (lookup_usage == manifest_lookup_type::type::UNSAT) {
                    return false;
                }
                if (this->lookup_column_amount->check_manifest_param(lookup_column_amount, strict)) {
                    return false;
                }
                if (lookup_size_for_column.size() != lookup_column_amount) {
                    return false;
                }
                for (std::uint32_t i = 0; i < lookup_column_amount; ++i) {
                    if (lookup_size_for_column_amount(i) > lookup_size_for_column[i]) {
                        return false;
                    }
                }
                return true;
            }

            // Checks if the manifest is satisfied for the component.
            // This is a runtime check in order to prevent bad intialization of components.
            template<typename BlueprintFieldType, typename ArithmetizationParams,
                        std::uint32_t ConstantAmount, std::uint32_t PublicInputAmount>
            bool check_manifest(
                const nil::blueprint::components::plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                                  ConstantAmount, PublicInputAmount>
                    &component) const {
                // TODO: add lookups when they arrive.
                return check_manifest(component.witness_amount(), ConstantAmount, 0, {});
            }

            // merge_with is intended to be used to automatically calculate new manifest in case of one component
            // using another component. You can specify only the parts you are directly using, and count on the system
            // automatically calculating correct manifest for you.
            // Thus this is mostly an intersection of params. The only exception is lookup_usage, which is a union,
            // and lookup_size_for_column_amount, which is a sum.
            plonk_component_manifest merge_with(const plonk_component_manifest &other) const {
                manifest_lookup_type new_lookup_usage = lookup_usage.merge_with(other.lookup_usage);

                std::shared_ptr<manifest_param> new_lookup_column_amount =
                    this->lookup_column_amount->merge_with(other.lookup_column_amount);
                lookup_size_func_type new_lookup_size_for_column_amount = empty_lookup_size_for_column_amount;
                if (new_lookup_usage == manifest_lookup_type::type::REQUIRED ||
                    new_lookup_usage == manifest_lookup_type::type::OPTIONAL) {

                    std::map<std::uint32_t, std::uint32_t> new_lookup_size_for_column_map;

                    for (auto value : *new_lookup_column_amount) {
                        std::uint32_t column = lookup_size_for_column_amount(value);
                        std::uint32_t other_column = other.lookup_size_for_column_amount(value);
                        new_lookup_size_for_column_map[value] = column + other_column;
                    }

                    new_lookup_size_for_column_amount = [new_lookup_size_for_column_map](std::uint32_t size) {
                        return new_lookup_size_for_column_map.at(size);
                    };
                } else {
                    new_lookup_size_for_column_amount = empty_lookup_size_for_column_amount;
                }

                return plonk_component_manifest(
                    witness_amount->merge_with(other.witness_amount),
                    constant_required.merge_with(other.constant_required),
                    new_lookup_usage,
                    new_lookup_column_amount,
                    new_lookup_size_for_column_amount
                );
            }
        };

        std::ostream& operator<<(std::ostream& os, const plonk_component_manifest &manifest) {
            os << "witness_amount: " << (*manifest.witness_amount) << " "
                << "constant_required: " << manifest.constant_required << " "
                << "lookup_usage: " << manifest.lookup_usage << " "
                << "lookup_column_amount: " << (*manifest.lookup_column_amount);
            if (manifest.lookup_usage == manifest_lookup_type::type::REQUIRED ||
                manifest.lookup_usage == manifest_lookup_type::type::OPTIONAL) {

                os << " lookup_size_for_column_amount: ";
                for (auto value : *manifest.lookup_column_amount) {
                    os << "[" << value << "]: " << manifest.lookup_size_for_column_amount(value) << " ";
                }
            }
            return os;
        }

        // Describes the maximum values of parameters compiler is willing to give to a component.
        struct compiler_manfiest {
        private:
            using manifest_param_ptr = std::shared_ptr<manifest_param>;

            std::uint32_t max_witness_columns;
            std::uint32_t max_lookup_columns;

            manifest_param_ptr witness_amount;
            manifest_param_ptr lookup_column_amount;
        public:
            std::uint32_t max_lookup_size;
            bool has_constant;

            bool has_lookup() const {
                return max_lookup_columns > 0;
            }

            void set_max_witness_amount(std::uint32_t max) {
                max_witness_columns = max;
                witness_amount = std::shared_ptr<manifest_param>(new manifest_range_param(0, max));
            }

            void set_max_lookup_column_amount(std::uint32_t max) {
                max_lookup_columns = max;
                lookup_column_amount = std::shared_ptr<manifest_param>(new manifest_range_param(0, max));
            }

            void set_max_lookup_size(std::uint32_t max) {
                max_lookup_size = max;
            }

            std::uint32_t get_max_witness_amount() const {
                return max_witness_columns;
            }

            std::uint32_t get_max_lookup_amount() const {
                return max_lookup_columns;
            }

            compiler_manfiest(std::uint32_t max_witness_columns, std::uint32_t max_lookup_columns,
                              std::uint32_t max_lookup_size, bool has_constant)
                : max_witness_columns(max_witness_columns),
                  max_lookup_columns(max_lookup_columns),
                  max_lookup_size(max_lookup_size),
                  has_constant(has_constant) {

                witness_amount = std::shared_ptr<manifest_param>(new manifest_range_param(0, max_witness_columns + 1));
                lookup_column_amount =
                    std::shared_ptr<manifest_param>(new manifest_range_param(0, max_lookup_columns + 1));
            }

            // Generates a new component manifest based on intersection with given compiler manifest.
            plonk_component_manifest intersect(const plonk_component_manifest &component_manifest) const {
                manifest_lookup_type compiler_lookup_usage = max_lookup_columns > 0
                                                                  ? manifest_lookup_type::type::OPTIONAL
                                                                  : manifest_lookup_type::type::NONE;
                manifest_lookup_type new_lookup_usage = component_manifest.lookup_usage.intersect(compiler_lookup_usage);
                plonk_component_manifest::lookup_size_func_type new_lookup_size_for_column_amount =
                    component_manifest.lookup_size_for_column_amount;
                auto new_lookup_column_amount =
                    component_manifest.lookup_column_amount->intersect(lookup_column_amount);

                if (new_lookup_usage == manifest_lookup_type::type::OPTIONAL ||
                    new_lookup_usage == manifest_lookup_type::type::REQUIRED) {

                    std::set<std::uint32_t> invalid_values;
                    for (auto value : *new_lookup_column_amount) {
                        if (component_manifest.lookup_size_for_column_amount(value) > max_lookup_size) {
                            invalid_values.insert(value);
                        }
                    }
                    new_lookup_column_amount = new_lookup_column_amount->subtract(invalid_values);
                    if (!new_lookup_column_amount->is_satisfiable()) {
                        if (new_lookup_usage == manifest_lookup_type::type::OPTIONAL) {
                            new_lookup_usage = manifest_lookup_type::type::NONE;
                        } else {
                            new_lookup_usage = manifest_lookup_type::type::UNSAT;
                        }
                    }
                }

                return plonk_component_manifest(
                    component_manifest.witness_amount->intersect(witness_amount),
                    component_manifest.constant_required.intersect(manifest_constant_type(has_constant ? 1 : 0)),
                    new_lookup_usage,
                    new_lookup_column_amount,
                    new_lookup_size_for_column_amount
                );
            }
        };

        // Base class for all component gate manifests
        class component_gate_manifest {
        public:
            virtual std::uint32_t gates_amount() const = 0;
            // This is called in comparison function
            // Derived classes should only support compariosn with instances of themselves
            // The case of different classes is already handled in the comparator
            // Default implementation is to return false, meaning equality of all instances in set terms.
            virtual bool operator<(const component_gate_manifest *other) const {
                return false;
            }
        };

        class component_gate_manifest_comparison {
        public:
            bool operator()(const std::shared_ptr<component_gate_manifest> &a,
                            const std::shared_ptr<component_gate_manifest> &b) const {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wpotentially-evaluated-expression"
                if (typeid(*(a.get())) != typeid(*(b.get()))) {
                #pragma clang diagnostic pop
                    return a.get() < b.get();
                } else {
                    return a->operator<(b.get());
                }
            }
        };

        // We use this to avoid having "duplicate" gates counted in gates count.
        // Done via references to allow constexpr access to gates amount.
        struct gate_manifest {
        private:
            std::uint32_t gates_amount;

            void calc_gates_amount() {
                std::uint32_t result = 0;
                for (auto gate : component_gate_manifests) {
                    result += gate.get()->gates_amount();
                }
                gates_amount = result;
            }

        public:
            std::set<std::shared_ptr<component_gate_manifest>, component_gate_manifest_comparison>
                component_gate_manifests = {};

            gate_manifest() : gates_amount(0) {}
            gate_manifest(const gate_manifest &other) : gates_amount(other.gates_amount) {
                component_gate_manifests = other.component_gate_manifests;
            }
            template<typename GateManifestType>
            gate_manifest(const GateManifestType &gate) : gates_amount(0) {
                add(gate);
            }

            template<typename GateManifestType>
            gate_manifest& add(const GateManifestType &gate) {
                component_gate_manifests.insert(std::make_shared<GateManifestType>(gate));
                calc_gates_amount();
                return *this;
            }

            std::uint32_t get_gates_amount() const {
                return gates_amount;
            }

            gate_manifest& merge_with(const gate_manifest &other) {
                component_gate_manifests.insert(other.component_gate_manifests.begin(),
                                                other.component_gate_manifests.end());
                calc_gates_amount();
                return *this;
            }
        };
    }       // namespace blueprint
}    // namespace nil

#endif // CRYPTO3_BLUEPRINT_COMPONENT_MANIFEST_HPP