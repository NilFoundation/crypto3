//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_STATIC_VECTOR_HPP
#define MARSHALLING_STATIC_VECTOR_HPP

#include <cstddef>
#include <array>
#include <algorithm>
#include <iterator>
#include <initializer_list>

#include <nil/marshalling/assert_type.hpp>

namespace nil {
    namespace marshalling {
        namespace container {
            namespace detail {

                template<typename T>
                class static_vector_base {
                public:
                    using value_type = T;
                    using size_type = std::size_t;
                    using reference = T &;
                    using const_reference = const T &;
                    using pointer = T *;
                    using const_pointer = const T *;
                    using iterator = pointer;
                    using const_iterator = const_pointer;
                    using reverse_iterator = std::reverse_iterator<iterator>;
                    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

                    using cell_type = typename std::aligned_storage<sizeof(T), std::alignment_of<T>::value>::type;

                    static_assert(sizeof(cell_type) == sizeof(T), "type T must be padded");

                    static_vector_base(cell_type *dataPtr, std::size_t cap) : data_(dataPtr), capacity_(cap) {
                    }

                    ~static_vector_base() noexcept {
                        clear();
                    }

                    static_vector_base(const static_vector_base &) = delete;

                    static_vector_base &operator=(const static_vector_base &) = delete;

                    std::size_t size() const {
                        return size_;
                    }

                    std::size_t capacity() const {
                        return capacity_;
                    }

                    bool empty() const {
                        return (size() == 0);
                    }

                    void pop_back() {
                        auto &lastElem = back();
                        lastElem.~T();
                        --size_;
                    }

                    T &back() {
                        MARSHALLING_ASSERT(!empty());
                        return elem(size() - 1);
                    }

                    const T &back() const {
                        MARSHALLING_ASSERT(!empty());
                        return elem(size() - 1);
                    }

                    T &front() {
                        MARSHALLING_ASSERT(!empty());
                        return elem(0);
                    }

                    const T &front() const {
                        MARSHALLING_ASSERT(!empty());
                        return elem(0);
                    }

                    template<typename TIter>
                    void assign(TIter from, TIter to) {
                        clear();
                        for (auto iter = from; iter != to; ++iter) {
                            if (capacity() <= size()) {
                                MARSHALLING_ASSERT(!"Not all elements are copied");
                                return;
                            }

                            new (cellPtr(size())) T(*iter);
                            ++size_;
                        }
                    }

                    void fill(std::size_t count, const T &value) {
                        clear();
                        MARSHALLING_ASSERT(count <= capacity());
                        for (auto idx = 0U; idx < count; ++idx) {
                            new (cellPtr(idx)) T(value);
                        }
                        size_ = count;
                    }

                    void clear() {
                        for (auto idx = 0U; idx < size(); ++idx) {
                            elem(idx).~T();
                        }
                        size_ = 0;
                    }

                    T *begin() {
                        return &(elem(0));
                    }

                    const T *begin() const {
                        return cbegin();
                    }

                    const T *cbegin() const {
                        return &(elem(0));
                    }

                    T *end() {
                        return begin() + size();
                    }

                    const T *end() const {
                        return cend();
                    }

                    const T *cend() const {
                        return cbegin() + size();
                    }

                    T &at(std::size_t pos) {
                        MARSHALLING_ASSERT(pos < size());
                        return elem(pos);
                    }

                    const T &at(std::size_t pos) const {
                        MARSHALLING_ASSERT(pos < size());
                        return elem(pos);
                    }

                    T &operator[](std::size_t pos) {
                        return elem(pos);
                    }

                    const T &operator[](std::size_t pos) const {
                        return elem(pos);
                    }

                    T *data() {
                        return &(elem(0));
                    }

                    const T *data() const {
                        return &(elem(0));
                    }

                    template<typename U>
                    T *insert(const T *pos, U &&value) {
                        MARSHALLING_ASSERT(pos <= end());
                        MARSHALLING_ASSERT(size() < capacity());
                        if (end() <= pos) {
                            push_back(std::forward<U>(value));
                            return &(back());
                        }

                        MARSHALLING_ASSERT(!empty());
                        push_back(std::move(back()));
                        auto *insertIter = begin() + std::distance(cbegin(), pos);
                        std::move_backward(insertIter, end() - 2, end() - 1);
                        *insertIter = std::forward<U>(value);
                        return insertIter;
                    }

                    T *insert(const T *pos, std::size_t count, const T &value) {
                        MARSHALLING_ASSERT(pos <= end());
                        MARSHALLING_ASSERT((size() + count) <= capacity());
                        auto *posIter = begin() + std::distance(cbegin(), pos);
                        if (end() <= posIter) {
                            while (0 < count) {
                                push_back(value);
                                --count;
                            }
                            return posIter;
                        }

                        MARSHALLING_ASSERT(!empty());
                        auto tailCount = static_cast<std::size_t>(std::distance(posIter, end()));
                        if (count <= tailCount) {
                            auto pushBegIter = end() - count;
                            auto pushEndIter = end();
                            for (auto iter = pushBegIter; iter != pushEndIter; ++iter) {
                                push_back(std::move(*iter));
                            }

                            auto moveBegIter = posIter;
                            auto moveEndIter = moveBegIter + (tailCount - count);
                            MARSHALLING_ASSERT(moveEndIter < pushEndIter);
                            std::move_backward(moveBegIter, moveEndIter, pushEndIter);

                            auto *assignBegIter = posIter;
                            auto *assignEndIter = assignBegIter + count;
                            for (auto iter = assignBegIter; iter != assignEndIter; ++iter) {
                                *iter = value;
                            }
                            return posIter;
                        }

                        auto pushValueCount = count - tailCount;
                        for (auto idx = 0U; idx < pushValueCount; ++idx) {
                            push_back(value);
                        }

                        auto *pushBegIter = posIter;
                        auto *pushEndIter = pushBegIter + tailCount;
                        for (auto iter = pushBegIter; iter != pushEndIter; ++iter) {
                            push_back(std::move(*iter));
                        }

                        auto assignBegIter = posIter;
                        auto assignEndIter = assignBegIter + tailCount;
                        for (auto iter = assignBegIter; iter != assignEndIter; ++iter) {
                            *iter = value;
                        }
                        return posIter;
                    }

                    template<typename TIter>
                    T *insert(const T *pos, TIter from, TIter to) {
                        using tag = typename std::iterator_traits<TIter>::iterator_category;
                        return insert_internal(pos, from, to, tag());
                    }

                    template<typename... TArgs>
                    T *emplace(const T *iter, TArgs &&...args) {
                        auto *insertIter = begin() + std::distance(cbegin(), iter);
                        if (iter == cend()) {
                            emplace_back(std::forward<TArgs>(args)...);
                            return insertIter;
                        }

                        MARSHALLING_ASSERT(!empty());
                        push_back(std::move(back()));
                        std::move_backward(insertIter, end() - 2, end() - 1);
                        insertIter->~T();
                        new (insertIter) T(std::forward<TArgs>(args)...);
                        return insertIter;
                    }

                    T *erase(const T *from, const T *to) {
                        MARSHALLING_ASSERT(from <= cend());
                        MARSHALLING_ASSERT(to <= cend());
                        MARSHALLING_ASSERT(from <= to);

                        auto tailCount = static_cast<std::size_t>(std::distance(to, cend()));
                        auto eraseCount = static_cast<std::size_t>(std::distance(from, to));

                        auto *moveSrc = begin() + std::distance(cbegin(), to);
                        auto *moveDest = begin() + std::distance(cbegin(), from);
                        std::move(moveSrc, end(), moveDest);

                        auto *eraseFrom = moveDest + tailCount;
                        auto *eraseTo = end();
                        MARSHALLING_ASSERT(eraseFrom <= end());
                        MARSHALLING_ASSERT(eraseCount <= size());
                        MARSHALLING_ASSERT(static_cast<std::size_t>(std::distance(eraseFrom, eraseTo)) == eraseCount);
                        for (auto iter = eraseFrom; iter != eraseTo; ++iter) {
                            iter->~T();
                        }
                        size_ -= eraseCount;
                        return moveDest;
                    }

                    template<typename U>
                    void push_back(U &&value) {
                        MARSHALLING_ASSERT(size() < capacity());
                        new (cellPtr(size())) T(std::forward<U>(value));
                        ++size_;
                    }

                    template<typename... TArgs>
                    void emplace_back(TArgs &&...args) {
                        MARSHALLING_ASSERT(size() < capacity());
                        new (cellPtr(size())) T(std::forward<TArgs>(args)...);
                        ++size_;
                    }

                    void resize(std::size_t count, const T &value) {
                        if (count < size()) {
                            erase(begin() + count, end());
                            MARSHALLING_ASSERT(count == size());
                            return;
                        }

                        while (size() < count) {
                            push_back(value);
                        }
                    }

                    void swap(static_vector_base<T> &other) {
                        auto swapSize = std::min(other.size(), size());
                        for (auto idx = 0U; idx < swapSize; ++idx) {
                            std::swap(this->operator[](idx), other[idx]);
                        }

                        auto otherSize = other.size();
                        auto thisSize = size();

                        if (otherSize == thisSize) {
                            return;
                        }

                        if (otherSize < thisSize) {
                            auto limit = std::min(thisSize, other.capacity());
                            for (auto idx = swapSize; idx < limit; ++idx) {
                                new (other.cellPtr(idx)) T(std::move(elem(idx)));
                            }

                            other.size_ = thisSize;
                            erase(begin() + otherSize, end());
                            return;
                        }

                        auto limit = std::min(otherSize, capacity());
                        for (auto idx = swapSize; idx < limit; ++idx) {
                            new (cellPtr(idx)) T(std::move(other.elem(idx)));
                        }
                        size_ = otherSize;
                        other.erase(other.begin() + thisSize, other.end());
                    }

                private:
                    cell_type &cell(std::size_t idx) {
                        MARSHALLING_ASSERT(idx < capacity());
                        return data_[idx];
                    }

                    const cell_type &cell(std::size_t idx) const {
                        MARSHALLING_ASSERT(idx < capacity());
                        return data_[idx];
                    }

                    cell_type *cellPtr(std::size_t idx) {
                        MARSHALLING_ASSERT(idx < capacity());
                        return &data_[idx];
                    }

                    T &elem(std::size_t idx) {
                        return reinterpret_cast<T &>(cell(idx));
                    }

                    const T &elem(std::size_t idx) const {
                        return reinterpret_cast<const T &>(cell(idx));
                    }

                    template<typename TIter>
                    T *insert_random_access(const T *pos, TIter from, TIter to) {
                        MARSHALLING_ASSERT(pos <= end());
                        auto *posIter = begin() + std::distance(cbegin(), pos);
                        if (end() <= posIter) {
                            for (; from != to; ++from) {
                                push_back(*from);
                            }

                            return posIter;
                        }

                        auto count = static_cast<std::size_t>(std::distance(from, to));
                        MARSHALLING_ASSERT(!empty());
                        auto tailCount = static_cast<std::size_t>(std::distance(posIter, end()));
                        if (count <= tailCount) {
                            auto pushBegIter = end() - count;
                            auto pushEndIter = end();
                            for (auto iter = pushBegIter; iter != pushEndIter; ++iter) {
                                push_back(std::move(*iter));
                            }

                            auto moveBegIter = posIter;
                            auto moveEndIter = moveBegIter + (tailCount - count);
                            MARSHALLING_ASSERT(moveEndIter < pushEndIter);
                            std::move_backward(moveBegIter, moveEndIter, pushEndIter);

                            auto *assignBegIter = posIter;
                            auto *assignEndIter = assignBegIter + count;
                            for (auto iter = assignBegIter; iter != assignEndIter; ++iter) {
                                *iter = *from;
                                ++from;
                            }
                            return posIter;
                        }

                        auto pushValueCount = count - tailCount;
                        auto pushInsertedBegIter = to - pushValueCount;
                        for (auto idx = 0U; idx < pushValueCount; ++idx) {
                            push_back(*pushInsertedBegIter);
                            ++pushInsertedBegIter;
                        }

                        auto *pushBegIter = posIter;
                        auto *pushEndIter = pushBegIter + tailCount;
                        for (auto iter = pushBegIter; iter != pushEndIter; ++iter) {
                            push_back(std::move(*iter));
                        }

                        auto assignBegIter = posIter;
                        auto assignEndIter = assignBegIter + tailCount;
                        for (auto iter = assignBegIter; iter != assignEndIter; ++iter) {
                            *iter = *from;
                            ++from;
                        }

                        return posIter;
                    }

                    template<typename TIter>
                    T *insert_input(const T *pos, TIter from, TIter to) {
                        T *ret = nullptr;
                        for (; from != to; ++from) {
                            if (ret == nullptr) {
                                ret = begin() + std::distance(cbegin(), pos);
                            }
                            insert(pos, *from);
                            ++pos;
                        }
                        return ret;
                    }

                    template<typename TIter>
                    T *insert_internal(const T *pos, TIter from, TIter to, std::random_access_iterator_tag) {
                        return insert_random_access(pos, from, to);
                    }

                    template<typename TIter>
                    T *insert_internal(const T *pos, TIter from, TIter to, std::input_iterator_tag) {
                        return insert_input(pos, from, to);
                    }

                    cell_type *data_ = nullptr;
                    std::size_t capacity_ = 0;
                    std::size_t size_ = 0;
                };

                template<typename T, std::size_t TSize>
                struct static_vector_storage_base {
                    using element_type = typename std::aligned_storage<sizeof(T), std::alignment_of<T>::value>::type;

                    using storage_type = std::array<element_type, TSize>;
                    storage_type data_;
                };

                template<typename T, std::size_t TSize>
                class static_vector_generic : public static_vector_storage_base<T, TSize>,
                                              public static_vector_base<T> {
                    using StorageBase = static_vector_storage_base<T, TSize>;
                    using Base = static_vector_base<T>;

                public:
                    using value_type = typename Base::value_type;
                    using size_type = typename Base::size_type;
                    using difference_type = typename StorageBase::storage_type::difference_type;
                    using reference = typename Base::reference;
                    using const_reference = typename Base::const_reference;
                    using pointer = typename Base::pointer;
                    using const_pointer = typename Base::const_pointer;
                    using iterator = typename Base::iterator;
                    using const_iterator = typename Base::const_iterator;
                    using reverse_iterator = typename Base::reverse_iterator;
                    using const_reverse_iterator = typename Base::const_reverse_iterator;

                    static_vector_generic() : Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                    }

                    static_vector_generic(size_type count, const T &value) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        assign(count, value);
                    }

                    explicit static_vector_generic(size_type count) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        MARSHALLING_ASSERT(count < Base::capacity());
                        while (0 < count) {
                            Base::emplace_back();
                            --count;
                        }
                    }

                    template<typename TIter>
                    static_vector_generic(TIter from, TIter to) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        assign(from, to);
                    }

                    template<std::size_t TOtherSize>
                    static_vector_generic(const static_vector_generic<T, TOtherSize> &other) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        assign(other.begin(), other.end());
                    }

                    static_vector_generic(const static_vector_generic &other) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        assign(other.begin(), other.end());
                    }

                    static_vector_generic(std::initializer_list<value_type> init) :
                        Base(&StorageBase::data_[0], StorageBase::data_.size()) {
                        assign(init.begin(), init.end());
                    }

                    ~static_vector_generic() noexcept = default;

                    static_vector_generic &operator=(const static_vector_generic &other) {
                        if (&other == this) {
                            return *this;
                        }

                        assign(other.begin(), other.end());
                        return *this;
                    }

                    template<std::size_t TOtherSize>
                    static_vector_generic &operator=(const static_vector_generic<T, TOtherSize> &other) {
                        assign(other.cbegin(), other.cend());
                        return *this;
                    }

                    static_vector_generic &operator=(std::initializer_list<value_type> init) {
                        assign(init);
                        return *this;
                    }

                    void assign(size_type count, const T &value) {
                        MARSHALLING_ASSERT(count <= TSize);
                        Base::fill(count, value);
                    }

                    template<typename TIter>
                    void assign(TIter from, TIter to) {
                        Base::assign(from, to);
                    }

                    void assign(std::initializer_list<value_type> init) {
                        assign(init.begin(), init.end());
                    }

                    void reserve(size_type new_cap) {
                        static_cast<void>(new_cap);
                        MARSHALLING_ASSERT(new_cap <= Base::capacity());
                    }
                };

                template<typename TOrig, typename TCast, std::size_t TSize>
                class static_vector_casted : public static_vector_generic<TCast, TSize> {
                    using Base = static_vector_generic<TCast, TSize>;
                    static_assert(sizeof(TOrig) == sizeof(TCast), "The sizes are not equal");

                public:
                    using value_type = TOrig;
                    using size_type = typename Base::size_type;
                    using difference_type = typename Base::difference_type;
                    using reference = value_type &;
                    using const_reference = const value_type &;
                    using pointer = value_type *;
                    using const_pointer = const value_type *;
                    using iterator = pointer;
                    using const_iterator = const_pointer;

                    static_vector_casted() = default;

                    static_vector_casted(size_type count, const_reference &value) :
                        Base(count, *(reinterpret_cast<typename Base::const_pointer>(&value))) {
                    }

                    explicit static_vector_casted(size_type count) : Base(count) {
                    }

                    template<typename TIter>
                    static_vector_casted(TIter from, TIter to) : Base(from, to) {
                    }

                    template<std::size_t TOtherSize>
                    static_vector_casted(const static_vector_casted<TOrig, TCast, TOtherSize> &other) : Base(other) {
                    }

                    static_vector_casted(const static_vector_casted &other) : Base(other) {
                    }

                    static_vector_casted(std::initializer_list<value_type> init) : Base(init.begin(), init.end()) {
                    }

                    ~static_vector_casted() noexcept = default;

                    static_vector_casted &operator=(const static_vector_casted &) = default;

                    template<std::size_t TOtherSize>
                    static_vector_casted &operator=(const static_vector_casted<TOrig, TCast, TOtherSize> &other) {
                        Base::operator=(other);
                        return *this;
                    }

                    static_vector_casted &operator=(std::initializer_list<value_type> init) {
                        Base::operator=(init);
                        return *this;
                    }

                    void assign(size_type count, const_reference &value) {
                        Base::assign(count, value);
                    }

                    template<typename TIter>
                    void assign(TIter from, TIter to) {
                        Base::assign(from, to);
                    }

                    void assign(std::initializer_list<value_type> init) {
                        assign(init.begin(), init.end());
                    }

                    reference at(size_type pos) {
                        return *(reinterpret_cast<pointer>(&(Base::at(pos))));
                    }

                    const_reference at(size_type pos) const {
                        return *(reinterpret_cast<const_pointer>(&(Base::at(pos))));
                    }

                    reference operator[](size_type pos) {
                        return *(reinterpret_cast<pointer>(&(Base::operator[](pos))));
                    }

                    const_reference operator[](size_type pos) const {
                        return *(reinterpret_cast<const_pointer>(&(Base::operator[](pos))));
                    }

                    reference front() {
                        return *(reinterpret_cast<pointer>(&(Base::front())));
                    }

                    const_reference front() const {
                        return *(reinterpret_cast<const_pointer>(&(Base::front())));
                    }

                    reference back() {
                        return *(reinterpret_cast<pointer>(&(Base::back())));
                    }

                    const_reference back() const {
                        return *(reinterpret_cast<const_pointer>(&(Base::back())));
                    }

                    pointer data() {
                        return reinterpret_cast<pointer>(Base::data());
                    }

                    const_pointer data() const {
                        return reinterpret_cast<const_pointer>(Base::data());
                    }

                    iterator begin() {
                        return reinterpret_cast<iterator>(Base::begin());
                    }

                    const_iterator begin() const {
                        return cbegin();
                    }

                    const_iterator cbegin() const {
                        return reinterpret_cast<const_iterator>(Base::cbegin());
                    }

                    iterator end() {
                        return reinterpret_cast<iterator>(Base::end());
                    }

                    const_iterator end() const {
                        return cend();
                    }

                    const_iterator cend() const {
                        return reinterpret_cast<const_iterator>(Base::cend());
                    }

                    iterator insert(const_iterator iter, const_reference value) {
                        return reinterpret_cast<iterator>(
                            Base::insert(reinterpret_cast<typename Base::const_iterator>(iter),
                                         *(reinterpret_cast<typename Base::const_pointer>(&value))));
                    }

                    iterator insert(const_iterator iter, TCast &&value) {
                        return reinterpret_cast<iterator>(
                            Base::insert(reinterpret_cast<typename Base::const_iterator>(iter),
                                         std::move(*(reinterpret_cast<typename Base::pointer>(&value)))));
                    }

                    iterator insert(const_iterator iter, size_type count, const_reference value) {
                        return reinterpret_cast<iterator>(
                            Base::insert(reinterpret_cast<typename Base::const_iterator>(iter), count,
                                         *(reinterpret_cast<typename Base::const_pointer>(&value))));
                    }

                    template<typename TIter>
                    iterator insert(const_iterator iter, TIter from, TIter to) {
                        return reinterpret_cast<iterator>(
                            Base::insert(reinterpret_cast<typename Base::const_iterator>(iter), from, to));
                    }

                    iterator insert(const_iterator iter, std::initializer_list<value_type> init) {
                        return reinterpret_cast<iterator>(Base::insert(
                            reinterpret_cast<typename Base::const_iterator>(iter), init.begin(), init.end()));
                    }

                    template<typename... TArgs>
                    iterator emplace(const_iterator iter, TArgs &&...args) {
                        return reinterpret_cast<iterator>(Base::emplace(
                            reinterpret_cast<typename Base::const_iterator>(iter), std::forward<TArgs>(args)...));
                    }

                    iterator erase(const_iterator iter) {
                        return erase(iter, iter + 1);
                    }

                    /// @brief Erases elements.
                    /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/erase">Reference</a>
                    iterator erase(const_iterator from, const_iterator to) {
                        return reinterpret_cast<iterator>(
                            Base::erase(reinterpret_cast<typename Base::const_iterator>(from),
                                        reinterpret_cast<typename Base::const_iterator>(to)));
                    }

                    void push_back(const_reference value) {
                        Base::push_back(*(reinterpret_cast<typename Base::const_pointer>(&value)));
                    }

                    void push_back(TCast &&value) {
                        Base::push_back(std::move(*(reinterpret_cast<TCast *>(&value))));
                    }
                };

                template<bool TSignedIntegral>
                struct static_vector_base_signed_integral;

                template<>
                struct static_vector_base_signed_integral<true> {
                    template<typename T, std::size_t TSize>
                    using type = static_vector_casted<T, typename std::make_unsigned<T>::type, TSize>;
                };

                template<>
                struct static_vector_base_signed_integral<false> {
                    template<typename T, std::size_t TSize>
                    using type = static_vector_generic<T, TSize>;
                };

                template<typename T, std::size_t TSize>
                using ChooseStaticVectorBase =
                    typename static_vector_base_signed_integral<std::is_integral<T>::value
                                                                && std::is_signed<T>::value>::template type<T, TSize>;

            }    // namespace detail

            /// @brief Replacement to <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a>
            ///     when no dynamic memory allocation is allowed.
            /// @details Uses <a href="http://en.cppreference.com/w/cpp/container/array">std::array</a>
            ///     in its private members to store the data. Provides
            ///     almost the same interface as
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a>.
            /// @tparam T Type of the stored elements.
            /// @tparam TSize Maximum number of elements that static_vector can store.
            /// @headerfile "marshalling/container/static_vector.h"
            template<typename T, std::size_t TSize>
            class static_vector : public detail::ChooseStaticVectorBase<T, TSize> {
                using Base = detail::ChooseStaticVectorBase<T, TSize>;
                using element_type = typename Base::element_type;

                static_assert(sizeof(T) == sizeof(element_type), "Sizes are not equal as expected.");

                template<typename U, std::size_t TOtherSize>
                friend class static_vector;

            public:
                /// @brief Type of single element.
                using value_type = typename Base::value_type;

                /// @brief Type used for size information
                using size_type = typename Base::size_type;

                /// @brief Type used in pointer arithmetics
                using difference_type = typename Base::storage_type::difference_type;

                /// @brief Reference to single element
                using reference = typename Base::reference;

                /// @brief Const reference to single element
                using const_reference = typename Base::const_reference;

                /// @brief Pointer to single element
                using pointer = typename Base::pointer;

                /// @brief Const pointer to single element
                using const_pointer = typename Base::const_pointer;

                /// @brief Type of the iterator.
                using iterator = typename Base::iterator;

                /// @brief Type of the const iterator
                using const_iterator = typename Base::const_iterator;

                /// @brief Type of the reverse iterator
                using reverse_iterator = typename Base::reverse_iterator;

                /// @brief Type of the const reverse iterator
                using const_reverse_iterator = typename Base::const_reverse_iterator;

                /// @brief Default constructor.
                static_vector() = default;

                /// @brief Constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                static_vector(size_type count, const T &value) : Base(count, value) {
                }

                /// @brief Constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                explicit static_vector(size_type count) : Base(count) {
                }

                /// @brief Constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                template<typename TIter>
                static_vector(TIter from, TIter to) : Base(from, to) {
                }

                /// @brief Copy constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                template<std::size_t TOtherSize>
                static_vector(const static_vector<T, TOtherSize> &other) : Base(other) {
                }

                /// @brief Copy constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                static_vector(const static_vector &other) : Base(other) {
                }

                /// @brief Constructor
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/vector">Reference</a>
                static_vector(std::initializer_list<value_type> init) : Base(init) {
                }

                /// @brief Destructor
                ~static_vector() noexcept = default;

                /// @brief Copy assignement
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator%3D">Reference</a>
                static_vector &operator=(const static_vector &) = default;

                /// @brief Copy assignement
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator%3D">Reference</a>
                template<std::size_t TOtherSize>
                static_vector &operator=(const static_vector<T, TOtherSize> &other) {
                    Base::operator=(other);
                    return *this;
                }

                /// @brief Copy assignement
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator%3D">Reference</a>
                static_vector &operator=(std::initializer_list<value_type> init) {
                    Base::operator=(init);
                    return *this;
                }

                /// @brief Assigns values to the container.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/assign">Reference</a>
                void assign(size_type count, const T &value) {
                    Base::assign(count, value);
                }

                /// @brief Assigns values to the container.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/assign">Reference</a>
                template<typename TIter>
                void assign(TIter from, TIter to) {
                    Base::assign(from, to);
                }

                /// @brief Assigns values to the container.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/assign">Reference</a>
                void assign(std::initializer_list<value_type> init) {
                    assign(init.begin(), init.end());
                }

                /// @brief Access specified element with bounds checking.
                /// @details The bounds check is performed with MARSHALLING_ASSERT() macro, which means
                ///     it is performed only in DEBUG mode compilation. In case NDEBUG
                ///     symbol is defined (RELEASE mode compilation), this call is equivalent
                ///     to operator[]().
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/at">Reference</a>
                reference at(size_type pos) {
                    return Base::at(pos);
                }

                /// @brief Access specified element with bounds checking.
                /// @details The bounds check is performed with MARSHALLING_ASSERT() macro, which means
                ///     it is performed only in DEBUG mode compilation. In case NDEBUG
                ///     symbol is defined (RELEASE mode compilation), this call is equivalent
                ///     to operator[]().
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/at">Reference</a>
                const_reference at(size_type pos) const {
                    return Base::at(pos);
                }

                /// @brief Access specified element without bounds checking.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_at">Reference</a>
                reference operator[](size_type pos) {
                    return Base::operator[](pos);
                }

                /// @brief Access specified element without bounds checking.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_at">Reference</a>
                const_reference operator[](size_type pos) const {
                    return Base::operator[](pos);
                }

                /// @brief Access the first element.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/front">Reference</a>
                /// @pre The vector is not empty.
                reference front() {
                    return Base::front();
                }

                /// @brief Access the first element.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/front">Reference</a>
                /// @pre The vector is not empty.
                const_reference front() const {
                    return Base::front();
                }

                /// @brief Access the last element.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/back">Reference</a>
                /// @pre The vector is not empty.
                reference back() {
                    return Base::back();
                }

                /// @brief Access the last element.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/back">Reference</a>
                /// @pre The vector is not empty.
                const_reference back() const {
                    return Base::back();
                }

                /// @brief Direct access to the underlying array.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/data">Reference</a>
                pointer data() {
                    return Base::data();
                }

                /// @brief Direct access to the underlying array.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/data">Reference</a>
                const_pointer data() const {
                    return Base::data();
                }

                /// @brief Returns an iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/begin">Reference</a>
                iterator begin() {
                    return Base::begin();
                }

                /// @brief Returns an iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/begin">Reference</a>
                const_iterator begin() const {
                    return cbegin();
                }

                /// @brief Returns an iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/begin">Reference</a>
                const_iterator cbegin() const {
                    return Base::cbegin();
                }

                /// @brief Returns an iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/end">Reference</a>
                iterator end() {
                    return Base::end();
                }

                /// @brief Returns an iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/end">Reference</a>
                const_iterator end() const {
                    return cend();
                }

                /// @brief Returns an iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/end">Reference</a>
                const_iterator cend() const {
                    return Base::cend();
                }

                /// @brief Returns a reverse iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rbegin">Reference</a>
                reverse_iterator rbegin() {
                    return reverse_iterator(end());
                }

                /// @brief Returns a reverse iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rbegin">Reference</a>
                const_reverse_iterator rbegin() const {
                    return rbegin();
                }

                /// @brief Returns a reverse iterator to the beginning.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rbegin">Reference</a>
                const_reverse_iterator crbegin() const {
                    return const_reverse_iterator(cend());
                }

                /// @brief Returns a reverse iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rend">Reference</a>
                reverse_iterator rend() {
                    return reverse_iterator(begin());
                }

                /// @brief Returns a reverse iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rend">Reference</a>
                const_reverse_iterator rend() const {
                    return crend();
                }

                /// @brief Returns a reverse iterator to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/rend">Reference</a>
                const_reverse_iterator crend() const {
                    return const_reverse_iterator(cbegin());
                }

                /// @brief Checks whether the container is empty.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/empty">Reference</a>
                bool empty() const {
                    return Base::empty();
                }

                /// @brief Returns the number of elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/size">Reference</a>
                size_type size() const {
                    return Base::size();
                }

                /// @brief Returns the maximum possible number of elements.
                /// @details Same as capacity().
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/max_size">Reference</a>
                /// @return TSize provided as template argument.
                size_type max_size() const {
                    return capacity();
                }

                /// @brief Reserves storage.
                /// @details Does nothing.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/reserve">Reference</a>
                void reserve(size_type new_cap) {
                    return Base::reserve(new_cap);
                }

                /// @brief Returns the number of elements that can be held in currently allocated storage.
                /// @details Same as max_size().
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/capacity">Reference</a>
                /// @return TSize provided as template argument.
                size_type capacity() const {
                    return Base::capacity();
                }

                /// @brief Reduces memory usage by freeing unused memory.
                /// @details Does nothing.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/shrink_to_fit">Reference</a>
                void shrink_to_fit() {
                }

                /// @brief Clears the contents.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/clear">Reference</a>
                void clear() {
                    Base::clear();
                }

                /// @brief Inserts elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/insert">Reference</a>
                iterator insert(const_iterator iter, const T &value) {
                    return Base::insert(iter, value);
                }

                /// @brief Inserts elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/insert">Reference</a>
                iterator insert(const_iterator iter, T &&value) {
                    return Base::insert(iter, std::move(value));
                }

                /// @brief Inserts elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/insert">Reference</a>
                iterator insert(const_iterator iter, size_type count, const T &value) {
                    return Base::insert(iter, count, value);
                }

                /// @brief Inserts elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/insert">Reference</a>
                template<typename TIter>
                iterator insert(const_iterator iter, TIter from, TIter to) {
                    return Base::insert(iter, from, to);
                }

                /// @brief Inserts elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/insert">Reference</a>
                iterator insert(const_iterator iter, std::initializer_list<value_type> init) {
                    return Base::insert(iter, init.begin(), init.end());
                }

                /// @brief Constructs elements in place.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/emplace">Reference</a>
                template<typename... TArgs>
                iterator emplace(const_iterator iter, TArgs &&...args) {
                    return Base::emplace(iter, std::forward<TArgs>(args)...);
                }

                /// @brief Erases elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/erase">Reference</a>
                iterator erase(const_iterator iter) {
                    return erase(iter, iter + 1);
                }

                /// @brief Erases elements.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/erase">Reference</a>
                iterator erase(const_iterator from, const_iterator to) {
                    return Base::erase(from, to);
                }

                /// @brief Adds an element to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/push_back">Reference</a>
                /// @pre The vector mustn't be full.
                void push_back(const T &value) {
                    Base::push_back(value);
                }

                /// @brief Adds an element to the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/push_back">Reference</a>
                /// @pre The vector mustn't be full.
                void push_back(T &&value) {
                    Base::push_back(std::move(value));
                }

                /// @brief Constructs an element in place at the end.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/emplace_back">Reference</a>
                /// @pre The vector mustn't be full.
                template<typename... TArgs>
                void emplace_back(TArgs &&...args) {
                    Base::emplace_back(std::forward<TArgs>(args)...);
                }

                /// @brief Removes the last element.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/pop_back">Reference</a>
                /// @pre The vector mustn't be empty.
                void pop_back() {
                    Base::pop_back();
                }

                /// @brief Changes the number of elements stored.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/resize">Reference</a>
                /// @pre New size mustn't exceed max_size().
                void resize(size_type count) {
                    resize(count, T());
                }

                /// @brief Changes the number of elements stored.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/resize">Reference</a>
                /// @pre New size mustn't exceed max_size().
                void resize(size_type count, const value_type &value) {
                    Base::resize(count, value);
                }

                /// @brief Swaps the contents.
                /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/resize">Reference</a>
                /// @pre New size mustn't exceed max_size().
                template<std::size_t TOtherSize>
                void swap(static_vector<T, TOtherSize> &other) {
                    Base::swap(other);
                }
            };

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator<(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return std::lexicographical_compare(v1.begin(), v1.end(), v2.begin(), v2.end());
            }

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator<=(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return !(v2 < v1);
            }

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator>(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return v2 < v1;
            }

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator>=(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return !(v1 < v2);
            }

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator==(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return (v1.size() == v2.size()) && (!(v1 < v2)) && (!(v2 < v1));
            }

            /// @brief Lexicographically compares the values in the vector.
            /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/operator_cmp">Reference</a>
            /// @related static_vector
            template<typename T, std::size_t TSize1, std::size_t TSize2>
            bool operator!=(const static_vector<T, TSize1> &v1, const static_vector<T, TSize2> &v2) {
                return !(v1 == v2);
            }

        }    // namespace container
    }    // namespace marshalling
}    // namespace nil

namespace std {

    /// @brief Specializes the std::swap algorithm.
    /// @see <a href="http://en.cppreference.com/w/cpp/container/vector/swap2">Reference</a>
    /// @related nil::marshalling::container::static_vector
    template<typename T, std::size_t TSize1, std::size_t TSize2>
    void swap(nil::marshalling::container::static_vector<T, TSize1> &v1,
              nil::marshalling::container::static_vector<T, TSize2> &v2) {
        v1.swap(v2);
    }

}    // namespace std
#endif    // MARSHALLING_STATIC_VECTOR_HPP
