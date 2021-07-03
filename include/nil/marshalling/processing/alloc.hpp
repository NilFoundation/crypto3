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

/// @file nil/marshalling/processing/alloc.h
/// This file contains various generic allocator classes that may be used
/// to allocate objects using dynamic memory or "in-place" allocations.

#ifndef MARSHALLING_ALLOC_HPP
#define MARSHALLING_ALLOC_HPP

#include <memory>
#include <type_traits>
#include <array>
#include <algorithm>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/processing/detail/alloc.hpp>
#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/types/tuple.hpp>

namespace nil {
    namespace marshalling {
        namespace processing {
            namespace alloc {

                /// @brief Dynamic memory allocator
                /// @details Uses standard operator "new" to allocate and initialise requested
                ///     object.
                /// @tparam TInterface Common interface class for all objects being allocated
                ///     with this allocator.
                template<typename TInterface>
                class dyn_memory {
                public:
                    /// @brief Smart pointer (std::unique_ptr) to the allocated object
                    using ptr_type = std::unique_ptr<TInterface>;

                    /// @brief Allocation function
                    /// @tparam TObj Type of the object being allocated, expected to be the
                    ///     same as or derived from TInterface.
                    /// @tparam TArgs types of arguments to be passed to the constructor.
                    /// @return Smart pointer to the allocated object.
                    template<typename TObj, typename... TArgs>
                    static ptr_type alloc(TArgs &&...args) {
                        static_assert(std::is_base_of<TInterface, TObj>::value,
                                      "TObj does not inherit from TInterface");
                        return ptr_type(new TObj(std::forward<TArgs>(args)...));
                    }

                    /// @brief Function used to wrap raw pointer into a smart one
                    /// @tparam Type of the object, expected to be the
                    ///     same as or derived from TInterface.
                    /// @param[in] obj Pointer to previously allocated object.
                    /// @return Smart pointer to the wrapped object.
                    template<typename TObj>
                    static ptr_type wrap(TObj *obj) {
                        static_assert(std::is_base_of<TInterface, TObj>::value,
                                      "TObj does not inherit from TInterface");
                        return ptr_type(obj);
                    }
                };

                /// @brief In-place single object allocator.
                /// @details May allocate only single object at a time. In order to be able
                ///     to allocate new object, previous one must be destructed first. The
                ///     allocator contains uninitialised storage area in its private data,
                ///     which is used to contain allocated object.
                /// @tparam TInterface Common interface class for all objects being allocated
                ///     with this allocator.
                /// @tparam TAllTypes All the possible types that can be allocated with this
                ///     allocator bundled in @b std::tuple. They are used to identify the
                ///     size required to allocate any of the provided objects.
                template<typename TInterface, typename TAllTypes>
                class in_place_single {
                public:
                    /// @brief Smart pointer (std::unique_ptr) to the allocated object.
                    /// @details The custom deleter makes sure the destructor of the
                    ///     allocated object is called.
                    using ptr_type = std::unique_ptr<TInterface, detail::in_place_deleter<TInterface>>;

                    /// @brief Allocation function
                    /// @tparam TObj Type of the object being allocated, expected to be the
                    ///     same as or derived from @b TInterface.
                    /// @tparam TArgs types of arguments to be passed to the constructor.
                    /// @return Smart pointer to the allocated object.
                    /// @pre If @b TObj is NOT the same as @b TInterface, i.e. @b TInterface is a base
                    ///     class of @b TObj, then @b TInterface must have virtual destructor.
                    template<typename TObj, typename... TArgs>
                    ptr_type alloc(TArgs &&...args) {
                        if (allocated_) {
                            return ptr_type();
                        }

                        static_assert(std::is_base_of<TInterface, TObj>::value,
                                      "TObj does not inherit from TInterface");

                        static_assert(nil::detail::is_in_tuple<TObj, TAllTypes>::value,
                                      ""
                                      "TObj must be in provided tuple of supported types");

                        static_assert(std::has_virtual_destructor<TInterface>::value
                                          || std::is_same<TInterface, TObj>::value,
                                      "TInterface is expected to have virtual destructor");

                        static_assert(sizeof(TObj) <= sizeof(place_), "Object is too big");

                        new (&place_) TObj(std::forward<TArgs>(args)...);
                        ptr_type obj(reinterpret_cast<TInterface *>(&place_),
                                     detail::in_place_deleter<TInterface>(&allocated_));
                        allocated_ = true;
                        return std::move(obj);
                    }

                    /// @brief Inquire whether the object is already allocated.
                    bool allocated() const {
                        return allocated_;
                    }

                    /// @brief Get address of the objects being allocated using this allocator
                    const void *alloc_addr() const {
                        return &place_;
                    }

                    /// @brief Function used to wrap raw pointer into a smart one
                    /// @tparam Type of the object, expected to be the
                    ///     same as or derived from TInterface.
                    /// @param[in] obj Pointer to previously allocated object.
                    /// @return Smart pointer to the wrapped object.
                    template<typename TObj>
                    ptr_type wrap(TObj *obj) {
                        if (obj == nullptr) {
                            return ptr_type();
                        }

                        static_assert(std::is_base_of<TInterface, TObj>::value,
                                      "TObj does not inherit from TInterface");
                        MARSHALLING_ASSERT(obj == reinterpret_cast<TInterface *>(&place_));    // Wrong object if fails
                        MARSHALLING_ASSERT(allocated_);                                        // Error if not set
                        return ptr_type(reinterpret_cast<TInterface *>(&place_),
                                        detail::in_place_deleter<TInterface>(&allocated_));
                    }

                private:
                    using aligned_storage_type = typename tuple_as_aligned_union<TAllTypes>::type;

                    aligned_storage_type place_;
                    bool allocated_ = false;
                };

                /// @brief In-place object pool allocator.
                /// @details Similar to @ref in_place_single allocator, but allows multiple
                ///     allocations at the same time, limited by TSize template parameter.
                /// @tparam TInterface Common interface class for all objects being allocated
                ///     with this allocator.
                /// @tparam TSize Number of objects this allocator is allowed to allocate.
                /// @tparam TAllTypes All the possible types that can be allocated with this
                ///     allocator bundled in @b std::tuple.
                template<typename TInterface, std::size_t TSize, typename TAllTypes = std::tuple<TInterface>>
                class in_place_pool {
                    using pool_element_type = in_place_single<TInterface, TAllTypes>;
                    using pool_type = std::array<pool_element_type, TSize>;

                public:
                    /// @brief Smart pointer (std::unique_ptr) to the allocated object.
                    /// @details Same as in_place_single::Ptr;
                    using ptr_type = typename pool_element_type::ptr_type;

                    /// @copydoc in_place_single::alloc
                    template<typename TObj, typename... TArgs>
                    ptr_type alloc(TArgs &&...args) {
                        auto iter = std::find_if(pool_.begin(), pool_.end(), [](const pool_element_type &elem) -> bool {
                            return !elem.allocated();
                        });

                        if (iter == pool_.end()) {
                            return ptr_type();
                        }

                        return iter->template alloc<TObj>(std::forward<TArgs>(args)...);
                    }

                    /// @brief Function used to wrap raw pointer into a smart one
                    /// @tparam Type of the object, expected to be the
                    ///     same as or derived from TInterface.
                    /// @param[in] obj Pointer to previously allocated object.
                    /// @return Smart pointer to the wrapped object.
                    template<typename TObj>
                    ptr_type wrap(TObj *obj) {
                        auto iter
                            = std::find_if(pool_.begin(), pool_.end(), [obj](const pool_element_type &elem) -> bool {
                                  return elem.allocated() && (elem.alloc_addr() == obj);
                              });

                        if (iter == pool_.end()) {
                            return ptr_type();
                        }

                        return iter->wrap(obj);
                    }

                private:
                    pool_type pool_;
                };

            }    // namespace alloc
        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ALLOC_HPP
