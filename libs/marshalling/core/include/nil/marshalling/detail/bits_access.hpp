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

#ifndef MARSHALLING_DETAIL_BIT_ACCESS_HPP
#define MARSHALLING_DETAIL_BIT_ACCESS_HPP

#include <tuple>
#include <type_traits>

#include <nil/marshalling/detail/macro_common.hpp>
#include <nil/marshalling/detail/gen_enum.hpp>
#include <nil/marshalling/detail/base_detection.hpp>

#ifdef MARSHALLING_MUST_DEFINE_BASE
#define MARSHALLING_AS_BITMASK_FUNC Base& asBitmask()
#define MARSHALLING_AS_BITMASK_CONST_FUNC const Base& asBitmask() const
#else    // #ifdef MARSHALLING_MUST_DEFINE_BASE
#define MARSHALLING_AS_BITMASK_FUNC \
    FUNC_AUTO_REF_RETURN(asBitmask, decltype(nil::marshalling::types::to_field_base(*this)))
#define MARSHALLING_AS_BITMASK_CONST_FUNC \
    FUNC_AUTO_REF_RETURN_CONST(asBitmask, decltype(nil::marshalling::types::to_field_base(*this)))
#endif    // #ifdef MARSHALLING_MUST_DEFINE_BASE

#define MARSHALLING_BIT_ACC_FUNC(f_, n_)                               \
    bool MARSHALLING_CONCATENATE(getBitValue_, n_)() const {           \
        return f_.get_bit_value(MARSHALLING_CONCATENATE(BitIdx_, n_)); \
    }                                                                  \
    void MARSHALLING_CONCATENATE(set_bit_value_, n_)(bool val) {       \
        f_.set_bit_value(MARSHALLING_CONCATENATE(BitIdx_, n_), val);   \
    }

#define MARSHALLING_BIT_ACC_FUNC_1(f_, n_) MARSHALLING_BIT_ACC_FUNC(f_, n_)
#define MARSHALLING_BIT_ACC_FUNC_2(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_1(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_3(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_2(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_4(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_3(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_5(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_4(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_6(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_5(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_7(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_6(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_8(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_7(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_9(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)            \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_8(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_10(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_9(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_11(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_10(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_12(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_11(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_13(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_12(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_14(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_13(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_15(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_14(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_16(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_15(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_17(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_16(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_18(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_17(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_19(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_18(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_20(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_19(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_21(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_20(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_22(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_21(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_23(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_22(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_24(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_23(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_25(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_24(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_26(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_25(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_27(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_26(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_28(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_27(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_29(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_28(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_30(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_29(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_31(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_30(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_32(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_31(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_33(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_32(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_34(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_33(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_35(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_34(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_36(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_35(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_37(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_36(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_38(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_37(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_39(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_38(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_40(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_39(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_41(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_40(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_42(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_41(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_43(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_42(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_44(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_43(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_45(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_44(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_46(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_45(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_47(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_46(f_, __VA_ARGS__))
#define MARSHALLING_BIT_ACC_FUNC_48(f_, n_, ...) \
    MARSHALLING_BIT_ACC_FUNC(f_, n_)             \
    MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_47(f_, __VA_ARGS__))

#define MARSHALLING_CHOOSE_BIT_ACC_FUNC_(N, f_, ...) MARSHALLING_EXPAND(MARSHALLING_BIT_ACC_FUNC_##N(f_, __VA_ARGS__))
#define MARSHALLING_CHOOSE_BIT_ACC_FUNC(N, f_, ...) \
    MARSHALLING_EXPAND(MARSHALLING_CHOOSE_BIT_ACC_FUNC_(N, f_, __VA_ARGS__))
#define MARSHALLING_DO_BIT_ACC_FUNC(f_, ...) \
    MARSHALLING_EXPAND(MARSHALLING_CHOOSE_BIT_ACC_FUNC(MARSHALLING_NUM_ARGS(__VA_ARGS__), f_, __VA_ARGS__))
#endif    // MARSHALLING_DETAIL_BIT_ACCESS_HPP
