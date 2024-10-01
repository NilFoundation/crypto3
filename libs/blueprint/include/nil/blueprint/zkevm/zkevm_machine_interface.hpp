//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/stack.hpp>

namespace nil {
    namespace blueprint {
        // at the time I am writing this there is no interface to the zkevm machine
        // this is a placeholder

        // Hi! I added to this placeholder a bit more funtionality that shouldn't be in test assigner and in zkevm_state
        class zkevm_machine_interface {
        public:
            using word_type = zkevm_word_type;

            struct state_type{
                zkevm_opcode opcode;
                word_type   additional_input;
                zkevm_stack stack;
                std::vector<uint8_t> memory;
                std::size_t gas;
                std::size_t pc;

                bool is_error;
                zkevm_opcode error_opcode;

                state_type():is_error(false){}

                state_type(
                    zkevm_opcode _opcode,
                    word_type    _additional_input,
                    zkevm_stack  _stack,
                    std::vector<uint8_t> _memory,
                    std::size_t _gas,
                    std::size_t _pc
                ): opcode(_opcode), additional_input(_additional_input), stack(_stack), memory(_memory), gas(_gas), pc(_pc), is_error(false)
                {}

                zkevm_word_type stack_pop(){
                    if(stack.size() == 0){
                        is_error = true;
                        error_opcode = opcode;
                        opcode = zkevm_opcode::err0;
                        std::cout << "stack_pop error" << std::endl;
                        return 0;
                    }
                    return stack.pop();
                }

                void run_opcode(){
                    using integral_type = boost::multiprecision::number<
                        boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                    switch(opcode) {
                        case zkevm_opcode::PUSH0:
                            stack.push(0);
                            gas-=2;
                            pc++;
                            break;
                        case zkevm_opcode::PUSH1:
                            stack.push(additional_input);
                            gas-=3; pc+=2;
                            break;
                        case zkevm_opcode::PUSH2:
                            stack.push(additional_input);
                            gas-=3; pc+=3;
                            break;
                        case zkevm_opcode::PUSH3:
                            stack.push(additional_input);
                            gas-=3; pc+=4;
                            break;
                        case zkevm_opcode::PUSH4:
                            stack.push(additional_input);
                            gas-=3; pc+=5;
                            break;
                        case zkevm_opcode::PUSH5:
                            stack.push(additional_input);
                            gas-=3; pc+=6;
                            break;
                        case zkevm_opcode::PUSH6:
                            stack.push(additional_input);
                            gas-=3; pc+=7;
                            break;
                        case zkevm_opcode::PUSH7:
                            stack.push(additional_input);
                            gas-=3; pc+=8;
                            break;
                        case zkevm_opcode::PUSH8:
                            stack.push(additional_input);
                            gas-=3; pc+=9;
                            break;
                        case zkevm_opcode::PUSH9:
                            stack.push(additional_input);
                            gas-=3; pc+=10;
                            break;
                        case zkevm_opcode::PUSH10:
                            stack.push(additional_input);
                            gas-=3; pc+=11;
                            break;
                        case zkevm_opcode::PUSH11:
                            stack.push(additional_input);
                            gas-=3; pc+=12;
                            break;
                        case zkevm_opcode::PUSH12:
                            stack.push(additional_input);
                            gas-=3; pc+=13;
                            break;
                        case zkevm_opcode::PUSH13:
                            stack.push(additional_input);
                            gas-=3; pc+=14;
                            break;
                        case zkevm_opcode::PUSH14:
                            stack.push(additional_input);
                            gas-=3; pc+=15;
                            break;
                        case zkevm_opcode::PUSH15:
                            stack.push(additional_input);
                            gas-=3; pc+=16;
                            break;
                        case zkevm_opcode::PUSH16:
                            stack.push(additional_input);
                            gas-=3; pc+=17;
                            break;
                        case zkevm_opcode::PUSH17:
                            stack.push(additional_input);
                            gas-=3; pc+=18;
                            break;
                        case zkevm_opcode::PUSH18:
                            stack.push(additional_input);
                            gas-=3; pc+=19;
                            break;
                        case zkevm_opcode::PUSH19:
                            stack.push(additional_input);
                            gas-=3; pc+=20;
                            break;
                        case zkevm_opcode::PUSH20:
                            stack.push(additional_input);
                            gas-=3; pc+=21;
                            break;
                        case zkevm_opcode::PUSH21:
                            stack.push(additional_input);
                            gas-=3; pc+=22;
                            break;
                        case zkevm_opcode::PUSH22:
                            stack.push(additional_input);
                            gas-=3; pc+=23;
                            break;
                        case zkevm_opcode::PUSH23:
                            stack.push(additional_input);
                            gas-=3; pc+=24;
                            break;
                        case zkevm_opcode::PUSH24:
                            stack.push(additional_input);
                            gas-=3; pc+=25;
                            break;
                        case zkevm_opcode::PUSH25:
                            stack.push(additional_input);
                            gas-=3; pc+=26;
                            break;
                        case zkevm_opcode::PUSH26:
                            stack.push(additional_input);
                            gas-=3; pc+=27;
                            break;
                        case zkevm_opcode::PUSH27:
                            stack.push(additional_input);
                            gas-=3; pc+=28;
                            break;
                        case zkevm_opcode::PUSH28:
                            stack.push(additional_input);
                            gas-=3; pc+=29;
                            break;
                        case zkevm_opcode::PUSH29:
                            stack.push(additional_input);
                            gas-=3; pc+=30;
                            break;
                        case zkevm_opcode::PUSH30:
                            stack.push(additional_input);
                            gas-=3; pc+=31;
                            break;
                        case zkevm_opcode::PUSH31:
                            stack.push(additional_input);
                            gas-=3; pc+=32;
                            break;
                        case zkevm_opcode::PUSH32:
                            stack.push(additional_input);
                            gas-=3; pc+=33;
                            break;
                        case zkevm_opcode::RETURN:
                            stack_pop();
                            stack_pop();
                            pc++; gas -= 2;
                            break;
                        case zkevm_opcode::NOT:{
                            word_type a = stack_pop();
                            word_type not_a = word_type(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular257) - a;
                            stack.push(not_a);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::ADD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a+b);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::SUB:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a-b);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::MUL:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a*b);
                            pc++; gas -=  5;
                            break;
                        }
                        case zkevm_opcode::MULMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            word_type N = stack_pop();
                            stack.push(N? (a * b) % N: 0);
                            pc++; gas -=  8;
                            break;
                        }
                        case zkevm_opcode::ADDMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            word_type N = stack_pop();
                            stack.push(N? (a + b) % N: 0);
                            pc++; gas -=  8;
                            break;
                        }
                        case zkevm_opcode::ISZERO:{
                            word_type a = stack_pop();
                            stack.push(a? 1 : 0);
                            pc++; gas -=  3;
                            break;
                        }
                        case zkevm_opcode::DIV:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<0>(eth_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SDIV:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<0>(eth_signed_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::MOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<1>(eth_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SMOD:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(std::get<1>(eth_signed_div(a, b)));
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::SIGNEXTEND:{
                            word_type b = stack_pop();
                            word_type x = stack_pop();
                            int len = (integral_type(b) < 32) ? int(integral_type(b)) + 1 : 32;
                            integral_type sign = (integral_type(x) << (8*(32-len) + 1)) >> 256;
                            word_type result = word_type((((integral_type(1) << 8*(32-len)) - 1) << 8*len)*sign) +
                                            word_type((integral_type(x) << (8*(32-len) + 1)) >> (8*(32-len) + 1));
                            stack.push(result);
                            pc++; gas -= 5;
                            break;
                        }
                        case zkevm_opcode::BYTE:{
                            word_type i = stack_pop();
                            word_type x = stack_pop();
                            int shift = (integral_type(i) < 32) ? int(integral_type(i)) : 32;
                            stack.push(word_type((integral_type(x) << ((8*shift) + 1)) >> (31*8 + 1)));
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SHL:{
                            word_type a = stack_pop();
                            word_type input_b = stack_pop();
                            int shift = (integral_type(input_b) < 256) ? int(integral_type(input_b)) : 256;
                            stack.push(word_type(integral_type(a) << shift));
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SHR:{
                            word_type a = stack_pop();
                            word_type input_b = stack_pop();
                            int shift = (integral_type(input_b) < 256) ? int(integral_type(input_b)) : 256;
                            integral_type r_integral = integral_type(a) << shift;
                            word_type b = word_type(integral_type(1) << shift);
                            stack.push(word_type::backend_type(r_integral.backend()));
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SAR:{
                            word_type input_a = stack_pop();
                            word_type input_b = stack_pop();
                            word_type a = abs_word(input_a);
                            int shift = (integral_type(input_b) < 256) ? int(integral_type(input_b)) : 256;
                            integral_type r_integral = integral_type(a) << shift;
                            word_type result = is_negative(input_a) ? (
                                                (r_integral == 0)? word_type(zkevm_modulus-1) : negate_word(word_type(r_integral))
                                            ) : word_type(r_integral);
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::AND:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a & b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::OR:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a | b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::XOR:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a ^ b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::GT:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a > b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::LT:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a < b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::EQ:{
                            word_type a = stack_pop();
                            word_type b = stack_pop();
                            stack.push(a == b);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SGT:{
                            word_type x = stack_pop();
                            word_type y = stack_pop();
                            bool result = (!is_negative(x) && is_negative(y));
                            result = result || (is_negative(x) && is_negative(y) && (abs_word(x) < abs_word(y)));
                            result = result || (!is_negative(x) && !is_negative(y) && (abs_word(x) > abs_word(y)));
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::SLT:{
                            word_type x = stack_pop();
                            word_type y = stack_pop();
                            bool result = (is_negative(x) && !is_negative(y));
                            result = result || (is_negative(x) && is_negative(y) && (abs_word(x) > abs_word(y)));
                            result = result || (!is_negative(x) && !is_negative(y) && (abs_word(x) < abs_word(y)));
                            stack.push(result);
                            pc++; gas -= 3;
                            break;
                        }
                        case zkevm_opcode::err0:{
                            BOOST_ASSERT(false);
                            break;
                        }
                        default:
                            std::cout << "Test machine unknown opcode " << opcode_to_string(opcode) << std::endl;
                            BOOST_ASSERT_MSG(false, "Opcode is not implemented inside test machine");
                    }
                }
            };

            zkevm_machine_interface(
                word_type         _bytecode_hash,
                unsigned long int _init_gas
            ) : bytecode_hash(_bytecode_hash) {
                current_state.gas = new_state.gas = _init_gas;
                current_state.pc = new_state.pc = 0;
            }

            // It is not a part of an interface. Real machine will really run here.
            // But we just read a trace from file and completely update our state.
            // This function is for work with trace
            void update_state(
                zkevm_opcode _opcode,
                std::vector<word_type> _stack,
                std::vector<uint8_t> _memory,
                std::size_t _gas,
                std::size_t _pc,
                word_type   _additional_input
            ){
                current_state = state_type(
                    _opcode,
                    _additional_input,
                    zkevm_stack(_stack),
                    _memory,
                    _gas,
                    _pc
                );
                new_state = current_state;
            }

            bool apply_opcode(
                zkevm_opcode _opcode,
                std::vector<std::uint8_t>  param = {}
            ){
                BOOST_ASSERT(!current_state.is_error);
                current_state = new_state;
                current_state.opcode = new_state.opcode = _opcode;
                current_state.additional_input = new_state.additional_input = zkevm_word_from_bytes(param);
                new_state.run_opcode();
                if( new_state.is_error ){
                    current_state.is_error = true;
                    current_state.opcode = new_state.opcode;
                    current_state.error_opcode = new_state.error_opcode;
                }
                return current_state.is_error;
            }

            void padding_state(){
                current_state.opcode = zkevm_opcode::padding;
                current_state.stack = {};
                current_state.memory = {};
                current_state.gas = 0;
                current_state.pc = 0;
                bytecode_hash = 0;
            }

            const state_type &get_current_state() const {
                return current_state;
            }

            const zkevm_opcode &opcode() const {
                return current_state.opcode;
            }

            const zkevm_word_type &additional_input() const {
                return current_state.additional_input;
            }

            const std::size_t pc() const {
                return current_state.pc;
            }

            const std::size_t gas() const {
                return current_state.gas;
            }

/*          const std::vector<word_type> & stack() const {
                return current_state.stack;
            }*/

            const std::size_t stack_size() const {
                return current_state.stack.size();
            }

            const std::size_t memory_size() const {
                return current_state.memory.size();
            }

            const zkevm_word_type stack_top(std::size_t depth = 0) const{
                return current_state.stack.top(depth);
            }

            const std::vector<std::uint8_t> & memory() const {
                return current_state.memory;
            }

            const bool is_error() const {
                return current_state.is_error;
            }

            const zkevm_opcode error_opcode() const {
                return current_state.error_opcode;
            }
            word_type         bytecode_hash;

        private:
            state_type        current_state;
            state_type        new_state;
            bool opcode_added;
        };
    }
}
