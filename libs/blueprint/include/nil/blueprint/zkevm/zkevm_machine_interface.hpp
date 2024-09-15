//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

            zkevm_machine_interface(unsigned long int _init_gas) : gas(_init_gas), pc(1) {}

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
                opcode = _opcode;
                stack = zkevm_stack(_stack);
                memory = _memory;
                gas = _gas;
                pc = _pc;
                additional_input = _additional_input;
            }

            // This function will be used for small tests.
            void apply_opcode(
                zkevm_opcode _opcode,
                word_type   param
            ){
                opcode = _opcode;
                additional_input  = param;
            }

            void padding_state(){
                opcode = zkevm_opcode::padding;
                stack = {};
                memory = {};
                gas = 0;
                pc = 0;
            }

            zkevm_opcode opcode;
            zkevm_stack stack;
            std::vector<uint8_t> memory;
            std::size_t gas;
            std::size_t pc;
            word_type   additional_input;
        };
    }
}
