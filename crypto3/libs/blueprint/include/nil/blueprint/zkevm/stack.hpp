//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <stack>

#include <nil/blueprint/zkevm/zkevm_word.hpp>

namespace nil {
    namespace blueprint {

        class zkevm_stack {
        public:
            using word_type = zkevm_word_type;

            void push(const word_type& word) {
                stack.push(word);
            }

            word_type pop() {
                word_type word = stack.top();
                stack.pop();
                return word;
            }

            word_type top() {
                return stack.top();
            }

            void swap() {
                word_type a = pop();
                word_type b = pop();
                push(a);
                push(b);
            }

            void dup() {
                word_type a = pop();
                push(a);
                push(a);
            }
        private:
            std::stack<word_type> stack;
        };
    }   // namespace blueprint
}   // namespace nil
