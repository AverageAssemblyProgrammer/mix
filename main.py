#!/usr/bin/env python3
import string

# Mix programming language

LETTERS = string.ascii_letters
DIGITS = '0123456789'
LETTERS_DIGITS = LETTERS + DIGITS

KEYWORDS = [
    "printh"
]

class Lexer:
    def __init__(self, idx : int, program : str):
        # TODO: implement the storage of line and token position for future error reporting
        self.idx = idx
        self.program = program

    def make_identifier(self, tmp : str):
        if tmp == 'printh':
            self.tokens.append(f"IDENTIFIER:{tmp}")

    def make_number(self, char : str):
        tmp_idx = self.idx
        post = self.program[tmp_idx+1]
        num = ''
        
        while post in DIGITS: 
            print(f"ERROR: number lexing hasn't been implemented yet: {char}")
            exit(-1)
            
        
    def tokenize(self):
        tokens = []
        self.tokens = tokens 
        tmp = ''
        while self.idx < len(self.program):
            tmp += self.program[self.idx]
            
            if tmp in KEYWORDS:
                # self.tokens.append(f"IDENTIFIER: {tmp}")
                self.make_identifier(tmp)
                tmp = ""
            elif tmp in DIGITS:
                self.make_number(tmp)
                tmp = ""
            elif tmp == "(":
                self.tokens.append(f"{tmp}")
                tmp = ""
            elif tmp == ")":
                self.tokens.append(f"{tmp}")
                tmp = ""
                
            self.idx += 1
            
        # print(self.program[:-1], end='')
        print(self.tokens)
        return self.program
        
    def lex(self):
        prg = self.tokenize()
        

def read_file(program : str):
    with open(program, 'r') as fd:
        program = fd.read()
    return program

def main():
    file_path = "example.test"
    program = read_file(file_path)

    lexer = Lexer(0, program)
    program = lexer.lex()

if __name__ == '__main__':
    main()
