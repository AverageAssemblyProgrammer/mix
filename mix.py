#!/usr/bin/env python3
import string
import sys
import subprocess
import shlex

from libs.Lexer import *

MIX_EXT = '.mix'

def read_file(program : str):
    with open(program, 'r') as fd:
        program = fd.read()
    return program

def usage(err : int):
    print("Usage: ./main.py SUBCOMMAND file_path")
    print("./main.py  |  com    |  input file path    - compiles the program")
    print("./main.py  |  sim    |  input file path    - simulates the program")
    print("./main.py  |  help   |  None               - prints this help screen and exits with exit code 0")
    
    if err == 0:
        exit(0)
    else:
        exit(err)

def check_s(subc):
    if subc == "com":
        return 
    elif subc == "sim":
        return 
    elif subc == "help":
        return 
    else:
        print(f"ERROR: Unknown Subcommand: {subc}")
        usage(1)
        
def get_args():
    if len(sys.argv) > 2:
        subc  = sys.argv[1]
        file_ = sys.argv[2]
        return subc, file_
    else:
        if len(sys.argv) > 1:
            if (sys.argv[1] == "help"):
                usage(0)
        print("ERROR: No file path given")
        usage(1)

class Simulater:
    def __init__(self, program):
        self.program = program

    def simulate_program(self):
        print("Simulating the program isn't implemented yet")
        exit(1)
        
class Compiler:
    def __init__(self, program_, program, basepath, mix_ext, ip = -1):
        self.program   = program
        self.basepath = basepath
        self.mix_ext   = mix_ext

        self.ip = ip
        self.pos = Position(-1, 0, -1, basepath, program_)
        self.advance()
        
    def endswith_(self, basepath, mix_ext):
      if basepath.endswith(mix_ext):
          basepath = basepath[:-len(mix_ext)]
      return basepath
        
    def generate_nasm_x86_64_assembly(self, tokens, basepath):
        basename = self.endswith_(basepath, MIX_EXT)
        
        with open(basename+".asm", "w") as asm:
            asm.write("BITS 64\n")
            asm.write("segment .text\n")
            asm.write("print:\n")
            asm.write("    mov     r9, -3689348814741910323\n")
            asm.write("    sub     rsp, 40\n")
            asm.write("    mov     BYTE [rsp+31], 10\n")
            asm.write("    lea     rcx, [rsp+30]\n")
            asm.write(".L2:\n")
            asm.write("    mov     rax, rdi\n")
            asm.write("    lea     r8, [rsp+32]\n")
            asm.write("    mul     r9\n")
            asm.write("    mov     rax, rdi\n")
            asm.write("    sub     r8, rcx\n")
            asm.write("    shr     rdx, 3\n")
            asm.write("    lea     rsi, [rdx+rdx*4]\n")
            asm.write("    add     rsi, rsi\n")
            asm.write("    sub     rax, rsi\n")
            asm.write("    add     eax, 48\n")
            asm.write("    mov     BYTE [rcx], al\n")
            asm.write("    mov     rax, rdi\n")
            asm.write("    mov     rdi, rdx\n")
            asm.write("    mov     rdx, rcx\n")
            asm.write("    sub     rcx, 1\n")
            asm.write("    cmp     rax, 9\n")
            asm.write("    ja      .L2\n")
            asm.write("    lea     rax, [rsp+32]\n")
            asm.write("    mov     edi, 1\n")
            asm.write("    sub     rdx, rax\n")
            asm.write("    xor     eax, eax\n")
            asm.write("    lea     rsi, [rsp+32+rdx]\n")
            asm.write("    mov     rdx, r8\n")
            asm.write("    mov     rax, 1\n")
            asm.write("    syscall\n")
            asm.write("    add     rsp, 40\n")
            asm.write("    ret\n")
            asm.write("global _start\n")
            asm.write("_start:\n")

            # print(tokens) 
            
            while len(tokens) > self.ip:
                if tokens[self.ip].type == "KEYWORD":
                    if tokens[self.ip].value == "printh":
                        self.advance()
                        if tokens[self.ip].type != "LPAREN":
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `(` but got `{tokens[self.ip+1].type}`')
                            return err
                        self.advance()

                        # TODO: implement printing of strings
                        # TODO: implement printing of expression typed statements: printh(34+35): output: 69
                        if tokens[self.ip].type == "INT":
                            # print(tokens[self.ip].value)
                            num = tokens[self.ip].value
                            asm.write(f'segment .text\n')
                            asm.write(f'    mov rdi, {num}\n')
                            asm.write(f'    call print\n')
                            
                        self.advance()
                        if tokens[self.ip].type != "RPAREN":
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `)` but got `{tokens[self.ip+1].type}:{tokens[self.ip+1].value}`')
                            return err
                        self.advance()
                        
                elif tokens[self.ip].type == "NEWLINE":
                    pass
                elif tokens[self.ip].type == "EOF":
                    break
                else:
                    pos_start = self.pos.copy()
                    err = Lexer.InvalidSyntaxError(pos_start, self.pos, f'{tokens[self.ip].type}')
                    return err
                
                self.advance()

            asm.write(f'segment .text\n')
            asm.write(f'    mov rax, 60\n')
            asm.write(f'    mov rdi, 0\n')
            asm.write(f'    syscall')
            
        self.generate_output(basepath, MIX_EXT)
        
    def advance(self):
        self.ip += 1
        self.pos.advance()
        
    def generate_output(self, basepath, mix_ext):
        if basepath.endswith(mix_ext):
            basepath = basepath[:-len(mix_ext)]
        print("[INFO] Generating %s" % (basepath + ".asm"))
        self.cmd_echoed(["nasm", "-felf64", basepath + ".asm"])
        self.cmd_echoed(["ld", "-o", basepath, basepath + ".o"])

    def cmd_echoed(self, cmd):
        print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
        subprocess.call(cmd)
        
    def compile_program(self):
        err = self.generate_nasm_x86_64_assembly(self.program, self.basepath)
        if err: return err

        
def main():
    subcommand, file_path = get_args()
    check_s(subcommand)
    program               = read_file(file_path)
    
    lexer         = Lexer('<stdin>', program)
    tokens, error = lexer.make_tokens()
    if error: print(error.as_string())

    # TODO: implement a parser

    if subcommand == "com":
        compi = Compiler(program, tokens, file_path, MIX_EXT)
        err = compi.compile_program()
        if err: print(err.as_string())
    elif subcommand == "sim":
        simu = Simulater(tokens)
        simu.simulate_program()
    elif subcommand == "help":
        usage(0)
    else:
        pass
    
if __name__ == '__main__':
    main()
