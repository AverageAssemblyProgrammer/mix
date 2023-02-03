#!/usr/bin/env python3
import string
import sys
import subprocess
import shlex
import random

from libs.Lexer import *
from libs.Parser import * 

MIX_EXT = '.mix'

# TODO: right now, we do a little bit of simulation within the compilation, get rid of it

def read_file(program : str):
    with open(program, 'r') as fd:
        program = fd.read()
    return program

def usage(err : int):
    print("Usage: ./main.py SUBCOMMAND file_path")
    print("./main.py  |  com    |  input file path    - compiles the program")
    print("./main.py  |  help   |  None               - prints this help screen and exits with exit code 0")
    
    if err == 0:
        exit(0)
    else:
        exit(err)

def check_s(subc):
    if subc == "com":
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
            # thanks tsodin
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
            nEof = True
            strs = []
            while len(tokens) > self.ip:
                assert(len(KEYWORDS) == 2), "Exhaustive handling of keywords in generate_nasm_x86_64_assembly"
                asm.write(f"addr_{self.ip}:\n")
                if tokens[self.ip][0].type == TT_KEYWORD:
                    if tokens[self.ip][0].value == "print":
                        self.advance()
                        if tokens[self.ip][0].type != TT_LPAREN:
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `(` but got `{tokens[self.ip+1][0].type}`')
                            return err
                        self.advance()
                        
                        if tokens[self.ip][0].type == TT_INT:
                            num = int(tokens[self.ip][0].value)
                            asm.write(f'    ;; -- print -- \n')
                            asm.write(f'    mov rdi, {num}\n')
                            asm.write(f'    call print\n')
                            
                        self.advance()
                        if tokens[self.ip][0].type != TT_RPAREN:
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `)` but got `{tokens[self.ip+1].type}:{tokens[self.ip+1][0].value}`')
                            return err
                        self.advance()
                        
                    elif tokens[self.ip][0].value == "puts":
                        self.advance()
                        if tokens[self.ip][0].type != TT_LPAREN:
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `(` but got `{tokens[self.ip+1][0].type}`')
                            return err
                        self.advance()
                        
                        if tokens[self.ip][0].type == TT_STRING:
                            nl = False
                            tmp = 0
                            string = tokens[self.ip][0].value
                            while tmp < len(string):
                                if string[tmp] == "\\":
                                    if string[tmp+1] == "n":
                                        nl = True
                                tmp += 1
                                
                            if nl:
                                str_len    = len(string) - 1
                            else:
                                str_len    = len(string)
                                
                            asm.write(f'    mov rax, 1\n')
                            asm.write(f'    mov rdi, 1\n')
                            asm.write(f'    mov rsi, str_{len(strs)}\n')
                            asm.write(f'    mov rdx, {str_len}\n')
                            asm.write(f'    syscall\n')
                            
                            strs.append(string)
                        else:
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'`puts` intrinsic can only print strings for now')
                            return err 
                            
                        self.advance()
                        
                        if tokens[self.ip][0].type != TT_RPAREN:
                            pos_start = self.pos.copy()
                            err = InvalidSyntaxError(pos_start, self.pos, f'Expected `)` but got `{tokens[self.ip+1].type}:{tokens[self.ip+1][0].value}`')
                            return err
                        self.advance()
                    else:
                        pos_start = self.pos.copy()
                        err = InvalidSyntaxError(pos_start, self.pos, f'{tokens[self.ip][0]}')
                        return err
                    
                elif tokens[self.ip][0].type == TT_IDENTIFIER:
                    if tokens[self.ip][0].value == OP_IF:
                        assert len(tokens[self.ip]) == 2, "`if` instruction does not have a reference to the end of its block."
                        end_pos = tokens[self.ip][1]
                        nfoundee = True
                        
                        while (nfoundee):
                            self.advance()
                            if tokens[self.ip][0].type == TT_EOF:
                                pos_start = self.pos.copy()
                                err = InvalidSyntaxError(pos_start, self.pos, f'`if` instruction needs the `==` sign for comparison for now?')
                                return err
                            elif tokens[self.ip][0].type == TT_EE:
                                nfoundee = False
                                
                        num1 = int(tokens[self.ip-1][0].value)
                        num2 = int(tokens[self.ip+1][0].value)
                        self.advance()
                        
                        # TODOOO: add EE to its own NODE (if-statement) for easy code like:
                        # if 1
                        # <op>
                        # <op>
                        # end
                        
                        # instead of
                        # if 1 == 1
                        # <op>
                        # <op>
                        # end
                        
                        #---EE---#
                        asm.write(f"    ;; -- EE --\n")
                        asm.write(f"    push {num1}\n")
                        asm.write(f"    push {num2}\n")
                        
                        asm.write("    mov rcx, 0\n")
                        asm.write("    mov rdx, 1\n")
                        asm.write("    pop rax\n")
                        asm.write("    pop rbx\n")
                        asm.write("    cmp rax, rbx\n")
                        asm.write("    cmove rcx, rdx\n")
                        asm.write("    push rcx\n")
                        #---END EE---#

                        #---IF----#
                        asm.write("    ;; -- IF --\n")
                        asm.write("    pop rax\n")
                        asm.write("    test rax, rax\n")
                        asm.write("    jz addr_%d\n" % end_pos)
                        #---END IF---#
                        self.advance()
                        
                    elif tokens[self.ip][0].value == OP_ELSE:
                        assert len(tokens[self.ip]) == 2, "`else` instruction does not have a reference to the end of its block."
                        asm.write(f"    jmp addr_{tokens[self.ip][1]}\n")
                        self.ip += 1
                        asm.write("addr_%d:\n" % self.ip)
                        
                    elif tokens[self.ip][0].value == OP_END:
                        asm.write("addr_%d:\n" % self.ip)
                        
                    else:
                        pos_start = self.pos.copy()
                        err = InvalidSyntaxError(pos_start, self.pos, f'{tokens[self.ip][0]}')
                        return err
                        
                elif tokens[self.ip][0].type == TT_NEWLINE:
                    asm.write("    ;; -- NEWLINE --\n")
                    self.advance(str('\\n'))
                elif tokens[self.ip][0].type == TT_EOF:
                    nEof = False
                    asm.write(f'    ;; -- EOF --\n')
                    asm.write(f'    mov rax, 60\n')
                    asm.write(f'    mov rdi, 0\n')
                    asm.write(f'    syscall\n')
                    asm.write(f'segment .data\n')
                    for st in range(len(strs)):
                        string = bytes(strs[st], 'utf-8').decode('unicode_escape')
                        bs = "db " + ','.join(map(hex, bytes(string, 'utf-8')))
                        asm.write(f'    str_{st}: {bs}\n')
                else:
                    pos_start = self.pos.copy()
                    err = InvalidSyntaxError(pos_start, self.pos, f'{tokens[self.ip][0]}')
                    return err
                
                self.advance()

            if nEof:
                asm.write(f'    ;; -- EOF --\n')
                asm.write(f'    mov rax, 60\n')
                asm.write(f'    mov rdi, 0\n')
                asm.write(f'    syscall\n')
                asm.write(f'segment .data\n')
                for st in range(len(strs)):
                    string = bytes(strs[st], 'utf-8').decode('unicode_escape')
                    bs = "db " + ','.join(map(hex, bytes(string, 'utf-8')))
                    asm.write(f'    str_{st}: {bs}\n')
                        
        self.generate_output(basepath, MIX_EXT)
        
    def advance(self, current_char=None):
        self.ip += 1
        if current_char:
            self.pos.advance(current_char)
        else:
            self.pos.advance(None)
        
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
    
    lexer         = Lexer(file_path, program)
    tokens, error = lexer.make_tokens()
    if error:
        print(error.as_string())
        exit(1)

    parser = Parser(tokens, file_path, program)
    tokens, error1 = parser.parse_tokens()
    if error1:
        print(error.as_string())
        exit(1)

    if subcommand == "com":
        compi = Compiler(program, tokens, file_path, MIX_EXT)
        err = compi.compile_program()
        if err:
            print(err.as_string())
            exit(1)
    elif subcommand == "help":
        usage(0)
    else:
        pass
    
if __name__ == '__main__':
    main()
