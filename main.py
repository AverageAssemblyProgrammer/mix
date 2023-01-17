#!/usr/bin/env python3
import string
import sys

import Lexer

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
        pass
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
        print("ERROR: No file path given")
        usage(1)
        
def main():
    subcommand, file_path = get_args()
    check_s(subcommand)
    program = read_file(file_path)
    
    lexer = Lexer.Lexer('<stdin>', program)
    tokens, error = lexer.make_tokens()
    if error: print(error)
    

if __name__ == '__main__':
    main()
