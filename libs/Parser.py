from libs.Lexer import *

class Parser:
    def __init__(self, tokens, basepath, program_, ip = -1):
        self.tokens   = tokens
        self.basepath = basepath
        self.program_ = program_
        self.ip       = ip

        self.pos = Position(-1, 0, -1, basepath, program_)
        self.advance()

    def crossreference_blocks(self, tokens):
        stack = []
        for ip in range(len(tokens)):
            if tokens[ip].value == OP_IF:
                stack.append(ip)

            elif tokens[ip].value == OP_ELSE:
                if_ip = stack.pop()
                assert tokens[if_ip].value == OP_IF, "`else` can only be used in `if`-blocks"
                pos_start = self.pos.copy()
                tokens[if_ip] = (Token(TT_IDENTIFIER, OP_IF, pos_start, self.pos), ip+1)
                stack.append(ip)
                
            elif tokens[ip].value == OP_END:
                block_ip = stack.pop()
                pos_start = self.pos.copy()
                if tokens[block_ip].value == OP_IF or tokens[block_ip].value == OP_ELSE:
                    tokens[block_ip] = (Token(TT_IDENTIFIER, tokens[block_ip].value, pos_start, self.pos), ip)
                else:
                    assert False, "`end` can only close `if-else` blocks for now"
                tokens[ip] = (Token(TT_IDENTIFIER, OP_END, pos_start, self.pos), )
                
            else:   
                pos_start = self.pos.copy()
                iszero = False
                if str(tokens[ip].value).isdigit():
                    if tokens[ip].value == 0:
                        tokens[ip] = (Token(tokens[ip].type, str(0), pos_start, self.pos), )
                        iszero = True
                if not(iszero):
                    tokens[ip] = (Token(tokens[ip].type, tokens[ip].value, pos_start, self.pos), )
                
        return tokens
                
    def expressioner(self, tokens):
        while len(tokens) > self.ip:
            if tokens[self.ip].type == TT_PLUS:
                # 35 + 34
                # 35 69 34
                # 69 34
                # 69
                sum_ = tokens[self.ip-1].value + tokens[self.ip+1].value
                pos_start = self.pos.copy()
                tokens[self.ip] = Token(TT_INT, int(sum_), pos_start, self.pos)
                tokens.pop(self.ip-1)
                tokens.pop(self.ip)
                self.ip -= 1
                # TODO: implement parsing of other operations
            self.advance()

        tmp = 0
        while len(tokens) > tmp:
            if tokens[tmp].type == TT_PLUS:
                self.expressioner(tokens)
            tmp += 1
        return tokens, None
    
    def advance(self):
        self.pos.advance()
        self.ip += 1

    def parse_tokens(self):
        toks, error = self.expressioner(self.tokens)
        toks = self.crossreference_blocks(toks)
        if error:
            return None, error
        else:
            return toks, None
