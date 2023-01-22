from libs.Lexer import *

class Parser:
    def __init__(self, tokens, basepath, program_, ip = -1):
        self.tokens   = tokens
        self.basepath = basepath
        self.program_ = program_
        self.ip       = ip

        self.pos = Position(-1, 0, -1, basepath, program_)
        self.advance()

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
        
    
    def crossreference_blocks(self, tokens):
        stack = []
        for ip in range(len(tokens)):
            if tokens[ip].value == OP_IF:
                stack.append(ip)
            elif tokens[ip].value == OP_END:
                if_ip = stack.pop()
                assert tokens[if_ip].value == OP_IF, "End can only close if blocks for now"
                pos_start = self.pos.copy()
                tokens[if_ip] = (Token(TT_IDENTIFIER, OP_IF, pos_start, self.pos), ip)
                tokens[ip] = (Token(TT_IDENTIFIER, OP_END, pos_start, self.pos), )
            else:
                tok_type = tokens[ip].type
                tok_val = None
                if tokens[ip].value:
                    tok_val = tokens[ip].value
                else:
                    tok_val = None
                pos_start = self.pos.copy()
                tokens[ip] = (Token(tok_type, tok_val, pos_start, self.pos), )
        return tokens
                       
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
