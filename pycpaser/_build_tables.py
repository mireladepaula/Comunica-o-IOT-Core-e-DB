import sys
sys.path[0:0] = ['.', '..']


from _ast_gen import ASTCodeGenerator
ast_gen = ASTCodeGenerator('_c_ast.cfg')
ast_gen.generate(open('c_ast.py', 'w'))

from pycparser import c_parser

c_parser.CParser(
    lex_optimize=True,
    yacc_debug=False,
    yacc_optimize=True)

import lextab
import yacctab
import c_ast
