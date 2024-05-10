import ast
import re
from typing import Any,List,Dict,Callable
import logging

logger = logging.getLogger()

from pydantic import BaseModel

AST_ALLOW_NODES = [
    "Call",
    "Expression",
    "Name",
    "Load",
    "Constant",
]

class AstValidatorOptions(BaseModel):
    allow_nodes: List[str]
    allow_functions: Dict[str,Any]
    allow_attributes: List = []


class AstValidator(ast.NodeVisitor):
    def __init__(self,options: AstValidatorOptions):
        # AST 语法转换
        self.options = options

    def generic_visit(self, node):
        """Check node, raise exception if node is not in whitelist."""
        if type(node).__name__ in self.options.allow_nodes:
            if isinstance(node, ast.Attribute):
                if node.attr not in self.options.attributes:
                    raise SyntaxError("Attribute {aname} is not allowed".format(aname=node.attr))

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id not in self.options.allow_functions:
                        raise SyntaxError("Call to function {fname}() is not allowed".format(fname=node.func.id))
                elif isinstance(node.func, ast.Attribute):
                    pass
                    print("attr:", node.func.attr)
                else:
                    raise SyntaxError('Indirect function call')

            ast.NodeVisitor.generic_visit(self, node)
        else:
            raise SyntaxError("Node type {optype!r} is not allowed. (whitelist it manually)".format(optype=type(node).__name__))




def expression(expr:str,data: Dict[str,Any],functions: Dict[str,Callable]) -> Any:
    """
    语法解析
    :param expr:
    :param data:
    :param functions:
    :return:
    """
    node = ast.parse(expr, '<usercode>', 'eval')

    validator_options = AstValidatorOptions(
        allow_nodes = AST_ALLOW_NODES,
        allow_functions = functions,
        allow_attributes = []
    )
    ast_validator = AstValidator(validator_options)
    ast_validator.visit(node)

    result = eval(expr, functions, data)
    return result


class Expr:
    """
    表达式执行
    """
    def __init__(self,import_functions: Dict[str,Callable]):
        self.import_functions = import_functions


    def eval(self,expr,data: Dict[str,Any] = {}) -> Any:
        """
        表达式执行
        """
        return expression(expr=expr,data=data,functions=self.import_functions)

    def eval_with_string(self,expression: str, data: Dict[str,Any] = {}):
        """
        语法执行
        """
        matches = re.finditer("(\{\{(.*?)\}\})", expression)
        for match in matches:
            macth_string = match.groups()[0]
            code = match.groups()[1]
            try:
                eval_code = self.eval(code,data)
                expression = expression.replace(macth_string, str(eval_code))
            except Exception as e:
                logger.warning(f"eval error: {e} code: {code}")
        return expression

