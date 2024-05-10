import uuid

import enum

from pydantic import BaseModel,ConfigDict,Field
from typing import List,Optional,Union
from typing import Literal,Callable,Dict
import re
import ast
from .functions import ALL_FUNCTIONS
from ..util import parse_raw_to_request
from ..rule import MatchRule,MatchRequest,TrapRule,TrapResponse


class Info(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    author: Optional[str] = None
    description: Optional[str] = None
    severity: Literal["info","low","medium","high","critical","unknown"]


class Matcher(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Literal["word","regex","binary","status","size","dsl","xpath"]
    condition: Optional[Literal["or","and"]] = None
    part: Optional[str] = None
    status: Optional[List[int]] = None
    size: Optional[List[int]] = None
    words: Optional[List[str]] = None
    regex: Optional[List[str]] = None
    binary: Optional[List[str]] = None
    dsl: Optional[List[str]] = None
    xpath: Optional[List[str]] = None
    encoding: Literal["hex"] = None
    match_all: Optional[bool] = Field(default=None,alias="match-all")



class BaseRequest(BaseModel):
    matchers: Optional[List[Matcher]] = None
    matchers_condition: Literal["and","or"] = Field(default="and",alias="matchers-condition")

class BasicHTTPRequest(BaseRequest):
    method: str
    path: List[str]
    headers: Optional[dict] = None
    body: Optional[str] = None

class RawHTTPRequest(BaseRequest):
    raw: List[str]


def _get_variable(name: str,variables: dict,idx: int = 1) -> Optional[Union[int,str]]:
    result = None
    if idx == 1:
        result = variables.get(name)
        
    if not result:
        item = f"{name}_{idx}"
        result = variables.get(item)
        return result
    else:
        return result

class NucleiTemplate(BaseModel):
    id: str
    info: Info
    variables: Optional[dict] = None
    http: List[Union[BasicHTTPRequest,RawHTTPRequest]]


    def to_trap_rule(self) -> TrapRule:
        match_rules = []
        for http in self.http:
            macther_dsl = tran_matchers_to_dsl(matchers=http.matchers, matchers_condition=http.matchers_condition)
            print(macther_dsl)
            py_expr = tran_nuclei_dsl_to_py_expr(macther_dsl)
            print(py_expr)
            if "\u0000@\u0000" in py_expr:
                raise TemplateParseError("not support null bytes")
            expr_visitor = ExprVisitor(variables=self.variables)
            expr_visitor.visit(ast.parse(py_expr))
            variables = expr_visitor.variables
            match_requests:List[MatchRequest] = []

            if isinstance(http, RawHTTPRequest):
                for raw in http.raw:
                    raw_lines: List[str] = raw.splitlines()
                    if raw_lines[0].strip().startswith("@"):
                        raw = "\r\n".join(raw_lines[1:])
                    raw = raw.replace("HTTP/1.1 HTTP/1.1", "HTTP/1.1")

                    raw_request = parse_raw_to_request(raw)
                    match_request = MatchRequest(
                        method=raw_request["method"],
                        path=raw_request["path"],
                        headers=raw_request["headers"],
                        body=raw_request.get("data", None)
                    )
                    if "{{Hostname}}" in match_request.headers.get("Host",""):
                        match_request.headers.pop("Host")
                    match_requests.append(match_request)

            if isinstance(http, BasicHTTPRequest):
                for path in http.path:
                    match_request = MatchRequest(
                        method=http.method,
                        path=path,
                        headers=http.headers,
                        body=http.body
                    )
                    match_requests.append(match_request)

            for idx,match_request in enumerate(match_requests):
                match_request.path = match_request.path.replace("{{BaseURL}}", "")
                if "{{interactsh-url}}" in match_request.path:
                    raise TemplateParseError("not support {{interactsh-url}}")
                match_request.path = re.sub(r'\{\{(.*?)}}', "", match_request.path )
                idx = idx + 1
                headers = _get_variable("header",variables=variables,idx=idx)
                trap_headers = {}
                if headers:
                    trap_headers = {"VulTrap": headers}
                status_code = _get_variable("status_code",variables=variables,idx=idx) or 200
                body = _get_variable("body",variables=variables,idx=idx) or ""
                trap_response = TrapResponse(
                    status_code=status_code,
                    headers=trap_headers,
                    body=body
                )

                match_rule = MatchRule(
                    request=match_request,
                    response=trap_response
                )
                match_rules.append(match_rule)

        trap_rule = TrapRule(
            id=self.id,
            info=self.info.model_dump(),
            traps=match_rules
        )
        return trap_rule




class HelperFunc(enum.Enum):
    contains = "contains"
    hex_encode = "hex_encode"


class TemplateParseError(Exception): pass

def tran_matchers_to_dsl(matchers: List[Matcher], matchers_condition: Literal["and","or"]) -> Optional[str]:
    if not matchers:
        raise TemplateParseError("not matcher found")

    dsl_list = []
    for matcher in matchers:
        condition = matcher.condition or "and"
        part = matcher.part or "body"
        word_replace = lambda word: word.replace("'", r"\'")
        match matcher.type:
            case "status":
                items = [f"status_code=={status}" for status in matcher.status]
                condition = "or"
            case "size":
                raise TemplateParseError("macth type 'size' not supported")
            case "regex":
                items = [f"{HelperFunc.contains.value}({part},'{word_replace(regex)}')"
                                  for regex in matcher.regex]
            case "binary":
                items = [
                    f"{HelperFunc.contains.value}({HelperFunc.hex_encode.value}({part},\"{binary}\"))" for binary in matcher.binary]
            case "word":
                encoding = matcher.encoding
                if not matcher.words:
                    raise TemplateParseError("matcher words is null")
                if encoding == "hex":
                    items = [f"{HelperFunc.contains.value}({HelperFunc.hex_encode.value}({part},\"{word}\"))" for word in matcher.words]
                else:
                    items = [f"{HelperFunc.contains.value}({part},'{word_replace(word)}')" for word in matcher.words]
            case "dsl":
                items = [fr"({dsl})" for dsl in matcher.dsl]
            case _:
                raise TemplateParseError("Unknown match type")

        if condition == "or":
            dsl = " || ".join(items)
        elif condition == "and":
            dsl = " && ".join(items)
        else:
            raise TemplateParseError(f"Unknow condition {condition}")
        dsl_list.append(dsl)
    if matchers_condition == "or":
        result_dsl = " || ".join(dsl_list)
    elif matchers_condition == "and":
        result_dsl = " && ".join(dsl_list)
    else:
        raise TemplateParseError(f"Unknow condition {matchers_condition}")
    return result_dsl


def tran_nuclei_dsl_to_py_expr(expression) -> str:
    """将nuclei的DSL语法转换为Python的expr解析语法"""
    return_bool_func = [
        'compare_versions', 'contains', 'contains_all', 'contains_any', 'regex',
        'starts_with', 'line_starts_with', 'ends_with', 'line_ends_with'
    ]
    expression = re.sub(r'\s+&&\s+', ' and ', expression)
    expression = re.sub(r'\s+\|\|\s+', ' or ', expression)
    for f in return_bool_func:
        expression = re.sub(fr'!\s*{f}\(', f'not {f}(', expression)
    return expression


class ExprVisitor(ast.NodeVisitor):
    def __init__(self,variables: dict = None,functions: Dict[str,Callable] = ALL_FUNCTIONS):
        self._variables = variables or {}
        for value in self._variables.copy().values():
            if type(value) == str:
                if "{{" and "rand" in value:
                    raise TemplateParseError(f"not support rand variables '{value}'")

        self._variables["randstr"] = uuid.uuid4().hex
        self.functions = functions
        self.variables = {}

    def visit_Compare(self, node):
        left = node.left
        indent = ""
        if type(left) == ast.Name:
            name: ast.Name = left #type: ignore
            indent = name.id
        op = node.ops[0]
        match type(op):
            case ast.Eq: pass
            case _:
                return node
        right = node.comparators[0]
        if type(right) == ast.Constant:
            val: ast.Constant = right #type: ignore
            self.variables[indent] = val.value
        return node

    def visit_UnaryOp(self, node):
        return

    def visit_Call(self, node):

        def replace(match):
            value = match.group(1)
            if re.findall(r'\{\{(.*?)}}',value):
                value = re.sub(r'\{\{(.*?)}}', replace, value)

            try:
                eval_result = eval_expression(variables=self._variables,functions=self.functions,expression=value)
                return eval_result
            except NameError as e:
                raise TemplateParseError(f"{e}")

        func: ast.Name = node.func #type: ignore
        if type(func) != ast.Name:
            return node
        func_name = func.id
        indent = ""
        args = node.args
        match func_name:
            case HelperFunc.contains.value:
                if type(args[0]) == ast.Name:
                    indent = args[0].id #type: ignore

        if len(args) == 1 and type(args[0]) == ast.Call:
            return node

        if type(args[1]) == ast.Constant and indent:
            val = args[1].value #type: ignore
            val = re.sub(r'\{\{(.*)}}', replace, val)

            if self.variables.get(indent):
                self.variables[indent] = self.variables[indent] + val
            else:
                self.variables[indent] = val
        return node


def eval_expression(variables:dict, functions: Dict[str,Callable],expression: str) -> Union[str,bool]:
    """
    执行expression

    Args:
        variables:
        functions:
        expression:

    Returns:

    """
    global_dict = {}
    global_dict.update(variables)
    global_dict.update(functions)
    return eval(expression, global_dict)

