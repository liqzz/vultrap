import yaml
from pydantic import BaseModel,ConfigDict
from typing import Dict, List

class MatchRequest(BaseModel):
    method: str
    path: str
    headers: dict | None = None
    body: str | None = None


class TrapResponse(BaseModel):
    status_code: int
    headers: dict | None = None # 响应内容
    body: str | None = None# 响应正文


class MatchRule(BaseModel):
    request: MatchRequest
    response: TrapResponse

class TrapRule(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    info: Dict
    traps: List[MatchRule]

    def model_dump_yaml(self,**kwargs) -> str:
        """
        解析为yaml 文本

        Args:
            **kwargs:

        Returns:

        """

        def str_presenter(dumper, data):
            if len(data.splitlines()) > 1:  # check for multiline string
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return dumper.represent_scalar('tag:yaml.org,2002:str', data)

        yaml.SafeDumper.add_representer(str, str_presenter)

        yaml_str = yaml.safe_dump(self.model_dump(**kwargs),allow_unicode=True,sort_keys=False)
        return yaml_str


