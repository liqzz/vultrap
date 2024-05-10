from .rule import TrapRule
from typing import Dict,List
import os
from .util import iter_dir_files
import yaml

def iter_rule_files(rule_dir: str,sufix: str = ".yaml") -> List[str]:
    """
    遍历所有规则文件

    Args:
        rule_dir: 规则目录

    Returns:

    """
    if not os.path.exists(rule_dir):
        raise NotADirectoryError(f"{rule_dir}")

    files = iter_dir_files(rule_dir,suffix=sufix)
    rule_files = [os.path.join(file[0],file[1]) for file in files]
    return rule_files


class TrapRuleLoader:
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(TrapRuleLoader, cls).__new__(cls)
        return cls._instance

    def __init__(self, rule_dir: str):
        """初始化规则加载"""
        self.rule_dir = rule_dir
        self.rules: Dict[str,TrapRule] = {}
        self.load_rules()

    def load_rules(self):
        RULE_FILES = iter_rule_files(rule_dir=self.rule_dir)

        rules = {}
        for rule_file in RULE_FILES:
            rule = self.load_trap_rule(rule_file)
            rules[rule.id] = rule
        self.rules = rules

    def load_trap_rule(self, config_file) -> TrapRule:
        """
        加载规则

        Args:
            config_file:

        Returns:

        """
        with open(config_file, 'r') as file:
            rule_data = yaml.safe_load(file)
        rule_model = TrapRule(**rule_data)  # 转换为配置模型对象
        return rule_model
