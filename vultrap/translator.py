from .rule import TrapRule
from typing import Optional
import logging
import os.path
import yaml
from .translators.nuclei import (NucleiTemplate,TemplateParseError)
from .util import iter_dir_files,HttpRawParseError
from http.client import HTTPException
from typing import Iterator

logger = logging.getLogger("vultrap")


def tran_nuclei_template_to_trap(template_code: str) -> Optional[TrapRule]:
    """
    转换nuclei 模板为trap rule

    Args:
        template_code:

    Returns:

    """
    template_obj = yaml.safe_load(template_code)
    if not template_obj.get("http"):
        logger.warning("Non-http protocol templates are not supported for the time being.")
        return None
    try:
        template = NucleiTemplate(**template_obj)
        trap_rule = template.to_trap_rule()
        return trap_rule
    except TemplateParseError as e:
        logger.debug(f"template parser error: {e}")
    except SyntaxError as e:
        logger.warning(f"Parse expr syntax error: {e}")
    except HttpRawParseError as e:
        logger.warning(f"Parse raw request error: {e}")
    except HTTPException as e:
        logger.warning(f"Parse raw request error: {e}")
    except Exception as e:
        logger.error(e)
        raise e


class MaximumErr(Exception): pass


def parse_nuclei_tempaltes(template_dir: str, trap_rule_dir: Optional[str] = None, max_unknow_err: int = 50) -> Iterator[TrapRule]:
    """
    解析nuclei 模板

    Args:
        template_dir:
        trap_rule_dir:

    Returns:
        Iterator[TrapRule]

    Raises:
        MaximumErr: Maximum number of errors exceeded

    """
    unkonwn_err_count = 0
    for dir, filename in iter_dir_files(template_dir, suffix=".yaml"):
        filepath = os.path.join(dir, filename)
        with open(filepath) as f:
            try:
                trap_rule = tran_nuclei_template_to_trap(f.read())
                if trap_rule:
                    if trap_rule_dir:
                        trap_rule_path = filepath.replace(template_dir, trap_rule_dir)
                        dir, _ = os.path.split(trap_rule_path)
                        os.makedirs(dir, exist_ok=True)
                        with open(trap_rule_path, "w") as ft:
                            ft.write(trap_rule.model_dump_yaml())
                    yield trap_rule
            except Exception as e:
                logger.error(f"Unknown error: {e}")
                unkonwn_err_count += 1
                if unkonwn_err_count > max_unknow_err:
                    raise MaximumErr("Maximum number of errors exceeded")