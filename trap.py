import logging
from mitmproxy.http import HTTPFlow
from mitmproxy.log import ALERT
from logging import getLogger
from vultrap.loader import TrapRuleLoader
from vultrap.eval.expr import Expr
import time
from watchdog.observers import Observer
import threading
from watchdog.events import FileSystemEventHandler
import os

logger = getLogger("flow-trap")
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter("%(asctime)s [%(module)s#%(lineno)d] %(levelname)s %(message)s", '%Y-%m-%d %H:%M:%S'))
logger.addHandler(log_handler)

expr = Expr(import_functions={})


TRAP_RULE_DIR = os.environ["TRAP_RULE_DIR"]
rules_loader = TrapRuleLoader(rule_dir=TRAP_RULE_DIR)
class ReloadRuleHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"moitor file modify: {event.src_path}, reaload")
        if not event.is_directory and event.src_path.endswith('.yml'):
            rules_loader.load_rules()

def rule_modify_monitor(rule_dir: str):
    """
    规则监控
    :return:
    """
    event_handler = ReloadRuleHandler()
    observer = Observer()
    observer.schedule(event_handler, rule_dir, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()


t = threading.Thread(target=rule_modify_monitor,daemon=True)
t.start()

def alert(text): logging.log(ALERT, text)

class HandleRequest:
    def __init__(self):
        self.counter_request = {}

    def response(self, flow: HTTPFlow):
        host = flow.request.host
        try:
            state_info = flow.response.get_state()
            flow_path = flow.request.path
            flow_body = flow.request.text
            flow_method = flow.request.method

            TRAP_RULES = rules_loader.rules
            for key,trap_rule in TRAP_RULES.items():
                for trap in trap_rule.traps:
                    path = trap.request.path
                    # headers = trap.request.headers # headers 后续处理
                    data = trap.request.body or ""
                    method = trap.request.method
                    if method == flow_method and data == flow_body and path == flow_path:
                        state_info["status_code"] = trap.response.status_code
                        flow.response.set_state(state_info)
                        headers = trap.response.headers or {"Content-Type": "text/html"}
                        for k,v in headers.items():
                            flow.response.headers[k] = v
                        resp = trap.response.body or "403 forbidden"
                        resp = expr.eval_with_string(resp)
                        flow.response.set_text(text=resp)
                        return

            state_info["status_code"] = 200
            flow.response.set_state(state_info)
            flow.response.headers["Content-Type"] = "text/html"
            flow.response.set_text(text="403 forbidden")
            return

        except Exception as e:
            logger.exception(f"{host} -> {e}")

addons = [HandleRequest()]
