import sys
import time
import os
import logging
import requests
import typer
from vultrap import parse_nuclei_tempaltes
import subprocess
import signal
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MITMPROXY_PATH=os.environ["MITMPROXY_PATH"]
DEFAULT_EASYSERVER_WORKDINGDIR=os.environ["EASYSERVER_WORKDINGDIR"]
DEFAULT_TRAP_RULE_DIR=os.environ["TRAP_RULE_DIR"]
DEFAULT_TRAN_NUCLEI_TEMPLATE_PATH=os.environ["TRAN_NUCLEI_TEMPLATE_PATH"]
DEFAULT_NUCLEU_DUMP_RULE_DIR=os.environ["NUCLEU_DUMP_RULE_DIR"]
VULTRAP_HOME_PATH = os.environ["VULTRAP_HOME_PATH"]
DEFAULT_SIMPLE_SERVER_LOG=os.environ["SIMPLE_SERVER_LOG"]
DEFAULT_VULTRAP_SERVER_LOG=os.environ["VULTRAP_SERVER_LOG"]
VULTRAP_SERVER_PORT=os.environ["VULTRAP_SERVER_PORT"]



app = typer.Typer()

logger = logging.getLogger("vultrap")
def init_logger(name: str = "vultrap"):
    """
    init global logger

    Args:
        name: special logger name

    Returns:

    """
    logger = logging.getLogger(name)
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(module)s#%(lineno)d] %(levelname)s %(message)s", '%Y-%m-%d %H:%M:%S'))
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)



@app.command()
def parse(template_path: str = DEFAULT_TRAN_NUCLEI_TEMPLATE_PATH, trap_rule_dir: str = DEFAULT_NUCLEU_DUMP_RULE_DIR, update_nuclei_template: bool = False):
    """
    Convert nuclei templates to camouflage rules
    """
    if not os.path.exists(template_path):
        typer.echo(typer.style(f"Error: Please make sure the nuclei directory exists '{template_path}'!", fg=typer.colors.RED))
        exit(-1)

    if update_nuclei_template:
        logger.info("start reaload nuclei template")
        subprocess.run(["nuclei","-ut"])
    trap_rules = [item for item in parse_nuclei_tempaltes(template_path, trap_rule_dir)]
    typer.echo(typer.style(f"generate trap rule done, count: {len(trap_rules)}", fg=typer.colors.GREEN))


@app.command()
def trapserver(trap_rule_dir: str = DEFAULT_TRAP_RULE_DIR,mitm_bin: str = DEFAULT_MITMPROXY_PATH, server_port: str = VULTRAP_SERVER_PORT):
    """
    strat vul trap server
    """
    easyserver_working_dir = DEFAULT_EASYSERVER_WORKDINGDIR
    command = ["uvicorn", "easyserver:app", "--host", "0.0.0.0", "--port", "8000"]
    fs = open(DEFAULT_SIMPLE_SERVER_LOG,"w")
    fm = open(DEFAULT_VULTRAP_SERVER_LOG, "w")

    easy_process = subprocess.Popen(command, stdout=fs, stderr=fs,cwd=easyserver_working_dir)

    time.sleep(1)
    while True:
        time.sleep(0.1)
        try:
            url = "http://127.0.0.1:8000"
            requests.head(url)
            typer.echo(typer.style(f"start simple server success.", fg=typer.colors.GREEN))
            break
        except Exception as e: pass

    server_env = {"TRAP_RULE_DIR": trap_rule_dir}
    server_command = [mitm_bin, "--mode", "reverse:http://127.0.0.1:8000", "--listen-port", f"{server_port}", "--listen-host", "0.0.0.0", "-s","trap.py"]
    mitm_process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=server_env, cwd=VULTRAP_HOME_PATH)

    typer.echo(typer.style(f"start trap server success.", fg=typer.colors.GREEN))
    def clean():
        typer.echo(typer.style(f"stop simple server", fg=typer.colors.GREEN))
        easy_process.terminate()
        typer.echo(typer.style(f"stop trap server", fg=typer.colors.GREEN))
        mitm_process.terminate()
        fs.close()
        fm.close()

    def signal_handler(signum, frame):
        clean()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        for line in iter(mitm_process.stdout.readline, b''):
            line = line.decode('utf-8')
            print(line, end='')
            fm.write(line)
    except KeyboardInterrupt:
        clean()


if __name__ == '__main__':
    init_logger()
    app()