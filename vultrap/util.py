from typing import TypeVar
import os
import io
from http.client import LineTooLong,HTTPMessage,HTTPException
from http import HTTPStatus
import http
from urllib.parse import urlparse
from typing import Optional,Iterator,Tuple

T = TypeVar("T")


def iter_dir_files(dir,suffix: Optional[str]) -> Iterator[Tuple[str,str]]:
    """
    递归目录下的所有文件

    Args:
        dir: 指定需要递归的目录
        suffix: 指定文件后缀，eg: .yaml

    Returns:

    """
    for root, dirs, files in os.walk(dir):
        for file in files:
            if suffix:
                if str(file).endswith(suffix):
                    yield (root,file)
            else:
                yield (root, file)



class HttpRawParseError(Exception): pass

class HTTPRequestParser:
    """
    http 请求解析
    """
    default_request_version = "HTTP/0.9"
    protocol_version = "HTTP/1.0"

    def __init__(self, http_raw: str | bytes):
        """
        解析原始http raw 请求

        Args:
            http_raw: 原始http raw 请求
        """
        if type(http_raw) == str:
            http_raw = http_raw.encode()
        self.rfile = io.BytesIO(http_raw)
        self.raw_requestline = self.rfile.readline()
        self.parse_request()

    def parse_request(self):
        self.command = None
        self.request_version  = self.default_request_version
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline

        words = requestline.split()
        if len(words) == 0:
            raise HTTPException(f"Invalid HTTP Parse {self.requestline}")
        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]
            if not version.startswith('HTTP/'):
                raise HttpRawParseError("version not startswith HTTP")
            base_version_number = version.split('/', 1)[1]
            version_number = base_version_number.split(".")
            if len(version_number) != 2:
                raise HttpRawParseError("version number != 2")
            version_number = int(version_number[0]), int(version_number[1])
            if version_number >= (2, 0):
                raise HTTPException(HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,"Invalid HTTP version (%s)" % base_version_number)
            self.request_version = version
        if not 2 <= len(words) <= 3:
            raise HTTPException(HTTPStatus.BAD_REQUEST,"Bad request syntax (%r)" % requestline)
        command, path = words[:2]
        self.command, self.path = command, path
        self.headers = http.client.parse_headers(self.rfile,_class=HTTPMessage)
        self.data = ''
        data = self.rfile.read()
        if data:
            self.data = bytes.decode(data)


    def to_dict(self):

        print(self.headers)
        result = {
            "command": self.command,
            "path": self.path,
            "headers": self.headers.items(),
            "request_version": self.request_version,
            "data": self.data
        }
        return result


def get_base_url(url) -> str:
    """
    提取base url

    Args:
        url: 输入指定URL

    Returns:
        str: 返回base url

    """
    parse_result = urlparse(url)
    base_url = f"{parse_result.scheme}://{parse_result.netloc}/"
    return base_url

def parse_raw_to_request(raw:bytes | str) -> dict:
    """

    :param url:
    :param raw:
    :return:
    """
    kwargs = {}
    if type(raw) not in [bytes,str]:
        raise HTTPException(f"Invalid HTTP Raw {raw}")
    http_parser = HTTPRequestParser(raw)
    method = http_parser.command
    path = http_parser.path
    headers = {}
    for hkey,hval in http_parser.headers.items():
        headers[hkey] = hval
    kwargs.setdefault("headers",headers)
    kwargs.setdefault("data", http_parser.data)
    kwargs.setdefault("path", path)
    kwargs.setdefault("method", method)
    return kwargs
