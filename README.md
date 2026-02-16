# pyrfc6266

![Tests](https://github.com/SemanticMatter/pyrfc6266/actions/workflows/main.yml/badge.svg?branch=master)

> **Note**: This package is a fork of [JohnDoee/pyrfc6266](https://github.com/JohnDoee/pyrfc6266), which is no longer maintained.
> The [original README](https://github.com/JohnDoee/pyrfc6266?tab=readme-ov-file#pyrfc6266).

A python implementation of RFC 6266 meant to replace [g2p/rfc6266](https://github.com/g2p/rfc6266) as it relies on LEPL.

This implementation relies on pyparsing.

## Installation

```shell
pip install pyrfc6266
```

## Usage

Parse a content-disposition header into its components:

```python
import pyrfc6266

pyrfc6266.parse('attachment; filename="foo.html"')
("attachment", [ContentDisposition(name="filename", value="foo.html")])
```

Parse a header into a useful filename:

```python
import pyrfc6266

pyrfc6266.parse_filename('attachment; filename="foo.html"')
"foo.html"
```

Turn a requests response into a filename:

```python
import requests
import pyrfc6266

response = requests.get(
    "http://httpbin.org/response-headers?Content-Disposition=attachment;%20filename%3d%22foo.html%22"
)
pyrfc6266.requests_response_to_filename(response)
"foo.html"
```

## License

[MIT](LICENSE)
