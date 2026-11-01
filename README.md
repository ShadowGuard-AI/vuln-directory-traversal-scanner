# vuln-Directory-Traversal-Scanner

I made this to fuzz URL parameters and upload fields with traversal sequences (../ at three depths) against three files I actually know the contents of: etc/passwd, win.ini, and boot.ini. Each payload is matched against markers from its own file, win.ini against its own section headers, not against another file's. Test URLs are built by parsing the query and replacing only the parameter under test, so a parameter value like "1" cannot rewrite the host or port.

Error status bodies are checked too, because a filter that blocks with a 403 often does it after the file was already resolved. The upload test does not trust a bare status code: it calls a traversal real only when the server created the file (a 201) or the uploaded content can be read back at the escaped path.

A scan that sent nothing, named a parameter that is not in the URL, was given an invalid URL, or had every request fail exits non-zero and prints no clean verdict. The -o output file works in both GET and upload modes.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-directory-traversal-scanner`

## Usage
`python main.py <url> [params]`

Example: `python main.py "http://127.0.0.1:8080/page?file=test.txt"`

## Parameters
- `-h`: Show help message and exit
- `-p`: The parameter to fuzz. Default is all GET parameters.
- `-f`: Path to a file to upload for file upload traversal testing.
- `-d`: Traversal depth (default: 3).
- `-o`: Output file to save results to.

## License
Copyright (c) ShadowGuard-AI
