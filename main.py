import argparse
import logging
import requests
import os
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def test_directory_traversal(url, parameter=None, depth=3):
    """
    Tests a URL for directory traversal vulnerabilities.

    Args:
        url (str): The URL to test.
        parameter (str, optional): The parameter to fuzz. Defaults to None.
        depth (int): The directory traversal depth. Defaults to 3.

    Returns:
        list: A list of vulnerable URLs.
    """

    vulnerable_urls = []
    traversal_sequences = ["../" * i for i in range(1, depth + 1)]  # Example: "../", "../../", "../../../"
    filenames = ["etc/passwd", "win.ini", "boot.ini"] # Common files to test for

    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if parameter:
        if parameter not in query_params:
            logging.warning(f"Parameter '{parameter}' not found in URL.  Skipping.")
            return vulnerable_urls

        for sequence in traversal_sequences:
            for filename in filenames:
                modified_url = url.replace(query_params[parameter][0], sequence + filename)
                try:
                    response = requests.get(modified_url, timeout=5)
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                    if "root:" in response.text or "[boot loader]" in response.text: # basic checks for content
                        logging.info(f"Potential directory traversal vulnerability found: {modified_url}")
                        vulnerable_urls.append(modified_url)
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error during request to {modified_url}: {e}")
                except Exception as e:
                    logging.error(f"An unexpected error occurred: {e}")


    else: #Fuzz all the parameters
        for param_name in query_params:
            for sequence in traversal_sequences:
                for filename in filenames:
                    modified_url = url.replace(query_params[param_name][0], sequence+filename)

                    try:
                        response = requests.get(modified_url, timeout=5)
                        response.raise_for_status()

                        if "root:" in response.text or "[boot loader]" in response.text:
                            logging.info(f"Potential directory traversal vulnerability found: {modified_url}")
                            vulnerable_urls.append(modified_url)
                    except requests.exceptions.RequestException as e:
                        logging.error(f"Error during request to {modified_url}: {e}")
                    except Exception as e:
                        logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_urls


def test_file_upload_traversal(url, file_path, depth=3):
    """
    Tests a file upload endpoint for directory traversal vulnerabilities.

    Args:
        url (str): The URL of the file upload endpoint.
        file_path (str): The path to the file to upload.  The filename in this path becomes the vulnerable component.
        depth (int): The directory traversal depth. Defaults to 3.

    Returns:
        bool: True if a vulnerability is found, False otherwise.
    """

    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return False

    traversal_sequences = ["../" * i for i in range(1, depth + 1)] # Example: "../", "../../", "../../../"

    filename = os.path.basename(file_path)

    for sequence in traversal_sequences:
        modified_filename = sequence + filename
        files = {'file': (modified_filename, open(file_path, 'rb'))}  # 'file' is a common field name for file uploads.  This should be customizable in the future.

        try:
            response = requests.post(url, files=files, timeout=10)
            response.raise_for_status()

            #Simple check - a real scanner would have to determine if the file was successfully created in the path
            if response.status_code == 200:
                logging.info(f"Potential directory traversal vulnerability found with filename: {modified_filename}")
                return True #Early return.  First hit is enough.

        except requests.exceptions.RequestException as e:
            logging.error(f"Error uploading file: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    return False


def main():
    """
    Main function to execute the vulnerability scanner.
    """
    args = setup_argparse()

    # Validate URL
    try:
        result = urllib.parse.urlparse(args.url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL")
    except ValueError as e:
        logging.error(f"Invalid URL: {e}")
        return

    # Validate file upload path (if provided)
    if args.file_upload and not os.path.isfile(args.file_upload):
        logging.error("Invalid file upload path.")
        return

    # Perform directory traversal test
    if args.file_upload:
        if test_file_upload_traversal(args.url, args.file_upload, args.depth):
            logging.info("File upload traversal vulnerability detected.")
        else:
            logging.info("No file upload traversal vulnerability detected.")

    else:
        vulnerable_urls = test_directory_traversal(args.url, args.parameter, args.depth)

        if vulnerable_urls:
            logging.info("Vulnerable URLs found:")
            for url in vulnerable_urls:
                logging.info(url)

            # Save to output file if specified
            if args.output:
                try:
                    with open(args.output, "w") as f:
                        for url in vulnerable_urls:
                            f.write(url + "\n")
                    logging.info(f"Vulnerable URLs saved to {args.output}")
                except IOError as e:
                    logging.error(f"Error writing to file: {e}")
        else:
            logging.info("No directory traversal vulnerabilities found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Scan a URL:
#    python vuln_dir_traversal_scanner.py "http://example.com/index.php?page=test.txt"
#
# 2. Scan a URL with a specific parameter to fuzz:
#    python vuln_dir_traversal_scanner.py "http://example.com/index.php?page=test.txt&id=123" -p page
#
# 3. Scan a URL and save the vulnerable URLs to a file:
#    python vuln_dir_traversal_scanner.py "http://example.com/index.php?page=test.txt" -o results.txt
#
# 4. Scan for file upload traversal vulnerability:
#   python vuln_dir_traversal_scanner.py "http://example.com/upload.php" -f test.txt