from optparse import OptionParser
import re
from urllib.parse import unquote, quote

decode_count = 3
encode_count = 0
file_name = ""
replace_url = ""
final_payloads = []
output_file = ''


def parse_arguments():
    global file_name, decode_count, encode_count, replace_url, output_file
    usage = "Usage: python ssrf_paymix.py -u replace_url -f file_name -d decode_count -e encode_count -o ouput_file\n\n\tfor more try help -h"

    parser = OptionParser(
        usage=usage)

    # add options
    parser.add_option('-f', dest='file_name',
                      type='string',
                      help='specify the input urls file name',)
    parser.add_option('-u', dest='replace_url',
                      type='string',
                      help='specify the ssrf payload for replace current urls',)
    parser.add_option('-d', dest='decode_count',
                      type='string',
                      help='specify decode count upto a limit ,default is 3',)
    parser.add_option('-e', dest='encode_count',
                      type='string',
                      help='specify the encode count to url encode the payload',)
    parser.add_option('-o', dest='out_file',
                      type='string',
                      help='output file name',)

    (options, args) = parser.parse_args()

    if (options.file_name == None):
        print(parser.usage)
        exit(0)
    else:
        file_name = options.file_name

    if (options.replace_url == None):
        print(parser.usage)
        exit(0)
    else:
        replace_url = options.replace_url

    if options.decode_count is not None:
        if options.decode_count.isnumeric():
            decode_count = int(options.decode_count)
        else:
            print(parser.usage)
            exit(0)
    if options.encode_count is not None:
        if options.encode_count.isnumeric():
            encode_count = int(options.encode_count)
        else:
            print(parser.usage)
            exit(0)
    output_file = options.out_file if options.out_file != None else 'payloads.txt'


def url_encode_payload(domain):
    counter = encode_count
    while counter != 0:
        domain = quote(domain, safe='')
        counter -= 1
    return domain


def file_write():
    unique = list(set(final_payloads))
    data = '\n'.join(unique)
    try:
        with open(output_file, 'w') as writer:
            writer.write(data)
            print('\nOutput file : '+output_file)
    except Exception as e:
        print("Exception in file write "+str(e))


def read_file():
    try:
        with open(file_name, 'r') as f:
            data = (f.read()).split('\n')
    except Exception as e:
        print('Exception in file read : ', e)
    print('Wait .....')
    for url in data:
        if(len(url.strip())) > 0:
            status = re.findall('http', url)
            if len(status) > 1:
                u = url
                i = decode_count
                u = check_url_encoded(u, i)
                if '%' not in u:
                    split_and_replace(u)


def check_url_encoded(u, i):
    try:
        # checking url encoded
        while '%' in u:
            i -= 1
            u = unquote(u)
            if i == 0:
                break
        return u
    except Exception as e:
        print('Exception in check url encoded', e)


def split_and_replace(u):
    try:
        if '?' in u:
            domain, parameters = re.split('\?', u)
            param_split = parameters.split('&')
            index = 0
            for i in (param_split[0:]):
                url_pattern = '^(http|https)://.*'
                param_value = i.split('=')
                if re.match(url_pattern, param_value[1]):
                    param_value[1] = replace_url
                    param_split[index] = "=".join(param_value)
                index += 1
            d = ""
            d += "&".join(param_split)
            if replace_url in d:
                domain += '?'+url_encode_payload(d)
                final_payloads.append(domain)
    except:
        pass


if __name__ == "__main__":
    print('\nSSRF Payload Mixer\n\tReplace urls to ssrf payloads\n')
    parse_arguments()
    read_file()
    file_write()
