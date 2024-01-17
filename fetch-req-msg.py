import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def open_wordlist(path):
    wordlist = []
    with open(path, 'r') as file:
        for line in file:
            wordlist.append(line.strip())
    return wordlist

def main(args):
    url = args[0]
    wordlist_file = args[1]
    wordlist = open_wordlist(wordlist_file)
    for word in wordlist:
        res = requests.get(url + word, verify=False)
        if 'No API Key provided' not in res.text:
            print(f"Message {res.text} at endpoint {url+word}\n")

if __name__ == '__main__':
    argv = sys.argv
    if len(argv) != 3:
        print("Usage: fetch-req-msg.py <URL> <WORDLIST>")
        exit(0)
    main(argv[1:])
