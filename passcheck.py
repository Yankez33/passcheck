import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'http://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. You are good!')
        return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

# TO RUN THIS PROGRAM YOU NEED TO  ENTER THE PASSWORD IN THE COMMAND LINE (python3...passcheck.py....password to be checked)

# Line 14 - response. status_code returns a number that indicates the status (200 is OK, 404 is Not Found). Python requests are generally used to fetch the content from a particular resource URI.
# Line 20 -Check password if it exists in API response
# Line 21 - Like digest() except the digest is returned as a string of double length, containing only hexadecimal digits. This may be used to exchange the value safely in email or other non-binary environments. hash
# UTF-8 must be used to encode or it will throw an error
# Line 22 - Will store the first 5 characters in a variable. second part will store the remaining characters
# Line 49 will exit you from the program after the check is done

'''url = 'http://api.pwnedpasswords.com/range/' + \
    'CBFDA'  # <<  hashed password first 5 characters
res = requests.get(url)
print(res)
'''
