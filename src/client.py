"""
TFTPy - This module implements an interactive and command line TFTP 
client.

This client accepts the following options:
    $ python3 client.py (get|put) [-p serv_port] server source_file [dest_file] 
    $ python3 client.py [-p serv_port] server

(C) Ana, Mendes 2022
"""

from docopt import docopt

def _main():
    '''
Usage: 
	client.py -h
	client.py <option> [-p serv_port] server remote_file [local_file]

Examples:
	client.py get [-p serv_port] server remote_file [local_file]
	client.py put [-p serv_port] server local_file [remote_file]		

Options:
	-h --help   Show information about the commands
	-g --get    Get a file from server and save it as local_file
	-p --put    Send a file to server and store it as remote_file
	-d --dir    Obtain a listing of remote files. Optional command to be use.
	-q --quit   Exit TFTP client
    '''
#:

if __name__ == '__main__':
    _main()
