#! /usr/bin/python
import sys
import subprocess

def write_stdout(s):
    sys.stdout.write(s)
    sys.stdout.flush()

def write_stderr(s):
    sys.stderr.write(s)
    sys.stderr.flush()

def main(args):
    while 1:
        write_stdout('READY\n')
        line = sys.stdin.readline()
        write_stderr(line)
        headers = dict([ x.split(':') for x in line.split() ])
        data = sys.stdin.read(int(headers['len']))
        res = subprocess.call(args, stdout=sys.stderr)
        write_stderr(data)
        write_stdout('RESULT 2\nOK')

if __name__ == '__main__':
    main(sys.argv[1:])
