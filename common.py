#!/usr/bin/env python
#-*- coding: utf-8 -*-
import re
import sys


def parse_config_file():
    fp = file('config.ini')
    cobj = re.compile(r'(\w+)\s*=\s*([^\s]+)')
    config = []
    for ln in fp:
        if ln.strip() is not "":
            config.append(cobj.match(ln.strip()).groups())
    return dict(config)

def parse_proto(conf):
    ''' parse the proto for server configure'''
    return re.match(r'(tcp|udp)://(\d+):\[(\d+\.\d+\.\d+\.\d+):(\d+)\]', conf).groups()

def parse_server(conf):
    ''' parse the proto for server configure'''
    return re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', conf).groups()

def parse_cli_params():
    '''parse param form command line'''
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-n", "--name", dest="name", type='string',
                      help="the name registerd in PROXY", metavar='cache')
    parser.add_option("-b", "--bind", dest="bind", type='string',
                      metavar="tcp://127.0.0.1:8881",
                      help="bind this server address")
    parser.add_option("-s", "--server", dest="server", type='string',
                      metavar="tcp://127.0.0.1:11211",
                      help="interactive with this server")

    (options, sys.argv[1:]) = parser.parse_args()
    return options
