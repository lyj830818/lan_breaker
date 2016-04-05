#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

DEBUG = False
def dump_dict(obj,force = False, format = 'console'):
    if not DEBUG and not force:
        return

    output = []

    if format == 'console':
        print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'
    elif format == 'html':
        output.append('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>')
    for key in obj:
        print '-------------------------------------------'
        for attr in dir(obj.get(key)):
            if re.match(r'^__.+__$',attr):
                continue

            if format == 'console':
                print "%s.%s = %s" % (key, attr, getattr(obj.get(key), attr))
            elif format == 'html':
                output.append("%s.%s = %s" % (key, attr, getattr(obj.get(key), attr)))

        if format == 'console':
            print '-------------------------------------------'
        elif format == 'html':
            output.append('-------------------------------------------')

    if format == 'console':
        print '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
    elif format == 'html':
        output.append('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')

    if format == 'html':
        return "\n".join(output)


def dump_obj(obj, force = False, format = 'console'):
    if not DEBUG and not force:
        return

    output = []
    if format == 'console':
        print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'
    elif format == 'html':
        output.append('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>')

    for attr in dir(obj):
        if re.match(r'^__.+__$', attr):
            continue
        if format == 'console':
            print "%s.%s = %s" % (obj, attr, getattr(obj, attr))
        elif format == 'html':
            output.append("%s.%s = %s" % (obj, attr, getattr(obj, attr)))

    if format == 'console':
        print '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
    elif format == 'html':
        output.append('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')

    if format == 'html':
        return "\n".join(output)


class SockItem:
    seq_counter = 1

    def __init__(self):
        self.sequence = self.seq_counter
        self.seq_counter += self.seq_counter
        self.type = ''
        self.server_tunnel_sock = None
        self.server_app_sock = None
        self.client_tunnel_sock = None
        self.client_app_sock = None
        self.client_app_sequence = 0
        self.client_tunnel_sequence = 0
        self.server_app_sequence = 0
        self.server_tunnel_sequence = 0
        self.status = ''
        self.to_send = ''
        # 这两个只有tunnel关心
        self.last_recv_time = None
        self.dida_last_send_time = None

    def reset_server_tunnel(self):
        self.type = 'server_tunnel'
        self.status = 'unused'
        self.to_send = ''


if __name__ == '__main__':
    aa = {}
    aa['k1'] = SockItem()
    aa['k2'] = SockItem()
    aa['k1'].sequence = 5
    dump_dict(aa)
