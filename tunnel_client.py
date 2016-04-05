#!/usr/bin/env python
#-*- coding: utf-8 -*-

import SocketServer
from collections import defaultdict

import os
import socket
import struct
import sys
import select
import re
from time import sleep, time
from applog import logger
from common import parse_config_file, parse_proto, parse_server


# sockStatus[sock] = {'sequence' : sequence, 'type':'tunnel/app','local_app_sock': when type is tunnel,
#  'remote_app_sequence': xxx , 'remote_tunnel_sequence' : xxx , status:'connect/connected/shutdown_read/closed'}
from debug_helper import dump_dict, dump_obj


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
        self.reset_after_send = False  #用于close app sock后，给tunnel对侧发送shutdown_wr指令后，释放这个tunnel
        # 这两个只有tunnel关心
        self.last_recv_time = None
        self.dida_last_send_time = None

    def reset_client_tunnel(self):
        self.type = 'client_tunnel'
        self.status = 'unused'
        self.to_send = ''
        self.reset_after_send = False


class TunnelPool:

    def __init__(self):
        pass

    def add_tunnel(self, tunnel):
        tmp = SockItem()
        tmp.type = 'client_tunnel'
        tmp.status = 'unused'
        tmp.client_tunnel_sock = tunnel
        tmp.last_recv_time = time()
        sockInfo[tunnel] = tmp

    def choose(self, app):
        tunnel = None
        try:
            tunnel = [s for s in sockInfo if sockInfo.get(s).type == "client_tunnel" and
                      sockInfo.get(s).status == "unused"][0]
        except IndexError, e:
            logger.error("no enough free tunnel")
            return None

        if tunnel:
            tunnel_info = sockInfo.get(tunnel)
            tunnel_info.status = "used"
            if tunnel_info:
                tunnel_info.client_app_sock = app

            app_info = SockItem()
            app_info.type = 'client_app'
            app_info.status = 'connected'
            app_info.server_app_sock = app
            app_info.server_tunnel_sock = tunnel

            return tunnel


def pack_client_tunnel_data(data, tunnel):
    client_tunnel_sock_info = sockInfo.get(tunnel)
    client_app_sock_info = sockInfo.get(client_tunnel_sock_info.client_app_sock)
    data_len = len(data)
    data = struct.pack("!4H", client_tunnel_sock_info.server_tunnel_sequence,
                       client_tunnel_sock_info.server_app_sequence,
                       client_tunnel_sock_info.sequence,
                       client_app_sock_info.sequence if client_app_sock_info != None else 0) + data
    return struct.pack("!i", data_len) + data


def unpack_tunnel_header(data):
    return struct.unpack("!i4H", data)


def client_tunnel_read_action(new_data, tunnel , sts, sas, cts, cas):

    client_tunnel_info = sockInfo.get(tunnel)
    # client_app_info = sockInfo.get(client_tunnel_info.client_app_sock)
    # client_app_sock = client_app_info.client_app_sock
    logger.debug("deal with read action")
    dump_obj(client_tunnel_info)

    if new_data.startswith(magic_str):
        new_data = new_data[magic_len:]
        if new_data.startswith("dida reply"):
            # todo 发现是心跳的回复
            logger.debug("got a dida reply")
            client_tunnel_info.dida_last_send_time = None
        elif new_data.startswith("dida request"):
            # todo 发现是心跳的请求
            logger.debug("got dida request")
            client_tunnel_info.to_send += pack_client_tunnel_data(magic_str + "dida reply", client_tunnel_info.client_tunnel_sock)
        elif new_data.startswith("connect:"):
            logger.debug("tell me to connect app")

            app_name = re.match(r"connect:(.+)\r\n", new_data).groups()[0]
            logger.debug("appname ->%s, appname2port-> %s", app_name, appname2port[app_name])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #todo 连接异常处理
            sock.connect((appname2port[app_name][1], int(appname2port[app_name][2])))
            client_app_info = SockItem()
            client_app_info.type = 'client_app'
            client_app_info.status = 'connected'
            #app sock 不必关心sequence
            # client_app_info.server_tunnel_sequence = sts
            # client_app_info.server_app_sequence = sas
            client_app_info.client_app_sock = sock
            client_app_info.client_tunnel_sock = tunnel
            sockInfo[sock] = client_app_info
            logger.debug("client app info")
            dump_obj(client_app_info)

            client_tunnel_info.client_app_sock = sock
            client_tunnel_info.server_tunnel_sequence = sts
            client_tunnel_info.server_app_sequence = sas

            logger.debug("client tunnel  info")
            dump_obj(client_tunnel_info)
            client_tunnel_info.to_send += pack_client_tunnel_data(magic_str + "connected:" + app_name + "\r\n", tunnel)

        elif new_data.startswith("shutdown_wr"):
            logger.debug("tell me to shutdown_wr")
            client_app_sock = client_tunnel_info.client_app_sock
            client_app_info = sockInfo.get(client_app_sock)
            logger.debug("client app sock %s shutdown_wr" , client_app_sock)
            dump_obj(client_app_info)
            client_app_sock.shutdown(socket.SHUT_WR)
            if client_app_info.status == 'shutdown_rd':
                logger.debug("client app sock %s close", client_app_sock)
                client_app_sock.close()
                del sockInfo[client_app_sock]
                client_tunnel_info.reset_client_tunnel()
                logger.debug("client tunnel sock %s resets ", client_tunnel_info.reset_client_tunnel)
                dump_obj(client_tunnel_info)
            else:
                client_app_info.status = 'shutdown_wr'

    else:
        #转发数据到app
        sockInfo.get(client_tunnel_info.client_app_sock).to_send += new_data


def new_tunnel():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((tunnel_config['addr'], int(tunnel_config['port'])))
    logger.debug("tunnel %s connected", sock)
    tunnel_pool.add_tunnel(sock)
    tunnel_timer[sock] = time()



def maintain_tunnel_pool():
    while len([info for info in sockInfo.values() if info.type == 'client_tunnel' and info.status == 'unused']) < 3:
        sleep(1)
        new_tunnel()

    logger.debug("sockinfo:")
    dump_dict(sockInfo)

def start_poll():
    while True:
        ins = [s for s in sockInfo if (sockInfo.get(s).status != "shutdown_rd" and sockInfo.get(s).type == 'client_app') or
               (sockInfo.get(s).status != "broken" and sockInfo.get(s).type == 'client_tunnel')]
        ous = [s for s in sockInfo if sockInfo.get(s).to_send != '' and
               ( (sockInfo.get(s).status != "shutdown_wr" and sockInfo.get(s).type == 'client_app') or
               (sockInfo.get(s).status != "broken" and sockInfo.get(s).type == 'client_tunnel'))]

        # logger.debug("ins : %s", ins)
        # logger.debug("ous : %s", ous)

        if len(ins) == 0 and len(ous) == 0:
            sleep(1)
            continue

        ready_ins, ready_ous = select.select(ins, ous, [], 3)[:2]
        for sock in ready_ins:
            info = sockInfo.get(sock)
            if info.type == 'client_app':
                tunnel_info = sockInfo.get(info.client_tunnel_sock)

                new_data = sock.recv(8192)
                logger.debug("client app sock %s recv new data %s", sock, repr(new_data))
                if new_data:
                    tunnel_info.to_send += pack_client_tunnel_data(new_data, tunnel_info.client_tunnel_sock)
                else:
                    logger.debug("server app sock %s shutdown_RD", sock)
                    sock.shutdown(socket.SHUT_RD)
                    tunnel_info.to_send += pack_client_tunnel_data( magic_str + "shutdown_wr", tunnel_info.client_tunnel_sock)
                    if info.status == 'shutdown_wr':
                        logger.debug("client app sock %s close and del from sockInfo", sock)
                        sock.close()
                        del sockInfo[sock]
                        tunnel_info.reset_after_send = True
                    else:
                        info.status = 'shutdown_rd'


            if info.type == 'client_tunnel':
                new_data = sock.recv(12)
                logger.debug("tunnel %s recv new data header %s", sock, repr(new_data))
                if new_data and len(new_data) == 12:
                    sockInfo.get(sock).last_recv_time = time()
                    data_len, sts, sas, cts, cas = unpack_tunnel_header(new_data)
                    if data_len > 0:
                        new_data = sock.recv(data_len)
                        logger.debug("tunnel %s recv new data body %s", sock, repr(new_data))
                        client_tunnel_read_action(new_data, sock, sts, sas, cts, cas)
                else:
                    #is a broken tunnel we can copy tunnel data to a new one
                    #todo copy tunnel or close tunnel and app
                    logger.debug("tunnel %s is broken", sock)
                    sockInfo.get(sock).status = 'broken'

        for sock in ready_ous:
            info = sockInfo.get(sock)
            logger.debug("socket %s ready to send", sock)
            logger.debug("before send the info is")
            dump_obj(info)
            to_send = info.to_send

            if info.type == 'client_tunnel':
                shutdown_flag = to_send.find(magic_str + 'shutdown_wr') != -1
                logger.debug("client tunnel send")

            logger.debug("to_send is %s", repr(to_send))
            if to_send:
                nsent = sock.send(to_send)
                info.to_send = to_send[nsent:]

            if info.type == 'client_tunnel':
                have_send_shutdown = shutdown_flag and to_send[nsent:].find(magic_str + 'shutdown_wr') == -1
                if have_send_shutdown and info.reset_after_send:
                    logger.debug("reset tunnel %s", sock)
                    info.reset_client_tunnel()

        #只对空闲tunnel做心跳，非空闲tunnel由app两端保持心跳
        for sock in [s for s in sockInfo if sockInfo.get(s).type == 'client_tunnel' and sockInfo.get(s).status != 'unused']:
            Max_Dida_Interval = 15
            Max_Dida_Timeout = 15
            tunnel_info = sockInfo.get(sock)
            if tunnel_info.dida_last_send_time is not None:
                #检查心跳是否超时，如果超时，设置这个tunnel为broke
                if time() - tunnel_info.dida_last_send_time > Max_Dida_Timeout:
                    logger.debug("dida timeout")
                    logger.debug("tunnel info is")
                    dump_obj(tunnel_info)
                    tunnel_info.status = 'broken'
                    #todo copy tunnel or close tunnel and app
                    tunnel_info.client_tunnel_sock.close()
                    del sockInfo[tunnel_info.client_tunnel_sock]

            else:
                #检查距离上次收到包间隔是否超过30秒
                if time() - tunnel_info.last_recv_time > Max_Dida_Interval:
                    logger.debug("send dida")
                    logger.debug("tunnel info is")
                    dump_obj(tunnel_info)

                    tunnel_info.to_send += pack_client_tunnel_data(magic_str + "dida request", sock)
                    #近似认为加入马上就会被发送
                    tunnel_info.dida_last_send_time = time()


if __name__ == '__main__':
    magic_str = 'tunnel_proto_magic:'
    magic_len = len(magic_str)
    # 实时更新sock的状态
    # sockStatus[sock] = {'sequence' : sequence, 'type':'tunnel/app','local_app_sock': when type is tunnel,
    #  'remote_app_sequence': xxx , 'remote_tunnel_sequence' : xxx , status:'connect/connected/shutdown_read/closed'}
    sockInfo = defaultdict()

    os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
    appname2port = {}
    tunnel_config = {}

    config = parse_config_file()
    tunnel_pool = TunnelPool()

    tunnel_timer = {}

    for name in config:
        if name == "tunnel_server":
            pass

        elif name == "tunnel_client":
            addr, port = parse_server(config[name])
            tunnel_config['addr'] = addr
            tunnel_config['port'] = port
        else:
            #app server
            proto, remote_port, local_addr, local_port = parse_proto(config[name])
            appname2port[name] = (proto, local_addr, local_port)

    maintain_tunnel_pool()

    #这里是无限循环，所以不用join了
    start_poll()



