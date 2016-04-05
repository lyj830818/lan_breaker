#!/usr/bin/env python
# -*- coding: utf-8 -*-
import BaseHTTPServer
import SocketServer
import pdb
import urlparse
from collections import defaultdict

import os
import socket
import struct
import sys
import select
import threading
from time import sleep, time
import re
from applog import logger
from common import parse_config_file, parse_proto, parse_server


# sockStatus[sock] = {'sequence' : sequence, 'type':'tunnel/app','local_app_sock': when type is tunnel,
#  'remote_app_sequence': xxx , 'remote_tunnel_sequence' : xxx , status:'connect/connected/shutdown_read/closed'}
from debug_helper import dump_obj, dump_dict


class SockItem:
    seq_counter = 1
    sequence = 0
    type = ''
    server_tunnel_sock = None
    server_app_sock = None
    client_tunnel_sock = None
    client_app_sock = None
    client_app_sequence = 0
    client_tunnel_sequence = 0
    server_app_sequence = 0
    server_tunnel_sequence = 0
    status = ''
    to_send = ''
    reset_after_send = False  #用于close app sock后，给tunnel对侧发送shutdown_wr指令后，释放这个tunnel
    # 这两个只有tunnel关心
    last_recv_time = None
    dida_last_send_time = None
    def __init__(self):
        SockItem.seq_counter += 1
        self.sequence = SockItem.seq_counter

    def reset_server_tunnel(self):
        self.type = 'server_tunnel'
        self.status = 'unused'
        self.to_send = ''
        self.reset_after_send = False


class TunnelPool:

    def __init__(self):
        pass

    def add_tunnel(self, tunnel):
        tmp = SockItem()
        tmp.type = 'server_tunnel'
        tmp.status = 'unused'
        tmp.server_tunnel_sock = tunnel
        tmp.last_recv_time = time()
        sockInfo[tunnel] = tmp

    def choose(self, app):
        tunnel = None
        try:
            logger.debug('sockinfo is')
            dump_dict(sockInfo , True)
            tunnel = [s for s in sockInfo if sockInfo.get(s).type == "server_tunnel" and
                      sockInfo.get(s).status == "unused"][0]
        except IndexError, e:
            logger.error("no enough free tunnel")
            return None

        if tunnel:
            tunnel_info = sockInfo.get(tunnel)
            tunnel_info.status = "used"
            if tunnel_info:
                tunnel_info.server_app_sock = app

            app_info = SockItem()
            app_info.type = 'server_app'
            app_info.status = 'connected'
            app_info.server_app_sock = app
            app_info.server_tunnel_sock = tunnel
            sockInfo[app] = app_info

            return tunnel


class TunnelServer(SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        """Constructor.  May be extended, do not override."""
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

    def shutdown_request(self, request):
        pass

    def close_request(self, request):
        # do not do anything
        pass


class TunnelServerHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        #
        tunnel_pool_lock.acquire()
        tunnel_pool.add_tunnel(self.request)
        logger.debug("establist a tunnel %s", self.request)
        tunnel_pool_lock.release()


class AppServer(SocketServer.TCPServer):
    # 类变量
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, name, bind_and_activate=True):
        """Constructor.  May be extended, do not override."""
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        # 实例变量
        self.name = name

    def close_request(self, request):
        # close tunnel and request
        pass

    def shutdown_request(self, request):
        pass


class AppHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        ''' handle each request '''
        tunnel_pool_lock.acquire()
        tunnel = tunnel_pool.choose(self.request)
        logger.debug("establist a new app socket %s <-> %s", self.request, tunnel)
        tunnel_pool_lock.release()

        cmd = magic_str + "connect:" + self.server.name + "\r\n"
        cmd = pack_server_tunnel_data(cmd, tunnel)
        sockInfo.get(tunnel).to_send += cmd

class WebRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_path = urlparse.urlparse(self.path)
        query_str = parsed_path.query
        query_dict = {}
        try:
            query_dict = dict([query_item.split("=") for query_item in query_str.split("&") if query_str != ''])
        except:
            pass
        message = []
        if parsed_path.path == '/read_state':
            if query_dict.get('sockinfo'):
                message.append(dump_dict(sockInfo,True,'html'))

        if parsed_path.path == '/new_sockinfo':
            tmp = SockItem()
            message.append(dump_obj(tmp,True,'html'))

        if parsed_path.path == '/eval.html':
            eval_file = open("eval.html")
            message = eval_file.read(81920)
            #result = eval("dump_dict(sockInfo,True)")
            #message.append(result)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(''.join(message) if message is not None else '')


    def do_POST(self):
        parsed_path = urlparse.urlparse(self.path)
        query_str = parsed_path.query
        query_dict = {}
        try:
            query_dict = dict([query_item.split("=") for query_item in query_str.split("&") if query_str != ''])
        except:
            pass
        data_length = self.headers.getheader('content-length')
        data = self.rfile.read(int(data_length))

        message = []
        if parsed_path.path == '/eval':
            try:
                exec_code = compile(data, '' ,'exec')
                exec( exec_code )
            except:
                logger.debug("exec code error ")
                logger.debug(data)
                pass



class ThreadingHttpServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

def pack_server_tunnel_data(data, tunnel):
    server_tunnel_sock_info = sockInfo.get(tunnel)
    server_app_sock_info = sockInfo.get(server_tunnel_sock_info.server_app_sock)
    data_len = len(data)

    data = struct.pack("!4H", server_tunnel_sock_info.sequence,
                       server_app_sock_info.sequence if server_app_sock_info != None else 0,
                       server_tunnel_sock_info.client_tunnel_sequence,
                       server_tunnel_sock_info.client_app_sequence) + data
    return struct.pack("!i", data_len) + data


def unpack_tunnel_header(data):
    return struct.unpack("!i4H", data)


def server_tunnel_read_action(new_data, tunnel , sts, sas, cts, cas):

    server_tunnel_info = sockInfo.get(tunnel)
    logger.debug("deal with read action")
    dump_obj(server_tunnel_info)

    if new_data.startswith(magic_str):
        new_data = new_data[magic_len:]
        if new_data.startswith("dida reply"):
            # todo 发现是心跳的回复
            logger.debug("dida reply")
            server_tunnel_info.dida_last_send_time = None
        elif new_data.startswith("dida request"):
            # todo 发现是心跳的请求
            logger.debug("got dida request")
            server_tunnel_info.to_send += pack_server_tunnel_data(magic_str + "dida reply", server_tunnel_info.server_tunnel_sock)
        elif new_data.startswith("connected:"):
            #todo
            #连接成功返回:connect success:app_name:client_tunnel_seq:client_app_seq
            logger.debug("connected reply")
            server_tunnel_info.client_tunnel_sequence = cts
            server_tunnel_info.client_app_sequence = cas

        elif new_data.startswith("shutdown_wr"):
            logger.debug("tell server app to shutdown_wr")
            server_app_info = sockInfo.get(server_tunnel_info.server_app_sock)
            server_app_sock = server_app_info.server_app_sock
            logger.debug("server app info is")
            dump_obj(server_app_info)

            server_app_sock.shutdown(socket.SHUT_WR)
            if server_app_info.status == 'shutdown_rd':
                logger.debug("server app %s shutdown close" , server_app_sock)
                server_app_sock.close()
                del sockInfo[server_app_sock]
                server_tunnel_info.reset_server_tunnel()

            else:
                server_app_info.status = 'shutdown_wr'

            logger.debug("tunnel after reset or shutdown_wr")
            dump_obj(server_tunnel_info)

    else:
        #转发数据到app
        sockInfo.get(server_tunnel_info.server_app_sock).to_send += new_data


def start_poll():
    while True:
        tunnel_pool_lock.acquire()
        ins = [s for s in sockInfo if (sockInfo.get(s).status != "shutdown_rd" and sockInfo.get(s).type == 'server_app') or
               (sockInfo.get(s).status != "broken" and sockInfo.get(s).type == 'server_tunnel')]
        ous = [s for s in sockInfo if sockInfo.get(s).to_send != '' and
               ((sockInfo.get(s).status != "shutdown_wr" and sockInfo.get(s).type == 'server_app') or
               (sockInfo.get(s).status != "broken" and sockInfo.get(s).type == 'server_tunnel'))]
        # logger.debug("ins : %s", ins)
        # logger.debug("ous : %s", ous)

        tunnel_pool_lock.release()
        if len(ins) == 0 and len(ous) == 0:
            sleep(1)
            continue

        ready_ins, ready_ous = select.select(ins, ous, [], 5)[:2]
        for sock in ready_ins:
            info = sockInfo.get(sock)
            if info.type == 'server_app':
                tunnel_info = sockInfo.get(info.server_tunnel_sock)

                new_data = sock.recv(8192)
                logger.debug("server app sock %s recv new data %s", sock, repr(new_data))
                if new_data:
                    tunnel_info.to_send += pack_server_tunnel_data(new_data, tunnel_info.server_tunnel_sock)
                else:
                    logger.debug("server app sock %s shutdown_RD", sock)
                    sock.shutdown(socket.SHUT_RD)
                    tunnel_info.to_send += pack_server_tunnel_data( magic_str + "shutdown_wr", tunnel_info.server_tunnel_sock)
                    if info.status == 'shutdown_wr':
                        logger.debug("server app sock %s close and del from sockInfo", sock)
                        sock.close()
                        del sockInfo[sock]
                        tunnel_info.reset_after_send = True

                    else:
                        info.status = 'shutdown_rd'


            if info.type == 'server_tunnel':
                new_data = sock.recv(12)
                logger.debug("tunnel %s recv new data header %s", sock, repr(new_data))
                if new_data and len(new_data) == 12:
                    sockInfo.get(sock).last_recv_time = time()
                    data_len, sts, sas, cts, cas = unpack_tunnel_header(new_data)
                    if data_len > 0:
                        new_data = sock.recv(data_len)
                        logger.debug("tunnel %s recv new data body %s", sock, repr(new_data))
                        server_tunnel_read_action(new_data, sock, sts, sas, cts, cas)
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

            if info.type == 'server_tunnel':
                shutdown_flag = to_send.find(magic_str + 'shutdown_wr') != -1
                logger.debug("server tunnel send")

            logger.debug("to_send is %s", repr(to_send))
            if to_send:
                nsent = sock.send(to_send)
                info.to_send = to_send[nsent:]

            if info.type == 'server_tunnel':
                have_send_shutdown = shutdown_flag and to_send[nsent:].find(magic_str + 'shutdown_wr') == -1
                if have_send_shutdown and info.reset_after_send:
                    logger.debug("reset tunnel %s", sock)
                    info.reset_server_tunnel()



            logger.debug("after send the info is")
            dump_obj(info)

        #只对空闲tunnel做心跳，非空闲tunnel由app两端保持心跳
        for sock in [s for s in sockInfo if sockInfo.get(s).type == 'server_tunnel' and sockInfo.get(s).status == 'unused']:
            Max_Dida_Interval = 15
            Max_Dida_Timeout = 15
            tunnel_info = sockInfo.get(sock)
            if tunnel_info.dida_last_send_time is not None:
                pdb.set_trace()
                #检查心跳是否超时，如果超时，设置这个tunnel为broke
                if time() - tunnel_info.dida_last_send_time > Max_Dida_Timeout:
                    logger.debug("dida timeout")
                    logger.debug("tunnel info is")
                    dump_obj(tunnel_info)
                    tunnel_info.status = 'broken'
                    #todo copy tunnel or close tunnel and app

                    tunnel_info.server_tunnel_sock.close()
                    del sockInfo[tunnel_info.server_tunnel_sock]

            else:
                #检查距离上次收到包间隔是否超过30秒
                if time() - tunnel_info.last_recv_time > Max_Dida_Interval:
                    logger.debug("send dida")
                    logger.debug("tunnel info is")
                    dump_obj(tunnel_info)
                    tunnel_info.to_send += pack_server_tunnel_data(magic_str + "dida request", sock)
                    #近似认为加入马上就会被发送
                    tunnel_info.dida_last_send_time = time()





class ServerThread(threading.Thread):
    def __init__(self, name, server):
        super(ServerThread, self).__init__()  # 调用父类的构造函数
        self.name = name
        self.server = server

    def run(self):
        print "Starting thread " + self.name
        self.server.serve_forever()
        print "Exiting thread" + self.name


if __name__ == '__main__':
    magic_str = 'tunnel_proto_magic:'
    magic_len = len(magic_str)
    # 实时更新sock的状态
    # sockStatus[sock] = {'sequence' : sequence, 'type':'tunnel/app','local_app_sock': when type is tunnel,
    #  'remote_app_sequence': xxx , 'remote_tunnel_sequence' : xxx , status:'connect/connected/shutdown_read/closed'}
    sockInfo = defaultdict()

    os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))

    config = parse_config_file()
    tunnel_pool = TunnelPool()
    tunnel_pool_lock = threading.Lock()

    tunnel_server_thread = app_server_thread = debug_server_thread = None

    debug_server = ThreadingHttpServer(('0.0.0.0', 9876), WebRequestHandler)
    debug_server_thread = threading.Thread(target=debug_server.serve_forever)
    debug_server_thread.setDaemon(True)
    debug_server_thread.start()


    for name in config:
        if name == "tunnel_server":
            addr, port = parse_server(config[name])
            logger.debug("start tunnel server %s, %s" % (addr, port))
            SERVER = TunnelServer((addr, int(port)), TunnelServerHandler)
            tunnel_server_thread = ServerThread("tunnel_server", SERVER)
            tunnel_server_thread.setDaemon(True)
            tunnel_server_thread.start()

        elif name == "tunnel_client":
            pass
        else:
            # app server
            proto, port = parse_proto(config[name])[:2]
            logger.debug("start app server on port %s" % port)
            SERVER = AppServer(('0.0.0.0', int(port)), AppHandler, name)
            app_server_thread = ServerThread("app_server", SERVER)
            app_server_thread.setDaemon(True)
            app_server_thread.start()


    # 这里是无限循环，所以不用join了
    start_poll()
    sys.exit(0)
