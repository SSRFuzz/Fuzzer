#! /usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import _thread
import datetime
import pyinotify


query_history = []
url_history = []

ftpconnect_history = []
filechange_history = []
httplog_history = []


def web_server():
    web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    web.bind(('0.0.0.0', 8088))
    web.listen(10)
    while True:
        try:
            conn, addr = web.accept()
            data = conn.recv(4096).decode(encoding='utf_8', errors='strict')
            # print(data)
            req_line = data.split("\r\n")[0]
            path = req_line.split()[1]
            route_list = path.split('/')
            html = "NO"
            print(route_list)

            if (len(route_list) == 3) and (route_list[1] == 'check'):
                if route_list[2] == 'ftpcon' and len(ftpconnect_history)!=0:
                    ftpconnect_history.clear()
                    html = 'YES'
                if route_list[2] == 'filecheck' and len(filechange_history)!=0:
                    filechange_history.clear()
                    html = 'YES'
                elif route_list[2] in url_history:
                    url_history.remove(route_list[2])
                    html = 'YES'
                else:
                    query_str = route_list[2]
                    for query_raw in set(query_history):
                        if bytes(query_str, encoding='utf-8') in query_raw:
                            query_history.remove(query_raw)
                            html = "YES"
            else:
                if route_list[1] not in url_history:
                    url_history.append(route_list[1])

            print(datetime.datetime.now().strftime('%m-%d %H:%M:%S') +
                " " + str(addr[0]) + ' web query: ' + path)
            raw = "HTTP/1.0 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (
                len(html), html)
            conn.send(raw.encode(encoding='utf_8', errors='strict'))
            conn.close()
        except:
            pass


def port_observer():
    ftpserver = socket.socket()
    ftpserver.bind(('0.0.0.0', 21))
    ftpserver.listen()

    while True:
        try:
            conn, addr = ftpserver.accept()
            # print(addr)
            if addr:
                ftpconnect_history.append("Conn")
            conn.send(b'\x02\x03\x03')
            conn.close()
        except:
            pass


def dns_observer():
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns.bind(('0.0.0.0', 53))
    
    while True:
        try:
            recv, addr = dns.recvfrom(1024)
            if recv not in query_history:
                query_history.append(recv)
            # print(datetime.datetime.now().strftime('%m-%d %H:%M:%S') +
            #       " " + str(addr[0]) + ' Dns Query: ' + recv)
            print(query_history)
        except Exception as e:
            print(e)


class MyEventHandler(pyinotify.ProcessEvent):

    def process_IN_ACCESS(self, event):
        filechange_history.append("ACCESS")
 
    def process_IN_ATTRIB(self, event):
        filechange_history.append("ATTRIB")
 
    def process_IN_CREATE(self, event):
        filechange_history.append("CREATE")
 
    def process_IN_DELETE(self, event):
        filechange_history.append("DELETE")
  
    def process_IN_MODIFY(self, event):
        filechange_history.append("MODIFY")

    def process_IN_OPEN(self, event):
        filechange_history.append("OPEN")


def file_observer():
    monitor_obj = pyinotify.WatchManager()
    monitor_obj.add_watch("/flag", pyinotify.ALL_EVENTS, rec=True)
    event_handler= MyEventHandler()
    monitor_loop= pyinotify.Notifier(monitor_obj, event_handler)
    monitor_loop.loop()

if __name__ == "__main__":
    # without dns
    web_server()

    # # with dns
    # _thread.start_new_thread(web_server, ())
    # _thread.start_new_thread(port_observer, ())
    # _thread.start_new_thread(dns_observer, ())

    # file_observer()
