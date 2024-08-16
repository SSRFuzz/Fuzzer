#! /usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import gevent.monkey
gevent.monkey.patch_all()
from gevent.pywsgi import WSGIServer
from flask import Flask, request
import mysql.connector
import gevent.queue
import requests
import logging
import base64
import copy
import zlib
import json
import sys

PY2 = sys.version_info[0] == 2
if not PY2:
    unicode = str
    from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl
else:
    from urlparse import urlsplit, urlunsplit, parse_qsl
    from urllib import quote

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
task_queue = gevent.queue.Queue()

class Checker():
    def __init__(self):
        self.prvd_db = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd='new_password',
            port='3306',
            database="ssrfuzz",
            auth_plugin='mysql_native_password'
        )
        cursor = self.prvd_db.cursor(buffered=True) 
        test = "show databases;"
        cursor.execute(test)
        self.prvd_db.commit()


    def update_check_info(self, url, body):
        cursor = self.prvd_db.cursor(buffered=True)
        udpate_info = "UPDATE check_info SET vulnable=1, url=\"{}\", body=\"{}\" where id=1;".format(url, body)
        cursor.execute(udpate_info)
        self.prvd_db.commit()


    def check_vuln(self):
        special_string = "info"
        checkapi = requests.get("http://127.0.0.1:8088/check/"+special_string)
        # print(checkapi.text)
        if "YES" in checkapi.text:
            print("Find Vuln")
            return True

checker = Checker()

def handle_task_queue():
    flag = True
    while True:
        task = task_queue.get()

        method = task['method']
        url = task['url']
        headers = task['headers']
        body = task['body']
        files = task['files']

        # print("URL:",url)
        # print("BODY:",body)

        header_string = '\n'.join(
            [key + ':' + value for key, value in headers.items()])
        logger.debug("sending request\n{} {}\n{}\n\n{}\n{}\n".format(
            method, url, header_string, body, files))
        try:
            requests.request(method=method, url=url, headers=headers, data=body, files=files,
                             allow_redirects=False, timeout=5)
        except:
            pass

        if checker.check_vuln():
            if flag:
                flag = False
                checker.update_check_info(url, body)
                task_queue.queue.clear()
                task_queue.put(task)
            else:
                flag = True


class Fuzzer(object):
    # payloads = ['\'\"><xtanzi>./../xtanzi','fuzz_test']
    # identify_payloads = ['\'\"><zfuzz>./../zfuzz', 'test>zfuzz;test']
    # identify_payloads = ['zfuzz>./../zzuzz', 'test>zfuzz;test']
    # identify_payloads = ['http://127.0.0.1', 'file:///tmp/1.txt']
    identify_payloads = ['http://127.0.0.1:8088/zfuzz', 'file:///zfuzz/1.txt']
    # identify_payloads = ['http://127.0.0.1:8088/zfuzz']
    rcmde_payloads = [';echo 8848']
    rcode_payloads = ['phpinfo();']
    # ssrf_payloads = ['http://127.0.0.1:8088/info', 'test1', 'test2']
    ssrf_payloads = ['http://127.0.0.1:8088/info', 'http://127.0.0.1:8088/test1', 'http://127.0.0.1:8088/test2', 'wait']

    def __init__(self, _request, _category):
        self.request = _request
        self.category = _category
        self.prvd_db = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="new_password",
            database="ssrfuzz",
            auth_plugin='mysql_native_password'
        )

    def __del__(self):
        pass

    def start(self):
        logger.debug('origin request: \n{}'.format(
            json.dumps(self.request, indent=4)))

        if 'query' in self.request and self.request['query']:
            self.fuzz_query()

        if 'data' in self.request and self.request['data']:
            self.fuzz_body()

#         if 'files' in self.request and self.request['files']:
#             self.fuzz_files()
#
#         if 'cookies' in self.request and self.request['cookies']:
#             self.fuzz_cookies()
#
#         if 'headers' in self.request and self.request['headers']:
#             self.fuzz_headers()

    # def clean_vuln_info(self):
    #     cursor = self.prvd_db.cursor(buffered=True)
    #     clean_sql = "TRUNCATE TABLE ssrf_info;"
    #     cursor.execute(clean_sql)
    #     self.prvd_db.commit()
    #     print(cursor.rowcount, "success")

    def set_check_param(self, param):
        cursor = self.prvd_db.cursor(buffered=True)
        clean_info_sql = "TRUNCATE TABLE check_info;"
        cursor.execute(clean_info_sql)
        # print("param:", param)
        insert_param = "INSERT INTO check_info (id, param) VALUES (1, \"{}\");".format(param)
        cursor.execute(insert_param)
        self.prvd_db.commit()


    def get_vuln_param(self):
        cursor = self.prvd_db.cursor(buffered=True)
        find_param_sql = "select vulnparam from ssrf_vuln where id = 1;"
        cursor.execute(find_param_sql)
        values = cursor.fetchall()
        # print(values[0][0], "success")
        vuln_param = values[0][0]
        return vuln_param


    def clean_vuln_param(self):
        cursor = self.prvd_db.cursor(buffered=True)
        clean_vuln_sql = "TRUNCATE TABLE ssrf_vuln;"
        cursor.execute(clean_vuln_sql)
        insert_id = "INSERT INTO ssrf_vuln (id) VALUES (1);"
        cursor.execute(insert_id)
        self.prvd_db.commit()


    def fuzz_query(self):
        query = copy.deepcopy(self.request['query'])

        # fuzz_queries = self.fuzz_value(query, self.category)
        # print("fuzz queries:",fuzz_queries)

        if self.category == "fuzz":
            fuzz_queries = self.fuzz_value(query, self.category)
            print("fuzz queries:",fuzz_queries)
            params = []
            for each_fuzz_query in fuzz_queries:
                for key, value in each_fuzz_query.items():
                    params.append(key)
            params = list(set(params))
            init_info = []
            for p in params:
                # tmp_val = (p, 'zfuzz>./../zzuzz', 'test>zfuzz;test')
                tmp_val = (p, Fuzzer.identify_payloads[0], Fuzzer.identify_payloads[1], base64.b64encode(str(self.request).encode("UTF-8")))
                init_info.append(tmp_val)
            # print(init_info)

            # mysql
            cursor = self.prvd_db.cursor(buffered=True)
            fuzz_init_sql = "INSERT INTO ssrf_info (param,Av1,Av2,requests) VALUES (%s, %s, %s, %s)"
            cursor.executemany(fuzz_init_sql, init_info)
            self.prvd_db.commit()
            print(cursor.rowcount, "success")
        else:
            param = self.get_vuln_param()
            self.clean_vuln_param()
            self.set_check_param(param)
            fuzz_queries = self.fuzz_one_value(query, param ,self.category)
            print("fuzz param:",param)
            print("fuzz queries:",fuzz_queries)

        for each_fuzz_query in fuzz_queries:
            fuzz_request = copy.deepcopy(self.request)
            fuzz_request['query'] = each_fuzz_query
            self.make_request(fuzz_request, 'query', self.category)

    def fuzz_body(self):
        body = copy.deepcopy(self.request['data'])
        fuzz_queries = self.fuzz_value(body, self.category)
        print("fuzz body:",fuzz_queries)

        if self.category == "fuzz":
            fuzz_queries = self.fuzz_value(body, self.category)
            print(fuzz_queries)
            params = []
            for each_fuzz_query in fuzz_queries:
                for key, value in each_fuzz_query.items():
                    params.append(key)
            params = list(set(params))
            init_info = []
            for p in params:
                # tmp_val = (p, 'zfuzz>./../zzuzz', 'test>zfuzz;test')
                tmp_val = (p,  Fuzzer.identify_payloads[0], Fuzzer.identify_payloads[1])
                init_info.append(tmp_val)
            # print(init_info)

            # mysql
            cursor = self.prvd_db.cursor(buffered=True)
            fuzz_init_sql = "INSERT INTO ssrf_info (param,Av1,Av2) VALUES (%s, %s, %s)"
            cursor.executemany(fuzz_init_sql, init_info)
            self.prvd_db.commit()
            print(cursor.rowcount, "success")
        else:
            param = self.get_vuln_param()
            self.clean_vuln_param()
            self.set_check_param(param)
            fuzz_queries = self.fuzz_one_value(body, param, self.category)
            print("fuzz param:",param)
            print("fuzz queries:",fuzz_queries)

        for each_fuzz_query in fuzz_queries:
            fuzz_request = copy.deepcopy(self.request)
            fuzz_request['data'] = each_fuzz_query
            self.make_request(fuzz_request, 'body', self.category)

    def fuzz_cookies(self):
        cookie = copy.deepcopy(self.request['cookies'])
        fuzz_queries = self.fuzz_value(cookie, self.category)

        for each_fuzz_query in fuzz_queries:
            fuzz_request = copy.deepcopy(self.request)
            fuzz_request['cookies'] = each_fuzz_query
            self.make_request(fuzz_request, 'cookies', self.category)

    def fuzz_files(self):
        files = copy.deepcopy(self.request['files'])
        for key in files:
            file_info = files[key]
            for each_fuzz_data in self.add_value(file_info['name'], self.category):
                fuzz_request = copy.deepcopy(self.request)
                fuzz_request['files'][key]['name'] = each_fuzz_data
                self.make_request(fuzz_request, 'body', self.category)

            for each_fuzz_data in self.add_value('', self.category):
                fuzz_request = copy.deepcopy(self.request)
                fuzz_request['files'][key]['data'] = each_fuzz_data
                self.make_request(fuzz_request, 'body', self.category)

    def fuzz_headers(self):
        headers = copy.deepcopy(self.request['headers'])
        fuzz_headers = self.fuzz_value(headers, self.category)

        for each_fuzz_header in fuzz_headers:
            fuzz_request = copy.deepcopy(self.request)
            fuzz_request['headers'] = each_fuzz_header
            self.make_request(fuzz_request, 'headers', self.category)

    @staticmethod
    def make_request(req, fuzz_origin=None, vuln_type=None):
        method = req['method']
        headers = req['headers']
        content_type = headers.get('Content-Type', '').lower()
        body = None
        files = {}

        if fuzz_origin == 'query' and 'query' in req and req['query']:
            urlspliter = urlsplit(req['url'])
            query_string = Fuzzer.json_to_php_array_string(req['query'])
            url = urlunsplit((urlspliter.scheme, urlspliter.netloc,
                              urlspliter.path, query_string, urlspliter.fragment))
        else:
            url = req['url']

        if fuzz_origin == 'body' and 'data' in req and req['data']:
            if 'application/x-www-form-urlencoded' in content_type:
                body = Fuzzer.json_to_php_array_string(req['data'])
            elif 'application/json' in content_type:
                body = json.dumps(req['data'])
            elif 'multipart/form-data' in content_type:
                body = {}
                for key, value in parse_qsl(Fuzzer.json_to_php_array_string(req['data'])):
                    body[key] = (None, value)

                req['headers'].pop('Content-Type')
        else:
            body = req.get('data')

        if 'multipart/form-data' in content_type:
            if 'files' in req and req['files']:
                for key in req['files']:
                    files[key] = (req['files'][key]['name'],
                                  req['files'][key].get('data', '!PNG Hello'))

        if fuzz_origin == 'cookies' and 'cookies' in req and req['cookies']:
            cookie_string = Fuzzer.json_to_php_array_string(req['cookies'])
            cookie_string = cookie_string.replace('&', ';')
            headers['Cookie'] = cookie_string

        headers['HTTP_PRVD_FUZZER'] = 'hello_from_fuzzer'
        if vuln_type != "fuzz":
            headers['HTTP_VULN_FUZZER'] = 'type_vuln_fuzzer'
            # print(headers['HTTP_VULN_FUZZER'])
        if 'Content-Length' in headers:
            headers.pop('Content-Length')

        task_queue.put({
            'method': method,
            'url': url,
            'headers': headers,
            'body': body,
            'files': files
        })

    @staticmethod
    def add_value(value, category):
        result = []

        if category == "rcmde":
            payloads = Fuzzer.rcmde_payloads
        elif category == "rcode":
            payloads = Fuzzer.rcode_payloads
        elif category == "ssrf":
            payloads = Fuzzer.ssrf_payloads
        elif category == "fuzz":
            payloads = Fuzzer.identify_payloads

        for i in payloads:
            value = value or ''
            result.append(i)

        return result

    @staticmethod
    def fuzz_value(data, category):
        """
        >>> Fuzzer.fuzz_value({'a': {"d": {"c": "x"}}})
        [{'a': {'d': {'c': 'x\'"><xtanzi>./../xtanzi'}}},]
        """
        reqs = []

        def _fuzz_value(value, category):
            if isinstance(value, (dict, list)):
                items = value.items() if isinstance(value, dict) else enumerate(value)
                for each_key, each_value in items:
                    new_values = _fuzz_value(each_value, category)

                    if not new_values:
                        continue

                    for each_new_value in new_values:
                        value[each_key] = each_new_value
                        reqs.append(copy.deepcopy(data))
                        value[each_key] = each_value

            elif isinstance(value, unicode):
                return Fuzzer.add_value(value, category)

        _fuzz_value(data, category)
        return reqs

    @staticmethod
    def fuzz_one_value(data, param, category):
        """
        >>> Fuzzer.fuzz_value({'a': {"d": {"c": "x"}}}, "c", "SSRF")
        [{'a': {'d': {'c': 'SSRF_PAYLOAD'}}},]
        """
        reqs = []

        def _fuzz_value(value, category):
            if isinstance(value, (dict, list)):
                items = value.items() if isinstance(value, dict) else enumerate(value)
                for each_key, each_value in items:
                    new_values = _fuzz_value(each_value, category)

                    if not new_values:
                        continue

                    for each_new_value in new_values:
                        if each_key == param:
                            value[each_key] = each_new_value
                            reqs.append(copy.deepcopy(data))
                            value[each_key] = each_value

            elif isinstance(value, unicode):
                # print("value: ", value)
                return Fuzzer.add_value(value, category)

        _fuzz_value(data, category)
        return reqs


    @staticmethod
    def json_to_php_array_string(data):
        """
        >>> Fuzzer.json_to_php_array_string({"key1": "value1", 'key2': 'value2'})
        'key1=value1&key2=value2'
        >>> Fuzzer.json_to_php_array_string({"key1": {"key11": "value11"}, "key2": "value2"})
        'key1[key11]=value11&key2=value2'
        >>> Fuzzer.json_to_php_array_string({"key1": ["value1", "value12", "value13"]})
        'key1[]=value1&key1[]=value12&key1[]=value13'
        >>> Fuzzer.json_to_php_array_string({"key1": {"key11": ['value11', 'value12']}})
        'key1[key11][]=value11&key1[key11][]=value12'
        """

        def to_string(value):
            if isinstance(value, dict):
                d = []
                for each_key, each_value in value.items():
                    result = to_string(each_value)

                    if isinstance(result, list):
                        for i in result:
                            d.append('[%s]%s' % (each_key, i))
                    else:
                        d.append('[%s]%s' % (each_key, result))

                return d

            elif isinstance(value, list):
                d = []
                for each_value in value:
                    result = to_string(each_value)

                    if isinstance(result, list):
                        for i in result:
                            d.append('[]%s' % i)
                    else:
                        d.append('[]%s' % result)

                return d

            elif isinstance(value, unicode):
                return '=' + quote(value)

        d = []
        for i in data:
            result = to_string(data[i])
            if isinstance(result, list):
                for j in result:
                    d.append(i + j)
            else:
                d.append(i + result)

        return '&'.join(sorted(d))

    @staticmethod
    def fuzz(_request, _category):
        f = Fuzzer(_request, _category)
        f.start()
        # print("category:",_category)
        # if _category != "fuzz":
        #     f.clean_vuln_info()


@app.route('/fuzz', methods=['POST'])
def index():
    if 'X-Sentry-Auth' not in request.headers:
        return "forbidden"

    h = request.headers['X-Sentry-Auth']
    sentry_info = {}
    for i in h.split(','):
        key, value = i.split('=')
        sentry_info[key.strip()] = value.strip()

    if sentry_info['sentry_key'] != 'admin' or sentry_info['sentry_secret'] != 'password':
        return "access deny"

    if not request.data:
        return "require data"

    data = base64.b64decode(request.data)
    try:
        data = zlib.decompress(data)
    except:
        pass

    data = data.decode('utf-8', errors='ignore')
    data = json.loads(data)

    Fuzzer.fuzz(data['request'], "fuzz")
    return 'hello fuzz'

@app.route('/ssrf', methods=['POST'])
def ssrf():
    if 'X-Sentry-Auth' not in request.headers:
        return "forbidden"

    # if 'Fuzz-Param' not in request.headers:
    #     return "FuzzWhat"

    h = request.headers['X-Sentry-Auth']
    sentry_info = {}
    for i in h.split(','):
        key, value = i.split('=')
        sentry_info[key.strip()] = value.strip()

    if sentry_info['sentry_key'] != 'admin' or sentry_info['sentry_secret'] != 'password':
        return "access deny"

    if not request.data:
        return "require data"

    data = base64.b64decode(request.data)
    try:
        data = zlib.decompress(data)
    except:
        pass

    data = data.decode('utf-8', errors='ignore')
    data = json.loads(data)

    Fuzzer.fuzz(data['request'], "ssrf")
    return 'hello ssrf'

if __name__ == '__main__':
    gevent.spawn(handle_task_queue)
    http_server = WSGIServer(('0.0.0.0', 9191), app)
    http_server.serve_forever()