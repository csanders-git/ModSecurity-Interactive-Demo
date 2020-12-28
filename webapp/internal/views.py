# -*- coding: utf-8 -*-
"""Public section, including homepage and signup."""
import re
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
    abort
)
from ..app import db
from .models import ModsecQuery

from sqlalchemy.exc import IntegrityError
from ModSecurity import ModSecurity
from ModSecurity import Rules
from ModSecurity import Transaction
from ModSecurity import ModSecurityIntervention
from ModSecurity import testLogCb
from ModSecurity import LogProperty
import logging

internal_blueprint = Blueprint("internal", __name__, static_folder="../static")


class HttpRequest:
    def __init__(self, request_query):
        # Interesting issue where occaisonally \r\n is added
        self.query = request_query.replace('\r\n', '\n').split('\n')
        self.method = ""
        self.path = ""
        self.version = ""
        self.headers = {}
        self.request_body = ""
        self.http_warning = False
        self.process_request_line()
        self.test_http_version()
        self.process_headers()
        self.process_body()

    def test_http_version(self):
        if self.version.upper().find("HTTP/") < 0:
            self.http_warning = True
        else:
            self.version = self.version.upper().replace('HTTP/', '')

    @staticmethod
    def list_get(search_list, index, default):
        if len(search_list) < index + 1:
            return default
        else:
            return search_list[index]

    @staticmethod
    def list_get_remainder(search_list, index, default, combinator):
        if len(search_list) < index + 1:
            return default
        else:
            return combinator.join(search_list[index:])

    def process_request_line(self):
        # we are promised at least one element
        req_line = self.query[0]
        split_req_line = re.compile(r'\s+').split(req_line)
        self.method = HttpRequest.list_get(split_req_line, 0, "")
        self.path = HttpRequest.list_get(split_req_line, 1, "")
        self.version = HttpRequest.list_get_remainder(split_req_line, 2, "", " ")
        if len(self.query) > 1:
            self.query = self.query[1:]
        else:
            self.query = []

    def process_headers(self):
        found_headers = {}
        if len(self.query) < 1:
            self.headers = found_headers
        for index, line in enumerate(self.query):
            if line == "":
                self.query = self.query[index:]
                self.headers = found_headers
                return
            header_line = line.split(':', 1)
            header_key = header_line[0]
            header_value = HttpRequest.list_get(header_line, 1, "")
            found_headers[header_key] = header_value.lstrip()
        self.headers = found_headers
        self.query = []

    def process_body(self):
        if len(self.query) < 2:
            self.body = ""
        self.body = "\n".join(self.query[1:])


def process_intervention(transaction, log, disruptive):
    intervention = ModSecurityIntervention()
    if intervention is None:
        return log, disruptive
    if transaction.intervention(intervention):
        if intervention.log is not None:
            print(intervention.log)
            log.append(intervention.log)
        if not intervention.disruptive:
            logging.debug("Intervention was NOT disruptive")
            return log, disruptive
        return log, True
        if intervention.url is not None:
            print(intervention.url)
        else:
            print(f"Status resovled: {intervention.status}")
    return log, disruptive


def headers_to_string(header_dict):
    headers = ""
    for header_name, header_value in header_dict.items():
        headers += f"{header_name}: {header_value}\n"
    return headers


class ModsecInstance:
    def __init__(self):
        self.modsec_handle = ModSecurity()
        self.rules = Rules()
        self.modsec_handle.setServerLogCb(
            self.cb, LogProperty.TextLogProperty)
        self.transaction = None
        self.log = []
        self.total_detections = 0

    def cb(self, data, rule_msg):
        self.log.append(rule_msg)
        #print(data, rule_msg)

    def load_rules(self):
        rule_count = self.rules.loadFromUri("webapp/include.conf")
        if rule_count < 1:
            logging.critical(
                f"Error trying to load rule file: {self.rules.getParserError()}")
        logging.info(f"Loaded {rule_count} rules")

    def create_transaction(self):
        self.transaction = Transaction(self.modsec_handle, self.rules)


@internal_blueprint.route("/", methods=["GET", "POST"])
def demo_home():
    """Demo page."""
    logging.basicConfig(level=logging.DEBUG)
    modsec = ModsecInstance()
    if request.method == 'POST':
        query_request = request.form['query_request']
        target = request.form['target']
        port = request.form['port']
        query_response = ""
        req_obj = HttpRequest(query_request)
        modsec.load_rules()
        modsec.create_transaction()

        disruptive = False
        modsec.transaction.processConnection(
            '127.0.0.1', 33333, '127.0.0.1', 8080)
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        print(
            f"Method: {req_obj.method}, Path: {req_obj.path}, Version: {req_obj.version}")
        modsec.transaction.processURI(
            req_obj.path, req_obj.method, req_obj.version)
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        # Request
        for header_key, header_value in req_obj.headers.items():
            print(f"Adding header {header_key}: {header_value}")
            modsec.transaction.addRequestHeader(header_key, header_value)
        modsec.transaction.processRequestHeaders()
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        print(f"Adding body: {req_obj.body}")
        modsec.transaction.appendRequestBody(req_obj.body)
        modsec.transaction.processRequestBody()
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        # Response
        modsec.transaction.processResponseHeaders(200, 'HTTP 1.2')
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        modsec.transaction.processResponseBody()
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        modsec.transaction.processLogging()
        log, disruptive = process_intervention(
            modsec.transaction, modsec.log, disruptive)
        modsec.total_detections = len(modsec.log)
        http_warning = req_obj.http_warning
        log_string = '\n'.join(modsec.log)
        #print(f"Log: {log_string}")
        #print(f"Disruptive: {disruptive}")
        query_response = log_string
    else:
        current_app.logger.info("Hello from the home page!")
        target = "127.0.0.1"
        port = "80"
        method = "GET"
        path = "/test?x=\"><script>alert(1);</script>"
        version = "HTTP/1.1"
        request_line = f"{method} {path} {version}"
        headers = {"Host": "localhost", "User-Agent": "OWASP CRS Demo"}
        body = ""
        query_request = f"{request_line}\n{headers_to_string(headers)}\n{body}"
        query_response = "Submit a HTTP message to see see CRS results"
        http_warning = False
    return render_template(
        "home.html",
        modsec=modsec.modsec_handle.whoAmI(),
        target=target,
        port=port,
        request=query_request,
        response=query_response,
        warning=http_warning,
        total_detections=modsec.total_detections
    )
