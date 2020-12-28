# -*- coding: utf-8 -*-
import json
from sqlalchemy import Column, Integer, Text
from webapp.database import db
import requests


class ModsecQuery(db.Model):
    query_id = Column(Integer, primary_key=True)
    query_msg_type = Column(Text)
    query_source_ip = Column(Text)
    query_source_port = Column(Text)
    query_dest_ip = Column(Text)
    query_dest_port = Column(Text)
    query_method = Column(Text)
    query_request_line = Column(Text)
    query_version = Column(Text)
    query_headers = Column(Text)
    query_body = Column(Text)

    def __init__(self, query_type, query_object):
        self.query_msg_type = query_type
        self.query_source_ip = query_object['query_source_ip']
        self.query_source_port = query_object['query_source_port']
        self.query_dest_ip = query_object['query_dest_ip']
        self.query_dest_port = query_object['query_dest_port']
        self.query_method = query_object['query_method']
        self.query_request_line = query_object['query_request_line']
        self.uery_version = query_object['query_version']
        self.query_headers = query_object['query_headers']

    def __repr__(self):
        return '<ModsecQuery %r>' % (self.query_msg_type)
