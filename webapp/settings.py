# -*- coding: utf-8 -*-
import os

ENV = os.environ.get('FLASK_ENV', "production")
DEBUG = True
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///./modsec.db')
DEBUG_TB_ENABLED = DEBUG
DEBUG_TB_INTERCEPT_REDIRECTS = False
SQLALCHEMY_TRACK_MODIFICATIONS = False
