# -*- coding: utf-8 -*-
"""The app module, containing the app factory function."""
import logging
import sys

from flask import Flask, render_template, g
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy

from webapp.database import db

from .internal.views import internal_blueprint

def create_app():
    """Create application factory"""
    app = Flask(__name__.split(".")[0])
    app.config.from_pyfile('settings.py')
    register_extensions(app)
    register_blueprints(app)
    register_database(app)
    register_errorhandlers(app)
    configure_logger(app)
    return app

def register_extensions(app):
    """Register Flask extensions."""
    csp = {
        'script-src': '\'self\' \'unsafe-inline\' coreruleset.org piwik.netnea.com',
        'default-src': '\'self\'',
        'style-src': '\'self\' \'unsafe-inline\' coreruleset.org',
        'font-src': '\'self\' coreruleset.org',
        'img-src': '\'self\' coreruleset.org',
        'worker-src': '\'self\''
    }
    Talisman(app, \
        strict_transport_security=False, \
        force_https=False, \
        session_cookie_secure=False, \
        content_security_policy=csp
    )
    return None

def register_database(app):
    """Initalize the databae for our app."""
    db.init_app(app)# -*- coding: utf-8 -*-

def register_blueprints(app):
    """Register Flask blueprints."""
    app.register_blueprint(internal_blueprint)
    return None

def register_errorhandlers(app):
    """Register error handlers."""

    def render_error(error):
        """Render error template."""
        # If a HTTPException, pull the `code` attribute; default to 500
        error_code = getattr(error, "code", 500)
        return render_template(f"{error_code}.html"), error_code

    for errcode in [401, 404, 500]:
        app.errorhandler(errcode)(render_error)
    return None

def configure_logger(app):
    """Configure loggers."""
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)
