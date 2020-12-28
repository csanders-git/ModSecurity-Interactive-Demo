# -*- coding: utf-8 -*-
"""Create an application instance."""
from webapp.app import create_app

def main():
    app = create_app()
    app.run(host='0.0.0.0', port=80, debug=True)

if __name__ == "__main__":
    main()
