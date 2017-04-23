import os
import rethinkdb as db
from flask import Flask, render_template, request, redirect, url_for

# RETHINKDB
RETHINKDB_HOST = os.environ.get("DOCKHERO_HOST")
RETHINKDB_DB = os.environ.get("RETHINKDB_DB")
RETHINKDB_PASSWORD = os.environ.get("RETHINKDB_PASSWORD")

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'this_should_be_configured')

# open connection before each request
@app.before_request
def before_request():
    try:
        g.db_conn = db.connect(host=RETHINKDB_HOST, port=28015, db=RETHINKDB_DB, password=RETHINKDB_PASSWORD).repl()
    except RqlDriverError:
        abort(503, "o fucc something is terribly wrong you should tell someone")

# close the connection after each request
@app.teardown_request
def teardown_request(exception):
    try:
        g.db_conn.close()
    except AttributeError:
        pass

@app.route('/')
def test():
    print('HOME')
    return str(db.table("users").run())

if __name__ == '__main__':
    app.run(debug=True)
