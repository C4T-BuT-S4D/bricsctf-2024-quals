#!/usr/bin/env python3

import flask

app = flask.Flask(__name__)

@app.get('/ca0b58371771e9a518d6d6ec71d2f943')
def exploit():
    return flask.send_from_directory('.', 'exploit.html')

@app.get('/report')
def report():
    return 'ok'

app.run('0.0.0.0', 4242)
