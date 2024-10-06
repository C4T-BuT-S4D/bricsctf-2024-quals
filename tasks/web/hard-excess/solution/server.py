#!/usr/bin/env python3

import json
import flask


app = flask.Flask(__name__)


@app.get('/exploit')
def exploit():
    return flask.send_from_directory('.', 'exploit.html')


@app.get('/report')
def report():
    report = flask.request.args.get('report')
    obj = json.loads(report)
    print(obj)

    return 'ok'


if __name__ == '__main__':
    app.run('0.0.0.0', 4242)
