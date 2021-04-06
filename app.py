#!/usr/bin/env python3

#imports
from flask import Flask, render_template, request, url_for, redirect, jsonify
import requests
from detector import *
from xssscanner import *
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = "hb7489fjbfygb"


@app.route("/", methods=["GET", "POST"])
def home():

    return render_template("index.html")


@app.route('/report', methods=['GET', 'POST'])
def report():

    if request.method == "POST":

        url = request.form["url"]

        scan_sql_injection(url)
        xss_scanner(url)

        clear_list = [xss_detected, scan_logs, risk_level, payloads_tried]
        clear_list2 = [db, sqli_detected, risk_state, logs]

        def clear(list):
            for x in list:
                x.clear()

        def clear2(list):
            for x in list:
                x.clear()

        return render_template("report.html", test_logs=logs, db=db, sqli_detected=sqli_detected, risk_state=risk_state, sqli_type=sqli_type, scan_logs=scan_logs, xss_type=xss_type, risk_level=risk_level, xss_detected=xss_detected, payloads_tried=payloads_tried), clear(clear_list), clear2(clear_list2)


if __name__ == "__main__":
    app.run(debug=False)