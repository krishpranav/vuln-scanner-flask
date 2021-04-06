#!/usr/bin/env/python

#imports
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import sys

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

logs = []
form_list = []
db = []
sqli_detected = []
sqli_type = ['Error-Based SQL Injection']
risk_state = []


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(first):
    # """A simple boolean function that determines whether a page is SQL Injection vulnerable from its `response`"""

    if 'mysql' in first.text.lower():
        error_msg = '[!] Injectable MySQL DB detected'
        print(error_msg)
        logs.append(error_msg)
        sqli_detected.append("True")
        risk_state.append("High")
        db.clear()
        db.append("MySQL")
        return True
    elif 'native client' in first.text.lower():
        error_msg = '[!] Injectable MSSQL DB detected'
        print(error_msg)
        logs.append(error_msg)
        sqli_detected.append("True")
        risk_state.append("High")
        db.clear()
        db.append("MSSQL")
        return True
    elif 'syntax error' in first.text.lower():
        error_msg = '[!] Injectable PostGRES DB detected'
        print(error_msg)
        logs.append(error_msg)
        db.clear()
        db.append("PostGRESSQL")
        risk_state.append("High")
        sqli_detected.append("True")
        return True
    elif 'ORA' in first.text.lower():
        error_msg = '[!] Injectable Oracle DB detected'
        print(error_msg)
        logs.append(error_msg)
        db.clear()
        db.append("Oracle DB")
        risk_state.append("High")
        sqli_detected.append("True")
        return True
    elif 'expects' in first.text.lower():
        error_msg = '[!] Injection Successful: DB Unknown'
        print(error_msg)
        sqli_detected.append("True")
        risk_state.append("High")
        logs.append(error_msg)
        db.clear()
        db.append("Unknown")
        return True
    else:
        error_msg = '[+] Unsuccessful Error-Based Injection'
        error_msg1 = '[+] Endpoint Parameter not Dynamic or Redirect Occured'
        # \n[!] Blind Injection Possible'
        print(error_msg)
        risk_state.append("Low")
        db.clear()
        db.append("Unknown")
        print(error_msg1)
        sqli_detected.append("False")
        logs.append(error_msg)
        logs.append(error_msg1)
        return False


def scan_sql_injection(url):
    # test on URL
    for c in f"\'":
        # add quote/double quote character to the URL
        new_url = f'{url}{c}'
        starting = f"[+] SQL Injection Started"
        print(starting)
        logs.append(starting)
        # print("[!] Trying", new_url)
        try_log = "[+] Trying " + new_url
        print(try_log)
        logs.append(try_log)
        # make the HTTP request
        res = s.get(new_url)
        # print(res.text)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceed for extracting forms and submitting them

            detected_log = "[!] SQL Injection vulnerability detected, link: " + new_url
            print(detected_log)
            logs.append(detected_log)

            # print(logs)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    form_length = f"[+] Detected {len(forms)} forms on {url}"
    form_try = '[+] Initiating SQL Injection Through Detected Forms'
    print(form_length)
    print(form_try)
    logs.append(form_length)
    logs.append(form_try)
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                form_detect = "[!] SQL Injection vulnerability detected, link: " + url
                print(form_detect)
                logs.append(form_detect)
                sqli_detected.clear()
                sqli_detected.append("True")
                risk_state.clear()
                risk_state.append("High")
                form_detected = "[+] Form: "
                print(form_detected)
                logs.append(form_detected)
                pprint(form_details)
                form_list.append(form_details)
            else:
                sqli_detected.clear()
                sqli_detected.append("False")
                db.clear()
                db.append("Unknown")
                risk_state.clear()
                risk_state.append("Low")

                # print(logs)
                break