#!/usr/bin/env/python

#imports
from urllib.parse import urljoin
from pprint import pprint
from bs4 import BeautifulSoup as bs
import requests
import math
import random


xss_detected = []
payloads_tried = []
scan_logs = []
xss_type = ["Reflected Cross-Site Scripting"]
risk_level = []
forms_found = []


def get_all_forms(url):
    # a simple web scrapping function that returns all forms from the HTML content

    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):

    # This function extracts all possible useful information about an HTML `form`

    details = {}
    # get the form action (target url)
    target = form.attrs.get("action")
    if target:
        action = target.lower()
    else:
        action = "?"

    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):

    # This willl submit the received forms
    # Params:
    #     form_details is a dictionary that contains all form information
    #     url is the URL that contains the form
    #     value is the injected payload
    # Returns the HTTP Response after form submission

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])

    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data, allow_redirects=True)
    else:
        # GET request
        return requests.get(target_url, params=data, allow_redirects=True)


def xss_scanner(url):

    # it takes in the inputed URL and then runs a funtion to detect all forms vulnerable and then returns true once all the vulnerable forms have been detected.

    # get all the forms from the URL
    forms = get_all_forms(url)
    log1 = f"[+] Detected {len(forms)} forms on {url}"
    scan_logs.append(log1)
    print(log1)

    if len(forms) == 0:
        log2 = f"[+] XSS Not Successful on {url}"
        risk_level.append("Low")
        scan_logs.append(log2)
        print(log2)

    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        p = open("payloads.txt", "r")
        pay = []
        for loads in p:
            pay.append(loads)
        for x in pay:
            payload = random.choice(pay)
            payloads_tried.append(payload)
            form_details = get_form_details(form)
            response = submit_form(form_details, url, payload)

            response_content = response.content.decode()

            if payload in response_content:
                log3 = f"[!] XSS Detected on {url}"
                scan_logs.append(log3)

                print(log3)

                forms1 = f"[*] Form details:"
                forms_found.append(forms1)
                print(forms1)

                pprint(form_details)
                forms2 = form_details
                forms_found.append(forms2)
                # print(forms2)

                is_vulnerable = True
                log4 = f'is vulnerable: {is_vulnerable}'
                scan_logs.append(log4)
                print(log4)

            else:
                log5 = f"[+] XSS Not Successful Through Forms on {url}"
                scan_logs.append(log5)

                print(log5)

            if pay.index(x) < len(pay) - 1:
                log6 = f"[*] Trying Next Payload"
                print(log6)

        # won't break because we want to print other available vulnerable forms
    xss_detected.append(is_vulnerable)
    if is_vulnerable:
        risk_level.append("High")
    else:
        risk_level.clear()
        risk_level.append("Low")
    log6 = f"XSS Test Complete"
    scan_logs.append(log6)
    return print(log6)