# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from java.util import List, ArrayList
from javax.swing import JMenuItem, SwingWorker
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("SQLiHunter")

        self.callbacks.registerContextMenuFactory(self)

        print("[*] SQLiHunter Loaded - Context Menu Ready")

        # Load payloads from file (JSON strings)
        with open("payloads.txt", "r") as f:
            self.payloads = [line.strip() for line in f if line.strip()]
        print("[*] {} Payloads Loaded".format(len(self.payloads)))

    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu_list = ArrayList()
        menu_item = JMenuItem("Scan with SQLiHunter", actionPerformed=self.perform_sqli_scan)
        menu_list.add(menu_item)
        return menu_list

    def perform_sqli_scan(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if not selected_messages:
            print("[!] No HTTP request selected.")
            return

        worker = SQLiScanWorker(selected_messages, self.helpers, self.payloads, self.callbacks)
        worker.execute()


class SQLiScanWorker(SwingWorker):
    def __init__(self, selected_messages, helpers, payloads, callbacks):
        self.selected_messages = selected_messages
        self.helpers = helpers
        self.payloads = payloads
        self.callbacks = callbacks

    def doInBackground(self):
        for message in self.selected_messages:
            request_info = self.helpers.analyzeRequest(message)
            url = request_info.getUrl()
            method = request_info.getMethod()
            full_request = message.getRequest()
            host = message.getHttpService()

            print("\n[+] Scanning {} {}".format(method, url))

            for payload in self.payloads:
                try:
                    print("[*] Testing payload: {}".format(payload))

                    new_request = self.inject_json_payload(request_info, full_request, payload)
                    if not new_request:
                        continue

                    response = self.callbacks.makeHttpRequest(host, new_request)
                    resp_info = self.helpers.analyzeResponse(response.getResponse())
                    status_code = resp_info.getStatusCode()

                    print("[+] Status Code: {} → Payload: {}".format(status_code, payload))

                    if status_code == 302:
                        print("[!!!] Login Bypass Possible! → Payload: {}".format(payload))

                except Exception as e:
                    print("[!] JSON injection error: {}".format(str(e)))

    def inject_json_payload(self, request_info, request_bytes, payload):
        try:
            raw_headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = request_bytes[body_offset:].tostring().decode()

            new_body = payload.strip()  # Assume entire payload is JSON string

            headers = list(raw_headers)

            # Ensure Content-Type is set to application/json
            found_ct = False
            for i, h in enumerate(headers):
                if h.lower().startswith("content-type"):
                    headers[i] = "Content-Type: application/json"
                    found_ct = True
            if not found_ct:
                headers.append("Content-Type: application/json")

            return self.helpers.buildHttpMessage(headers, new_body)
        except Exception as e:
            print("[!] JSON Payload Injection Error: {}".format(str(e)))
            return None
