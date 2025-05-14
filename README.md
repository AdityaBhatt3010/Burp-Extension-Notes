## ✅ Top-Level Imports

```python
from burp import IBurpExtender, IContextMenuFactory
```

* These are **Burp API interfaces**.

  * `IBurpExtender`: Required for registering the extension.
  * `IContextMenuFactory`: Allows you to add custom items to the right-click context menu.

```python
from java.util import List, ArrayList
```

* Java collections used by Burp. `ArrayList` is required to return the context menu.

```python
from javax.swing import JMenuItem, SwingWorker
```

* `JMenuItem`: GUI item added to Burp's context menu.
* `SwingWorker`: Allows **background scanning** without freezing the Burp UI.

```python
import re
```

* Python’s regular expressions (not heavily used here, but included for flexibility).

---

## ✅ Extension Initialization Class

```python
class BurpExtender(IBurpExtender, IContextMenuFactory):
```

* Main class that connects our code to Burp's API.
* Implements both `IBurpExtender` and `IContextMenuFactory`.

---

### `registerExtenderCallbacks()`

```python
def registerExtenderCallbacks(self, callbacks):
```

* Called **automatically by Burp** when the extension is loaded.

```python
    self.callbacks = callbacks
    self.helpers = callbacks.getHelpers()
    self.callbacks.setExtensionName("SQLiHunter")
```

* `callbacks`: Burp’s core API access.
* `helpers`: Provides encoding, decoding, and request manipulation functions.
* Sets the extension name in the Burp interface.

```python
    self.callbacks.registerContextMenuFactory(self)
```

* Registers the context menu factory — now our extension can **add right-click menu options**.

```python
    print("[*] SQLiHunter Loaded - Context Menu Ready")
```

* Console message confirming successful load.

```python
    with open("payloads.txt", "r") as f:
        self.payloads = [line.strip() for line in f if line.strip()]
    print("[*] {} Payloads Loaded".format(len(self.payloads)))
```

* Loads **JSON payloads from a file** (one per line), stripping whitespace and skipping blanks.

---

### `createMenuItems()`

```python
def createMenuItems(self, invocation):
```

* Called when you right-click a request in Burp.

```python
    self.invocation = invocation
```

* Stores context of the selected request(s).

```python
    menu_list = ArrayList()
    menu_item = JMenuItem("Scan with SQLiHunter", actionPerformed=self.perform_sqli_scan)
    menu_list.add(menu_item)
    return menu_list
```

* Adds a menu item labeled **"Scan with SQLiHunter"**, which calls `perform_sqli_scan()` when clicked.

---

## ✅ Scan Trigger Function

```python
def perform_sqli_scan(self, event):
```

* This function runs when the context menu item is clicked.

```python
    selected_messages = self.invocation.getSelectedMessages()
    if not selected_messages:
        print("[!] No HTTP request selected.")
        return
```

* Gets the selected HTTP request(s). If none selected, it returns.

```python
    worker = SQLiScanWorker(selected_messages, self.helpers, self.payloads, self.callbacks)
    worker.execute()
```

* Spawns a `SwingWorker` thread so scanning doesn’t block the Burp UI.

---

## ✅ `SQLiScanWorker` Background Thread Class

```python
class SQLiScanWorker(SwingWorker):
```

* Separate background thread for executing the scan (non-blocking).

```python
def __init__(self, selected_messages, helpers, payloads, callbacks):
```

* Constructor to pass required data into the worker.

---

### `doInBackground()` — Main Scanner Logic

```python
def doInBackground(self):
```

* Called automatically by SwingWorker in a background thread.

```python
    for message in self.selected_messages:
```

* Loop over selected HTTP messages.

```python
        request_info = self.helpers.analyzeRequest(message)
        url = request_info.getUrl()
        method = request_info.getMethod()
        full_request = message.getRequest()
        host = message.getHttpService()

        print("\n[+] Scanning {} {}".format(method, url))
```


## EXP

Certainly! Let's break this down with a **sample HTTP request** and explain what will be stored in each of the variables in your Burp Suite Extension code (likely written in Jython or Python with the Burp Extender API):

* Parse basic request info:

  * URL, HTTP method, full raw request bytes, and host object.

---

### 🔹 **Sample HTTP Request (Raw format)**

```http
GET /login?user=admin HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*
```

---

### 🧠 Variable Breakdown

Let's say this HTTP request is intercepted by your extension and passed to `message`.

```python
request_info = self.helpers.analyzeRequest(message)
```

This line uses Burp’s `IExtensionHelpers.analyzeRequest()` method to get an `IRequestInfo` object from the HTTP message.

---

### 1. `url = request_info.getUrl()`

**Stored value:**

```
http://example.com/login?user=admin
```

**What it is:**
The full URL of the request, including the protocol, host, path, and query parameters.

---

### 2. `method = request_info.getMethod()`

**Stored value:**

```
GET
```

**What it is:**
The HTTP method used in the request (e.g., `GET`, `POST`, `PUT`, `DELETE`, etc.).

---

### 3. `full_request = message.getRequest()`

**Stored value:**
This will be a **byte array** representing the entire raw HTTP request.

To make it human-readable:

```python
print(full_request.tostring())
```

Or decode:

```python
print(full_request.decode('utf-8'))
```

**What it is:**
The entire raw HTTP request as bytes, including headers and body.

---

### 4. `host = message.getHttpService()`

**Stored value (as `IHttpService` object):**

* `host.getHost()` → `example.com`
* `host.getPort()` → `80`
* `host.getProtocol()` → `http`

**What it is:**
An `IHttpService` object from which you can get the **host, port, and protocol**.

---

### 🖨 Final Output of Your Print Statement:

```python
print("\n[+] Scanning {} {}".format(method, url))
```

**Console Output:**

```
[+] Scanning GET http://example.com/login?user=admin
```

---

### ✅ Summary Table

| Variable       | Type           | Value                                                        |
| -------------- | -------------- | ------------------------------------------------------------ |
| `url`          | `java.net.URL` | `http://example.com/login?user=admin`                        |
| `method`       | `str`          | `GET`                                                        |
| `full_request` | `byte[]`       | Raw HTTP request (use `.decode()` to view as string)         |
| `host`         | `IHttpService` | Object with host/port/protocol (`example.com`, `80`, `http`) |

## EXP END

---

### For Each Payload

```python
        for payload in self.payloads:
```

* Iterate over all loaded payloads.

```python
            print("[*] Testing payload: {}".format(payload))
```

* Print payload being tested.

```python
            new_request = self.inject_json_payload(request_info, full_request, payload)
```

* Call helper function to inject the JSON payload into the request body.

```python
            if not new_request:
                continue
```

* If request failed to build, skip to next.

```python
            response = self.callbacks.makeHttpRequest(host, new_request)
```

* Send the modified request to the same host.

```python
            resp_info = self.helpers.analyzeResponse(response.getResponse())
            status_code = resp_info.getStatusCode()
```

* Analyze the HTTP response and get the status code.

```python
            print("[+] Status Code: {} → Payload: {}".format(status_code, payload))
```

* Print the status code and payload.

```python
            if status_code == 302:
                print("[!!!] Login Bypass Possible! → Payload: {}".format(payload))
```

* If **HTTP 302 Found** is returned (usually a redirect after successful login), it’s flagged.

---

### Helper: `inject_json_payload()`

```python
def inject_json_payload(self, request_info, request_bytes, payload):
```

* Creates a **new request with the payload injected into the body**.

```python
    raw_headers = request_info.getHeaders()
    body_offset = request_info.getBodyOffset()
    body = request_bytes[body_offset:].tostring().decode()
```

* Extracts headers and body from the original request.

```python
    new_body = payload.strip()
```

* Use the payload as the new JSON body.

```python
    headers = list(raw_headers)

    # Ensure Content-Type is application/json
    found_ct = False
    for i, h in enumerate(headers):
        if h.lower().startswith("content-type"):
            headers[i] = "Content-Type: application/json"
            found_ct = True
    if not found_ct:
        headers.append("Content-Type: application/json")
```

* Ensures that the new request uses the correct content type (`application/json`).

```python
    return self.helpers.buildHttpMessage(headers, new_body)
```

* Builds and returns a complete HTTP message from headers + body.

```python
except Exception as e:
    print("[!] JSON Payload Injection Error: {}".format(str(e)))
    return None
```

* Handles and logs errors.

---

## ✅ Summary

| Component             | Role                                                             |
| --------------------- | ---------------------------------------------------------------- |
| `BurpExtender`        | Initializes the extension, loads payloads, adds right-click menu |
| `perform_sqli_scan`   | Starts a background worker when the menu item is clicked         |
| `SQLiScanWorker`      | Sends injected requests and analyzes responses                   |
| `inject_json_payload` | Replaces request body with each test payload                     |
