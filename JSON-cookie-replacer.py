from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel, JScrollPane, JTextArea, JButton
import json


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JSON cookie replacer")
        self.cookieStore = {}
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return CookieTab(self.callbacks, self.helpers, controller, self.cookieStore)


class CookieTab(IMessageEditorTab):

    def __init__(self, callbacks, helpers, controller, cookieStore):
        self.cookieStore = cookieStore
        self.callbacks = callbacks
        self.helpers = helpers
        self.controller = controller
        self.currentMessage = None

        self.panel = JPanel()
        self.panel.setLayout(None)

        self.textArea = JTextArea()
        scroll = JScrollPane(self.textArea)
        scroll.setBounds(10, 10, 520, 220)

        self.clearButton = JButton("Clear", actionPerformed=self.clearText)
        self.clearButton.setBounds(10, 240, 100, 30)

        self.applyButton = JButton("Apply", actionPerformed=self.applyCookies)
        self.applyButton.setBounds(120, 240, 100, 30)

        self.panel.add(scroll)
        self.panel.add(self.clearButton)
        self.panel.add(self.applyButton)

    # --- Tab metadata ---

    def getTabCaption(self):
        return "Cookies"

    def getUiComponent(self):
        return self.panel

    def isEnabled(self, content, isRequest):
        return isRequest

    # --- Message handling ---

    def setMessage(self, content, isRequest):
        self.currentMessage = content
        if not content:
            return

        requestInfo = self.helpers.analyzeRequest(content)
        host = None
        for h in requestInfo.getHeaders():
            if h.lower().startswith("host:"):
                host = h.split(":", 1)[1].strip()
                break

        if not host:
            return

        if host in self.cookieStore:
            self.textArea.setText(self.cookieStore[host])

    def getMessage(self):
        return self.currentMessage

    def isModified(self):
        return self.currentMessage is not None

    def getSelectedData(self):
        return None
    
    def clearText(self, event):
        self.textArea.setText("")

    # --- Core logic ---

    def applyCookies(self, event):
        if not self.currentMessage:
            return

        try:
            jsonText = self.textArea.getText()
            jsonCookies = json.loads(jsonText)
            requestInfo = self.helpers.analyzeRequest(self.currentMessage)
            host = None
            for h in requestInfo.getHeaders():
                if h.lower().startswith("host:"):
                    host = h.split(":", 1)[1].strip()
                    break

            if not host:
                return
            self.cookieStore[host] = jsonText
        except Exception as e:
            print("CookieTab error:", e)
            return

        requestInfo = self.helpers.analyzeRequest(self.currentMessage)
        headers = list(requestInfo.getHeaders())
        body = self.currentMessage[requestInfo.getBodyOffset():]

        cookieIndex = -1
        for i, h in enumerate(headers):
            if h.lower().startswith("cookie:"):
                cookieIndex = i
                break

        if cookieIndex == -1:
            return

        # Parse existing cookies
        cookieHeader = headers[cookieIndex][7:].strip()
        cookieMap = {}

        for c in cookieHeader.split(";"):
            if "=" in c:
                k, v = c.strip().split("=", 1)
                cookieMap[k] = v
        self.cookieStore[host] = self.textArea.getText()
        # Replace values from JSON
        for item in jsonCookies:
            name = item.get("name")
            value = item.get("value")
            if name in cookieMap:
                cookieMap[name] = value

        # Rebuild Cookie header
        newCookieHeader = "Cookie: " + "; ".join(
            ["{}={}".format(k, v) for k, v in cookieMap.items()]
        )

        headers[cookieIndex] = newCookieHeader
        newRequest = self.helpers.buildHttpMessage(headers, body)
        self.currentMessage = newRequest
        self.callbacks.issueAlert("Cookies updated")
