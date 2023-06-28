#==============================================================#
# Barsa deserilizer burp plugib                                #
# By Alireza Kalhor                                            #
# Contact Information:                                         #
#    Email    : alirezakalhor799@gmail.com                     #
#    Telegram : https://t.me/KalhorAlireza                     #
#    Twitter  : https://twitter.com/alirezaklhr                #
#==============================================================#

import json
import re
from burp import IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorTab, IHttpListener
from java.awt import BorderLayout, Font, Insets
from javax.swing.border import EmptyBorder
from javax.swing import JCheckBox, JPanel
from java.net import URL

PATTERN = r"[\x80-\xff]+"

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Create custom tab
        self.custom_tab = CustomTab(callbacks)
        # Add the custom tab
        callbacks.addSuiteTab(self.custom_tab)

        callbacks.setExtensionName("Serialized data editor")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)
        
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return SerializedInputTab(self, controller, editable)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            if self.custom_tab.encrypt_all_checkbox.isSelected():                
                request = messageInfo.getRequest()
                requestInfo = self._helpers.analyzeRequest(request)
                if requestInfo.getMethod() == "POST":
                    requestBody = request[requestInfo.getBodyOffset():].tostring().decode('utf-8')
                    requestHeader = requestInfo.getHeaders()
                    try:
                        requestBody = json.loads(bytes(requestBody))
                    except ValueError:
                        print("[!] ValueError in loading requestBody")
                    if "parameters" in requestBody:
                        if type(requestBody["parameters"]) == dict:
                            parameters = requestBody["parameters"]
                            parameters_string = json.dumps(parameters)
                            encrypted_parameters = encrypt(parameters_string)

                        else:
                            parameters = requestBody["parameters"]
                            encrypted_parameters = encrypt(parameters)
                            
                            
                        action = requestBody["action"]
                        post_body_dict = {
                            "action": action,
                            "parameters": encrypted_parameters
                        }

                        post_body = json.dumps(post_body_dict)
                        modifiedRequest = self._helpers.buildHttpMessage(requestHeader, post_body)
                        messageInfo.setRequest(modifiedRequest)           

            elif self.custom_tab.encrypt_checkbox.isSelected():     
                if toolFlag == 32:
                    # Request is comming from intruder  
                    request = messageInfo.getRequest()
                    requestInfo = self._helpers.analyzeRequest(request)
                    if requestInfo.getMethod() == "POST":
                        requestBody = request[requestInfo.getBodyOffset():].tostring().decode('utf-8')
                        requestHeader = requestInfo.getHeaders()
                        try:
                            requestBody = json.loads(bytes(requestBody))
                        except ValueError:
                            print("[!] ValueError in loading requestBody")
                        if "parameters" in requestBody:
                            if type(requestBody["parameters"]) == dict:
                                parameters = requestBody["parameters"]
                                parameters_string = json.dumps(parameters)
                                encrypted_parameters = encrypt(parameters_string)

                            else:
                                parameters = requestBody["parameters"]
                                encrypted_parameters = encrypt(parameters)
                                
                                
                            action = requestBody["action"]
                            post_body_dict = {
                                "action": action,
                                "parameters": encrypted_parameters
                            }

                            post_body = json.dumps(post_body_dict)
                            modifiedRequest = self._helpers.buildHttpMessage(requestHeader, post_body)
                            messageInfo.setRequest(modifiedRequest)  
            
                                
                    
        else:
            if self.custom_tab.decrypt_checkbox.isSelected():
                response = messageInfo.getResponse()
                responseInfo = self._helpers.analyzeRequest(response)
                responsetBody = response[responseInfo.getBodyOffset():].tostring().decode('utf-8')
                responsetHeaders = responseInfo.getHeaders()
                if responsetBody.startswith("$%$"):
                    responsetBody = responsetBody[3:] 
                    decrypted_response = decrypt(responsetBody)
                    response_body_bytes = self._helpers.stringToBytes(decrypted_response)
                    modifiedResponse = self._helpers.buildHttpMessage(responsetHeaders, response_body_bytes)
                    messageInfo.setResponse(modifiedResponse)
                else:
                    modifiedBody = re.sub(PATTERN, lambda match: decrypt(match.group()), responsetBody)
                    response_body_bytes = self._helpers.stringToBytes(modifiedBody)
                    modifiedResponse = self._helpers.buildHttpMessage(responsetHeaders, response_body_bytes)
                    messageInfo.setResponse(modifiedResponse)

class CustomTab(ITab):
    
    def __init__(self, callbacks):
        self.panel = JPanel()
        self.decrypt_checkbox = JCheckBox("Automatic decryption of responses")
        self.encrypt_checkbox = JCheckBox("Automatic encryption of requests (intruder)")
        self.encrypt_all_checkbox = JCheckBox("Automatic encryption of requests (ALL)")
        
    def getTabCaption(self):
        return "Serialized data editor"
    
    def getUiComponent(self):
        self.createUI()
        return self.panel
    
    def createUI(self):
        # Set the checkboxes' font
        # You can change these settings
        font = Font("Arial", Font.PLAIN, 30)
        self.decrypt_checkbox.setFont(font)
        self.encrypt_checkbox.setFont(font)
        self.encrypt_all_checkbox.setFont(font)

        # (PADDING_FROM_UP, PADDING_FROM_LEFT, PADDING_FROM_DOWN, PADDING_FROM_LEFT)
        decrypt_checkbox_padding = Insets(300, 500, 0, 0)
        encrypt_checkbox_padding = Insets(0, 500, 0, 0)
        encrypt_all_checkbox_padding = Insets(0, 500, 300, 0)
        
        self.decrypt_checkbox.setBorder(EmptyBorder(decrypt_checkbox_padding))
        self.encrypt_checkbox.setBorder(EmptyBorder(encrypt_checkbox_padding))
        self.encrypt_all_checkbox.setBorder(EmptyBorder(encrypt_all_checkbox_padding))
        
        # Set the panel layout and add checkboxes
        self.panel.setLayout(BorderLayout())
        self.panel.add(self.decrypt_checkbox, BorderLayout.NORTH)
        self.panel.add(self.encrypt_checkbox, BorderLayout.CENTER)
        self.panel.add(self.encrypt_all_checkbox, BorderLayout.SOUTH)



class SerializedInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.controller = controller
        
    def getTabCaption(self):
        return "Serialized data"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()  
        
    def isEnabled(self, content, isRequest):
        # Enable this tab for requests containing a "parameters" field in the POST body
        if isRequest:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            if requestInfo.getMethod() == "POST":
                requestBody = content[requestInfo.getBodyOffset():].tostring()
                try:
                    requestBody = json.loads(requestBody.encode("utf-8"))
                except ValueError:
                    return False
                if "parameters" in requestBody:
                    return True
        
        else:
            if self._extender.custom_tab.decrypt_checkbox.isSelected():
                return False
            return True

         
    def setMessage(self, content, isRequest):
        if isRequest:
            if content is None:
                # clear our display
                self._txtInput.setText(None)
                self._txtInput.setEditable(False)
            
            else:
                requestInfo = self._extender._helpers.analyzeRequest(content)
                requestBody = content[requestInfo.getBodyOffset():].tostring()
                
                try:
                    requestBody = json.loads(bytes(requestBody))
                except ValueError:
                    self._txtInput.setText("ValueError")
                    self._txtInput.setEditable(False)
                
                if b"parameters" in requestBody:
                    decrypted_request = decrypt(requestBody["parameters"])
                    pretty_json = json.dumps(json.loads(decrypted_request), indent=4)
                    self._txtInput.setText(pretty_json)
                    self._txtInput.setEditable(self._editable)
                
                else:
                    self._txtInput.setText("There is no parameters in request.")
                    self._txtInput.setEditable(False)
        else:
            #it's response
            responseInfo = self.controller.getHttpService()
            url = responseInfo.getProtocol().encode('utf-8').strip() + "://" + responseInfo.getHost().encode('utf-8').strip()  + ":" + str(responseInfo.getPort()) + "/"
            
            if self._extender._callbacks.isInScope(URL(url)):
                responseInfo = self._extender._helpers.analyzeResponse(content)
                responsetBody = content[responseInfo.getBodyOffset():].tostring().decode('utf-8')
           
                if responsetBody.startswith("$%$"):
                    responsetBody = responsetBody[3:]
                    
                    decrypted_response = decrypt(responsetBody)
                    self._txtInput.setText(decrypted_response)
                    self._txtInput.setEditable(False)
            
            else:
                self._txtInput.setText("[!] Origin of the sender is not in scope!")
                self._txtInput.setEditable(False)
        
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            # reserialize the data
            parameters = self._txtInput.getText()
            parameters = self._extender._helpers.bytesToString(parameters)
            encrypted_parameters = encrypt(parameters)
            requestInfo = self._extender._helpers.analyzeRequest(self._currentMessage)
            requestBody = self._currentMessage[requestInfo.getBodyOffset():].tostring()
            requestHeaders = requestInfo.getHeaders()

            try:
                requestBody = json.loads(bytes(requestBody))
            except ValueError:
                print("[!] ValueError in loading the requestBody")
            
            # now let's get the action parameter
            action = requestBody["action"].encode('utf-8').strip()
            
            # Let's build the full POST request body
            post_body = '{"action":' + '"' + action + '"' + ',' + '"parameters":' + '"' + encrypted_parameters + '"' + '}'
            post_body_bytes = self._extender._helpers.stringToBytes(post_body)

            request = self._extender._helpers.buildHttpMessage(requestHeaders, post_body_bytes)
            	
            # update the request with the new parameter value
            return request
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

def decrypt(encrypted_string):
    decrypted_string_list = []
    for char in encrypted_string:
        decrypted_string_list.append(ord(char))
    decrypted_string = [((char + 256 - 100)%256) for char in decrypted_string_list]
    
    decrypted_string = "".join([chr(char) for char in decrypted_string])
    return decrypted_string

def encrypt(string):
    encrypted_string_list = []
    for char in string:
        encrypted_string_list.append((ord(char) + 100) % 256)
    
    encrypted_string = "".join([chr(char) for char in encrypted_string_list])
    return encrypted_string.encode('utf-8')