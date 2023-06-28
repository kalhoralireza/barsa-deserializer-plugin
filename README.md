# Barsa Deserializer Plugin
A BurpSuite plugin that allows encryption and decryption of messages exchanged between the client and the server that is implemented by the Bersa system.

# Article
You can learn about the process of creating this plugin HERE.

# Installation
1. Visit [Jython Offical Site](https://www.jython.org/download), and download the latest stand alone JAR file.
2. Open Burp, go to **Extensions** -> **Extension Settings** -> **Python Environment**, set the **Location of Jython standalone JAR file** and **Folder for loading modules** to the directory where the Jython JAR file was saved.
4. Download the `Barsa-Plugin.py` from this project.
5. Go to the **Extensions** -> **Installed** and click **Add** under **Burp Extensions**.
6. Select **Extension type** of **Python** and select the **Barsa-Plugin.py** file.

# Features
- Added a custom tab in the `Repeater` tab for easy encryption and decryption of the req/res body.
- Included a customizable tab to modify the plugin's behavior, providing the following options:
    - Automatic decryption of responses
    - Automatic encryption of requests (intruder)
    - Automatic encryption of requests (ALL)


# Special Thanks
I would like to express my gratitude to my teacher, **[Mr. Kashfi](https://twitter.com/hkashfi/)**, who consistently guided and greatly assisted me in writing this article.