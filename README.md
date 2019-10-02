# burp--Adhoc-Payload-Processors
Generate payload processors on the fly - without having to create individual extensions.

Name: Adhoc Payload Processing

Description:
Creates a new suite tab “Adhoc Payload Processing” that allows users to quickly define new payload processors with a single ruby function with a signature similar to the Burp Extension API using Ruby strings. All the boiler plate of registering extensions is handled automatically. The tool allows for creating, removing, and saving your payload processors within Burp suite.

Once the function body is defined simply click “Create Payload Processor” to make it immediately available in Intruder. Processors can be similarly removed with the “Remove Processor” button and a fresh processor template is always available clicking “Restore Template.” Finally, the currently defined payload processors can be saved using the “Save Extension State” button; this will preserve payload processors across  restarts of the suite.

Note: there are probably UI layout issues with larger fonts 

Screenshot:
![Alt text](/screenshot.png?raw=true "User Interface")
