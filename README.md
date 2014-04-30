Blazer - AMF Testing Made Easy! 
=====================

**Blazer** is a custom *AMF messages generator with fuzzing capabilities*, developed as [Burp Suite plugin][1]. 
This extension can be used to generate and fuzz custom AMF messages. It is designed and implemented to make AMF testing easy, and yet allows researchers to control fully the entire security testing process.

Features:

 - Automatic Java objects generation from method signatures via Java reflection and "best-fit" heuristics 
 - Fuzzing capabilities, with customizable data pools and attack vectors
 - Ability to start, pause, restore and stop testing 
 - Easy-to-use internal methods to construct custom AMF messages 
 - Embedded BeanShell for manual testing 
 - JARs, classes and Java src import feature
 - AMF request/response export functionality (AMF2XML) 
 - Sandboxing using a custom security manager 
 - Highly integrated in Burp Suite 
 - Support for Java server-side remoting technologies (Adobe BlazeDS, Adobe LiveCycle Data Services, GraniteDS, ...)

For more details, please refer to the [Google project page][2].

![Blazer UI][3]
 
 
> **Disclaimer:** 
> Please note that I am not actively maintaining this extension. Still, if you plan to fork and work on it, I am happy to help you! 


  [1]: http://portswigger.net/burp/
  [2]: https://code.google.com/p/blazer/
  [3]: http://i.imgur.com/VEfrW.png
