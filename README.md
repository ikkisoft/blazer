# Blazer - AMF Testing Made Easy! ![Blazer Logo](http://i.imgur.com/SSTc20K.png "Blazer Logo")

**Blazer** is a custom [AMF messages][4] generator with fuzzing capabilities, developed as [Burp Suite plugin][1]. 
This extension can be used to generate and fuzz custom AMF messages. It is designed and implemented to make AMF testing easy, and yet allow researchers to control fully the entire security testing process.

Using Blazer, testing AMF-based applications is easier and more robust. As it is highly integrated in a well-known testing suite, web security practitioners can start using the tool with minimal setup in few seconds.

### From 0 to AMF messages generation and fuzzing in just few clicks

Blazer implements a new testing approach, introduced at [Black Hat USA 2012][5]. This automated gray-box testing technique allows security researchers to improve the coverage and the effectiveness of fuzzing efforts targeting complex applications.

For further details, please refer to the wiki [documentation](https://github.com/ikkisoft/blazer/wiki) and the original [whitepaper][7] and [presentation][6]. Another recent presentation is available on [SlideShare][8].

![Blazer UI][3]

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

Blazer has been developed in Java as a Burp Suite extension and released under the [GNU General Public License][2]. 
Burp extensions are supported by both free and professional Burp Suite versions.
 
> **Disclaimer:** 
> Please note that I am not actively maintaining this extension anymore. Feel free to fork and improve it! 

  [1]: http://portswigger.net/burp/
  [2]: http://www.gnu.org/licenses/
  [3]: http://i.imgur.com/VEfrW.png
  [4]: http://en.wikipedia.org/wiki/Action_Message_Format
  [5]: http://www.blackhat.com/usa/bh-us-12-briefings.html#Carettoni
  [6]: https://github.com/ikkisoft/blazer/blob/master/docs/BH2012_LucaCarettoni_PRESO_FINAL.pdf
  [7]: https://github.com/ikkisoft/blazer/blob/master/docs/BH2012_LucaCarettoni_WP_FINAL.pdf
  [8]: http://www.slideshare.net/ikkisoft/amf-testing-made-easy-deepsec-2012
