```
!!!
This repository contains implementation of J-Pake which was a result of an assignament for the Security Technologies project of Masaryk University. The implementation has number of issues, such as secrets not being cleared, and usage of non-Javacard compatible library. It is not fit for use in transfering secrets, nor is actively supported.
```
# PV204 Security Technologies Project

Project of [PV204 Security Technologies for Spring, 2020](https://is.muni.cz/course/fi/spring2020/PV204).

1. Analyze 3 certificates, report and presentation.  
   * [https://www.commoncriteriaportal.org/products/](https://www.commoncriteriaportal.org/products/)
2. Design and implement secure channel using ECDH.
   * J-Pake secure channel establishment and AES256 encrypted communication, for JavaCard
3. Audit and attack other implementation

## Certificates

* FM1280 V05
* genuscreen 7.0
* Thinklogical TLX1280

## Team Members

* [Anh Minh Tran](https://github.com/TAnhMinh)  
* [Ankur Lohchab](https://github.com/ankurlohchab)  
* [Tomáš Madeja](https://github.com/TomasMadeja

## J-Pake secure channel
The implementation was only tested for JCardSym. It includes a SecureChannel class that can be used for establishing connection and communication as seen below.

```
JCardSymInterface sym = JCardSymInterface.defaultCreateConnect();

byte[] id = Util.hexStringToByteArray("00010203040506070809");
char[] password = {'1', '1', '1', '1'};
SecureChannel channel = new SecureChannel(sym, id, password);
channel.establishSC();

ResponseAPDU r;
byte[] buff;
r = channel.send(CMD_HELLO);
buff = r.getData();
System.out.println(channel.decryptDataBuffer(buff));
System.out.println(Util.bytesToHex(buff));
```

This also showcases the existing api. This secure channel only provides option to create channel, establish it, and send/recieve data. User is responsible for tracking the size of their APDUS (exception is raised if APDU is too large).
