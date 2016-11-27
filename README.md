# gst-api-authentication-java
How to do Authentication with GST API Using Java


# Requirements

- Java 8
- Maven 3.3+
- Java Unlimited Policy Files (http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)

Install Java 8, Maven and Download Java Unlimited Policy Files

Extract the Downloaded Zip file into jre/lib/security folder replacing existing files of the same name

You can run the Application from Any IDE/Command Line

## Install to Local Maven Repo for Using with Other Projects

```bash
mvn compile install

```

And Add maven dependency in the other project

```xml
<dependency>
    <groupId>net.smartgst</groupId>
    <artifactId>net.smartgst.auth</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```