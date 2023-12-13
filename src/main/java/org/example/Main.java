package org.example;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class Main {
    public static void main(String[] args) throws Exception {
        //creating a constructor of file class and parsing an XML file
        File file = new File("C:\\Users\\Octavian\\IdeaProjects\\xmlenc\\src\\main\\resources\\examples\\signed.xml");
//an instance of factory that gives a document builder
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//an instance of builder to parse the specified xml file
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(file);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new FileInputStream("C:\\Users\\Octavian\\IdeaProjects\\xmlenc\\src\\main\\resources\\certs\\6.cer");

        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);



        XMLSamtykkeDocumentSecurity xmlSamtykkeDocumentSecurity = new XMLSamtykkeDocumentSecurity();
        xmlSamtykkeDocumentSecurity.encryptXMLDocument(doc, certificate);
    }
}