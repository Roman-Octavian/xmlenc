package org.example;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) throws Exception {
        File file = new File("src/main/resources/examples/request.xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(file);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new FileInputStream("src/main/resources/certs/test.cer");
        Certificate skatPub = certificateFactory.generateCertificate(certificateInputStream);

        CertificateFactory certificateFactory2 = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream2 = new FileInputStream("src/main/resources/certs/publicCert.pem");
        Certificate dreamplanPub = certificateFactory2.generateCertificate(certificateInputStream2);

        File privateKey = new File(Main.class.getClassLoader().getResource("./certs/privateKey.pem").getFile());

        PrivateKeyLoader privateKeyLoader = new PrivateKeyLoader();
        PrivateKey key = privateKeyLoader.readPKCS8PrivateKey(privateKey);

        XMLSamtykkeDocumentSecurity xmlSamtykkeDocumentSecurity = new XMLSamtykkeDocumentSecurity();
        xmlSamtykkeDocumentSecurity.signXMLDocument(doc, doc.getDocumentElement().getFirstChild(), (X509Certificate) dreamplanPub, key);

        xmlSamtykkeDocumentSecurity.encryptXMLDocument(doc, skatPub);

        xmlSamtykkeDocumentSecurity.encodeFile("encrypted.xml", "encoded.xml");

    }
}