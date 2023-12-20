package org.example;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;

public class XMLSamtykkeDocumentSecurity {

    public XMLSamtykkeDocumentSecurity() throws Exception {
        org.apache.xml.security.Init.init();
    }

    public void signXMLDocument(Document xmlDocToSign, Node refChild, X509Certificate signingCertificate, PrivateKey signingPrivateKey) throws Exception {
        try {
// Create an XML Signature object
            XMLSignature _signature = new XMLSignature(xmlDocToSign, "",
                    ALGO_ID_SIGNATURE_RSA_SHA1);
            System.out.print("XMLSignature created with [ALGO_ID_SIGNATURE_RSA_SHA1]");
// Signature is going to be enveloped by the document.
                    Node _test = xmlDocToSign.getDocumentElement();
            _test.insertBefore(_signature.getElement(), refChild);
            System.out.print("Signature Element added to XML Document");
            Transforms _transforms = new Transforms(xmlDocToSign);
            _transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            _transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
// Add the above Document/Reference
            _signature.addDocument("",
                    _transforms, "http://www.w3.org/2001/04/xmlenc#sha256");
            System.out.print("Transforms added to Signature with ["
                    + _transforms.toString());
// KeyInfo for the signing certificate
            _signature.addKeyInfo(signingCertificate);
            System.out.print("KeyInfo added to Signature with ["
                    + _signature.getKeyInfo().toString());
// Sign the XML document
            _signature.sign(signingPrivateKey);
            System.out.print("Document signed!");
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            Result output = new StreamResult(new File("signed.xml"));
            Source input = new DOMSource(xmlDocToSign);
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(input, output);
        } catch (Exception e) {
            System.out.print("Failed to create signature :: " + e);
            throw new Exception("Failed to create signature");
        }
    }

    public X509Certificate verifyXMLDocument(Document xmlDocToVerify) throws Exception {
        X509Certificate _cert = null;
        try {
// Signature Element
            Element _sigElement = (Element) xmlDocToVerify.getElementsByTagNameNS(
                    Constants.SignatureSpecNS,
                    Constants._TAG_SIGNATURE).item(0);
            System.out.print("Signature element found in Document");
// Creates a XMLSignature
            System.out.println(_sigElement);
            XMLSignature _signature = new XMLSignature(_sigElement, "");
            _cert = _signature.getKeyInfo().getX509Certificate();
// Check Signature
            if (_signature.checkSignatureValue(_cert) == false) {
                throw new Exception("invalid signature");
            }
            System.out.print("Document verified");
        } catch (Exception e) {
            System.out.print("Failed to verify document :: " + e);
            throw new Exception("Failed to verify document");
        }
        return _cert;
    }

    public X509Certificate getSignatureCertificate(Document xmlDoc) throws Exception {
        X509Certificate _cert = null;
        try {
// Signature Element from the document
            Element _sigElement = (Element) xmlDoc.getElementsByTagNameNS(
                    Constants.SignatureSpecNS,
                    Constants._TAG_SIGNATURE).item(0);
            System.out.print("Signature element found in Document");
// Creates a XMLSignature
            XMLSignature _signature = new XMLSignature(_sigElement, "");
            _cert = _signature.getKeyInfo().getX509Certificate();
            System.out.print("Certificate extracted");
        } catch (Exception e) {
            System.out.print("Failed to extract certificate :: " + e);
            throw new Exception("Failed to extract certificate");
        }
        return _cert;
    }

    public void encryptXMLDocument(Document xmlDocToEncrypt, Certificate encryptionCertificate) throws Exception {
        try {
            // Get a session(symmetric)key to be used for encrypting the element.
            Key _sessionKey = GenerateDataEncryptionKey();
            System.out.print("session[symmetric]key created");
            // Get a key to be used for encrypting the symmetric key.
            XMLCipher _keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            _keyCipher.init(XMLCipher.WRAP_MODE, encryptionCertificate.getPublicKey());
            EncryptedKey _encryptedKey = _keyCipher.encryptKey(xmlDocToEncrypt, _sessionKey);
            System.out.print("XMLCipher created");
            // Let us encrypt the contents of the element.
            XMLCipher _dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            _dataCipher.init(XMLCipher.ENCRYPT_MODE, _sessionKey);
            // Setting keyinfo inside the encrypted data being prepared.
            EncryptedData _encryptedData = _dataCipher.getEncryptedData();
            KeyInfo _keyInfo = new KeyInfo(xmlDocToEncrypt);
            _keyInfo.add(_encryptedKey);
            _encryptedData.setKeyInfo(_keyInfo);
            System.out.print("KeyInfo added to document");
            /*
             * doFinal -
             * "true" below indicates that we want to encrypt element's content
             * and not the element itself. Also, the doFinal method would
             * modify the document by replacing the EncryptedData element
             * for the data to be encrypted.
             */
            _dataCipher.doFinal(xmlDocToEncrypt, xmlDocToEncrypt.getDocumentElement(), true);
            System.out.print("Document encrypted");
            System.out.println(xmlDocToEncrypt);
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            Result output = new StreamResult(new File("encrypted.xml"));
            Source input = new DOMSource(xmlDocToEncrypt);
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(input, output);
        } catch (Exception e) {
            System.out.print("Failed to encrypt document :: " + e);
            throw new Exception("Failed to encrypt document");
        }
    }

    public void test(Certificate encryptionCertificate) throws Exception {
        try {
            System.out.println(Base64.getEncoder().encodeToString(encryptionCertificate.getPublicKey().getEncoded()));
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void encodeFile(String inputFile, String outputFile)
            throws IOException {
        Path inPath = Paths.get(inputFile);
        Path outPath = Paths.get(outputFile);
        try (OutputStream out = Base64.getEncoder().wrap(Files.newOutputStream(outPath))) {
            Files.copy(inPath, out);
        }
    }

    public void decodeFile(String encodedfilecontent, String decodedfile)
            throws IOException {
        Path inPath = Paths.get(encodedfilecontent);
        Path outPath = Paths.get(decodedfile);
        try (InputStream in = Base64.getDecoder().wrap(Files.newInputStream(inPath))) {
            Files.copy(in, outPath);
        }
    }

public void decryptXMLDocument(Document xmlDocToDecrypt,
                               PrivateKey decryptionPrivateKey) throws Exception {
    try {
// Find Encryption Element i XML Document
        Element _encryptedDataElement =
                (Element) xmlDocToDecrypt.getElementsByTagNameNS(
                        EncryptionConstants.EncryptionSpecNS,
                        EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
        System.out.print("EcryptedData element found in Document");
// Create XMLCipher to do the decryption
        XMLCipher _xmlCipher = XMLCipher.getInstance();
        _xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        _xmlCipher.setKEK(decryptionPrivateKey);
        System.out.print("XMLChiper initeret");
        /*
         * The following doFinal call replaces the encrypted data with
         * decrypted contents in the document.
         */
        _xmlCipher.doFinal(xmlDocToDecrypt, _encryptedDataElement);
        System.out.print("Document decrypted");
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        Result output = new StreamResult(new File("decrypted.xml"));
        Source input = new DOMSource(xmlDocToDecrypt);
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.transform(input, output);
    } catch (Exception e) {
        System.out.print("Failed to decrypt document :: " + e);
        throw new Exception("Failed to decrypt document");
    }
}

    private SecretKey GenerateDataEncryptionKey() throws Exception {
        String jceAlgorithmName = "DESede";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(168);
        return keyGenerator.generateKey();
    }
}
