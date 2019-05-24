package implementation;

import code.GuiException;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.DateFormat;
import java.util.*;

import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;
import gui.Constants;
import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;
import sun.security.provider.DSAPublicKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

import static gui.GuiInterfaceV1.reportError;

public class MyCode extends x509.v3.CodeV3 {

    private PKCS10CertificationRequest csr;
    private static  KeyStore ks;
    private static final String pass = "root";
    private static final String file_to_store_ks = "mojaRadnja.p12";


    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }

    private void updateKeyStoreFile() {
        try {
            FileOutputStream fos = new FileOutputStream(file_to_store_ks);
            ks.store(fos, pass.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
            reportError(e);
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            ks = KeyStore.getInstance("pkcs12");
            File fajl = new File(file_to_store_ks);
            if (fajl.exists()) {
                FileInputStream fis = new FileInputStream(file_to_store_ks);
                ks.load(fis, pass.toCharArray());
                return ks.aliases();
            } else {
                ks.load(null, null);
                ks.store(new FileOutputStream(file_to_store_ks), pass.toCharArray());
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
            reportError(e);
        }

        return null;
    }

    @Override
    public void resetLocalKeystore() {
        try {
            ks.load(null,null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            reportError(e);
            e.printStackTrace();
        }
        updateKeyStoreFile();
    }

    @Override
    public int loadKeypair(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);

            //SETTING SUBJECT INFO
            access.setSubject(certificate.getSubjectX500Principal().getName());
//            Scanner scanner = new Scanner (certificate.getSubjectX500Principal().getName());
//            scanner.useDelimiter(",");
//            while (scanner.hasNext()) {
//                Scanner auxScanner = new Scanner(scanner.next());
//                auxScanner.useDelimiter("=");
//                switch (auxScanner.next()){
//                    case "CN": access.setSubjectCommonName(auxScanner.next());break;
//                    case "OU": access.setSubjectOrganizationUnit(auxScanner.next()); break;
//                    case "O": access.setSubjectOrganization(auxScanner.next()); break;
//                    case "ST": access.setSubjectState(auxScanner.next()); break;
//                    case "C": access.setSubjectCountry(auxScanner.next()); break;
//                    case "L": access.setSubjectLocality(auxScanner.next());break;
//                }
//            }

            //SETTING CA INFO //TODO proveri ovo
            access.setIssuer(certificate.getIssuerX500Principal().getName());
            access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

            //SETTING CERTIFICATE VALIDITY
            access.setNotBefore(certificate.getNotBefore());
            access.setNotAfter(certificate.getNotAfter());

            //CERTIFICATE VERSION
            access.setVersion(certificate.getVersion() - 1);

            //SERIAL NUMBER
            access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));

            //SIGNATURE ALGORITHM
            String alg = certificate.getPublicKey().getAlgorithm();
            access.setPublicKeyAlgorithm(alg);
            access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
            if (alg == "RSA") {
                RSAPublicKeyImpl rsa_alg = (RSAPublicKeyImpl) certificate.getPublicKey();
                access.setPublicKeyParameter(String.valueOf(rsa_alg.getModulus().bitLength())); //+1 ?
            }

            if (alg == "DSA") {
                DSAPublicKeyImpl dsa_alg = (DSAPublicKeyImpl) certificate.getPublicKey();
                access.setPublicKeyParameter(String.valueOf(dsa_alg.getY().bitLength()));
            }
            //todo or like this??? ECPrivateKeyImpl ecPrivateKey = (ECPrivateKeyImpl) keyStore.getKey(s, password);
            //                    ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
            if (alg == "EC") {
                ECPublicKeyImpl ec_alg = (ECPublicKeyImpl) certificate.getPublicKey();
                access.setPublicKeyECCurve(String.valueOf(ec_alg.getParams().getCurve()));
                access.setPublicKeyParameter(String.valueOf(ec_alg.getParams()));
            }

            //TODO izgleda da sam obrnuo load i save keypair (vidi Critical)
            //VERSION 3 EXTENSIONS
            if (certificate.getVersion() == 3) {

                //critical
                access.setCritical(Constants.BC, false);
                access.setCritical(Constants.SKID, false);
                access.setCritical(Constants.SDA, false);
                Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
                for (String oid : criticalExtensionOIDs) {

                    if (oid == org.bouncycastle.asn1.x509.Extension.basicConstraints.toString()) {
                        access.setCritical(Constants.BC, true);
                    }

                    if (oid == org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.toString()) {
                        access.setCritical(Constants.SKID, true);
                    }

                    if (oid == org.bouncycastle.asn1.x509.Extension.subjectDirectoryAttributes.toString()) {
                        access.setCritical(Constants.SDA, true);
                    }

                }


                //basic constraints
                byte[] extensionValue2 = certificate.getExtensionValue("2.5.29.19");
                if (extensionValue2 != null) {
                    byte[] subjectOctets2 = ASN1OctetString.getInstance(extensionValue2).getOctets();
                    BasicConstraints basicConstraints = BasicConstraints.getInstance(subjectOctets2);
                    access.setPathLen(String.valueOf(basicConstraints.getPathLenConstraint()));
                    access.setCA(basicConstraints.isCA());
                }


            //subject key identifier
                byte[] extensionValue = certificate.getExtensionValue("2.5.29.14");
                if (extensionValue != null) {
                    byte[] subjectOctets = ASN1OctetString.getInstance(extensionValue).getOctets();
                    SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(subjectOctets);
                    access.setSubjectKeyID(String.valueOf(subjectKeyIdentifier.getKeyIdentifier()));
                    access.setEnabledSubjectKeyID(true);
                } else {
                    access.setEnabledSubjectKeyID(false);
                }


            //subject directory attributes
                byte[] extensionValue1 = certificate.getExtensionValue("2.5.29.9");
                if (extensionValue1 != null) {
                    byte[] subjectOctets1 = ASN1OctetString.getInstance(extensionValue1).getOctets();
                    SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(subjectOctets1);

                    //TODO ne znam sta ispisuje subjectDirectoryAttriutes vektor, pa kad to proverim mozemo popuniti polja
                    Vector v = subjectDirectoryAttributes.getAttributes();
//                    for (Object s123 : v) {
//                        System.out.println(
//                                s123
//                        );
//                    }
                }
//                access.setSubjectDirectoryAttribute(Constants.POB, subjectDirectoryAttributes.getAttributes()); //Place of birth
//                access.setSubjectDirectoryAttribute(Constants.COC, String v); //Country of citizenship
//               access.setGender();
//                access.setDateOfBirth();


            }

            return 0;
            //TODO return

        } catch (KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        }


        return -1;
    }

    @Override
    public boolean saveKeypair(String s) {
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(access.getPublicKeyECCurve());
            keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

            //publicKeyInfo
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey subjectPublicKeyInfo = keyPair.getPublic();

            //subject
            X500NameBuilder x500NameBuilder = new X500NameBuilder();
            ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]{BCStyle.C, BCStyle.ST, BCStyle.L, BCStyle.O, BCStyle.OU, BCStyle.CN};
            String[] values = new String[] {access.getSubjectCountry(), access.getSubjectState(), access.getSubjectLocality(),
                                            access.getSubjectOrganization(), access.getSubjectOrganizationUnit(), access.getSubjectCommonName()};
            x500NameBuilder.addMultiValuedRDN(oids,values);
            X500Name subject = x500NameBuilder.build();

            //issuer
            X500Name issuer = subject;

            //DateTo DateFrom
            Date notBefore = access.getNotBefore();
            Date notAfter = access.getNotAfter();

            //Serial Number
            BigInteger serialNumber = BigInteger.valueOf(Long.parseLong(access.getSerialNumber()));


            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                   issuer,
                   serialNumber,
                   notBefore,
                   notAfter,
                   subject,
                   subjectPublicKeyInfo
            );

            if (access.getVersion() == Constants.V3) {
                access.setCritical(Constants.BC, false);
                access.setCritical(Constants.SKID, false);
                access.setCritical(Constants.SDA, false);

                //basic constraints
                BasicConstraints basicConstraints = new BasicConstraints(Integer.parseInt(access.getPathLen()));
                certificateBuilder.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), basicConstraints.getEncoded());


                //subject key identifier
                if (access.getEnabledSubjectKeyID()) {
                    SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(subjectPublicKeyInfo.getEncoded());
                    certificateBuilder.addExtension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID), subjectKeyIdentifier.getEncoded());
                }

                //subject directory attributes
                Vector v = new Vector();
                v.add(access.getSubjectDirectoryAttribute(Constants.POB));
                v.add(access.getSubjectDirectoryAttribute(Constants.COC));
                v.add(access.getGender());
                v.add(access.getDateOfBirth());
                SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(v);
                certificateBuilder.addExtension(Extension.subjectDirectoryAttributes, access.isCritical(Constants.SDA), subjectDirectoryAttributes.getEncoded());
            }

            JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm());
            ContentSigner contentSigner = jcaContentSignerBuilder.build(privateKey);

            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));


            ks.setKeyEntry(s, privateKey, pass.toCharArray(), new Certificate[]{certificate});
            updateKeyStoreFile();

        } catch (CertificateException | IOException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException | KeyStoreException e) {
           e.printStackTrace();
           reportError(e);
        }

        return false;
    }

    @Override
    public boolean removeKeypair(String s) {        //done

        try {

            ks.deleteEntry(s);
            updateKeyStoreFile();       //my method, keystore file has to be up to date to local keystore
            return true;

        } catch (KeyStoreException e) {
            reportError(e);
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {   //done

        try {
            KeyStore blaKS = KeyStore.getInstance("pkcs12");
            FileInputStream fis = new FileInputStream(s1);
            blaKS.load(fis, s2.toCharArray());
            Enumeration<String> aliases_list =  blaKS.aliases();
            while (aliases_list.hasMoreElements()) {
                String curr = aliases_list.nextElement();
                Key key = blaKS.getKey(curr, s2.toCharArray());
                Certificate[] certificates = blaKS.getCertificateChain(curr);
                ks.setKeyEntry(s, key, s2.toCharArray(), certificates);
                updateKeyStoreFile();  //my method, keystore file has to be up to date to local keystore
            }
            return true;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        try {
            KeyStore blaKS = KeyStore.getInstance("pkcs12");
            Key key = ks.getKey(s,pass.toCharArray());
            Certificate[] certificates = ks.getCertificateChain(s);
            blaKS.setKeyEntry(s,key,s2.toCharArray(),certificates);
            FileOutputStream fos = new FileOutputStream(s1);
            blaKS.store(fos, s2.toCharArray());
            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | CertificateException e) {
            e.printStackTrace();
            reportError(e);
        }

        return false;
    }

    @Override
    public boolean importCertificate(String s, String s1) {

        InputStream inStream = null;
        try {
            inStream = new FileInputStream(s);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
            ks.setCertificateEntry(s1,cert);
            updateKeyStoreFile();
            return true;
        } catch (FileNotFoundException | CertificateException | KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    reportError(e);
                }
            }
        }
        return false;
    }

    @Override
    public boolean exportCertificate(String s, String s1, int i, int i1) {
        try {
            if (i1 == 0) { //head only
                X509Certificate certificate = (X509Certificate) ks.getCertificate(s1);
                if (i == 0) {  //DER encoding
                    FileOutputStream fos = new FileOutputStream(new File(s + ".cer"));
                    fos.write(certificate.getEncoded());
                    fos.flush();
                    fos.close();
                } else {    //PEM encoding
                    JcaPEMWriter pemWriter = new JcaPEMWriter (new FileWriter(s + ".cer"));
                    pemWriter.writeObject(certificate);
                    pemWriter.flush();
                    pemWriter.close();
                }
            } else { //whole chain
                X509Certificate[] certificates = (X509Certificate[]) ks.getCertificateChain(s1);
                if (i == 0) {   //DER encoding
                    FileOutputStream fos = new FileOutputStream(new File(s + ".cer"));
                    int j = 0;
                    while (j != certificates.length) {
                        fos.write(certificates[j].getEncoded());
                        j++;
                    }
                    fos.flush();
                    fos.close();
                } else {    //PEM encoding
                    JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(s + ".cer"));
                    int j = 0;
                    while (j != certificates.length){
                        pemWriter.writeObject(certificates[j]);
                        j++;
                    }
                    pemWriter.flush();
                    pemWriter.close();
                }
            }
            return true;
        } catch (KeyStoreException | CertificateEncodingException | IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean exportCSR(String s, String s1, String s2) {
        try(FileWriter fileWriter = new FileWriter(s)) {

            X509Certificate certificate = (X509Certificate) ks.getCertificate(s1);

            JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                    certificate.getSubjectX500Principal(),
                    certificate.getPublicKey()
            );
            JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(s2);
            ContentSigner contentSigner = jcaContentSignerBuilder.build((PrivateKey) ks.getKey(s, pass.toCharArray()));
            PKCS10CertificationRequest csr = jcaPKCS10CertificationRequestBuilder.build(contentSigner);

            JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(fileWriter);
            jcaPEMWriter.writeObject(csr);
            jcaPEMWriter.close();
            return true;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public String importCSR(String s) {

        try (FileReader fileReader = new FileReader(s)){

            PemReader pemReader = new PemReader(fileReader);
            PEMParser pemParser = new PEMParser(pemReader);
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
            this.csr = csr;
            return csr.getSubject().toString();
            //todo might need to reformat final string for GUI purposes
        } catch (IOException e) {
            e.printStackTrace();
            reportError(e);
        }
        return null;
    }

    @Override
    public boolean signCSR(String file, String alias, String algorithm) {
        try(FileWriter fileWriter = new FileWriter(file)) {

            X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
            PublicKey publicKey = certificate.getPublicKey();
            PrivateKey privateKey;

        } catch (IOException | KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public boolean importCAReply(String s, String s1) {
        return false;
    }

    @Override
    public boolean canSign(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
            if ( certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())){
                Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
                for (String oid : criticalExtensionOIDs) {
                    if (oid == org.bouncycastle.asn1.x509.Extension.basicConstraints.toString()) {
                        byte[] extensionValue = certificate.getExtensionValue("2.5.29.19");
                        if (extensionValue != null) {
                            byte[] subjectOctets = ASN1OctetString.getInstance(extensionValue).getOctets();
                            BasicConstraints basicConstraints = BasicConstraints.getInstance(subjectOctets);
                            if (basicConstraints.isCA()) {
                                return true;
                            } else {
                                return false;
                            }
                        }
                    }
                }
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
            X509CertificateHolder certificateHolder = new X509CertificateHolder(org.bouncycastle.asn1.x509.Certificate.getInstance(certificate));
            //certificate.getSubjectPrincipal.getName - also an option
            return certificateHolder.getSubject().toString() + "," + "SA=" + certificateHolder.getSignatureAlgorithm().toString();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        }
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
            return certificate.getPublicKey().getAlgorithm();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            reportError(e);
        }
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey instanceof DSAPublicKey)
                return String.valueOf(((DSAPublicKey) publicKey).getY().bitLength());
            else if (publicKey instanceof RSAPublicKey) {
                return String.valueOf(((RSAPublicKey) publicKey).getModulus().bitLength());
            } else {
                ECPrivateKeyImpl ecPrivateKey = (ECPrivateKeyImpl) ks.getKey(s, pass.toCharArray()); //private or public
                return ecPrivateKey.getParams().getCurve().toString();
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
            reportError(e);
        }
        return null;
    }
}
