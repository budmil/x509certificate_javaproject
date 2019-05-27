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

import com.sun.xml.internal.bind.v2.runtime.NameBuilder;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;
import gui.Constants;
import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
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
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;
import sun.security.provider.DSAPublicKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import x509.v3.GuiV3;

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
          //  System.out.println("load: " + certificate.getSubjectX500Principal().getName());

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
//            access.setIssuer(certificate.getIssuerX500Principal().getName());
//            access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

            //SETTING CERTIFICATE VALIDITY
            access.setNotBefore(certificate.getNotBefore());
            access.setNotAfter(certificate.getNotAfter());

            //CERTIFICATE VERSION
            access.setVersion(certificate.getVersion() - 1);

            //SERIAL NUMBER
            access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));

            //SIGNATURE ALGORITHM
            String alg = certificate.getPublicKey().getAlgorithm();
            access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());

           // access.setPublicKeyAlgorithm(alg);
            access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
           // access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
            System.out.println(alg);
            //ovo ili ovo dole: access.setPublicKeyParameter(certificate.getPublicKey().toString());

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

            int ret = 1;

            //VERSION 3 EXTENSIONS
            if (certificate.getVersion() == 3) {

                //critical
                access.setCritical(Constants.BC, false);
                access.setCritical(Constants.SKID, false);
                access.setCritical(Constants.SDA, false);
                Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
                if (criticalExtensionOIDs != null) {
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

                }
                //basic constraints
                byte[] extensionValue2 = certificate.getExtensionValue("2.5.29.19");
                if (extensionValue2 != null) {
                    byte[] subjectOctets2 = ASN1OctetString.getInstance(extensionValue2).getOctets();
                    BasicConstraints basicConstraints = BasicConstraints.getInstance(subjectOctets2);
                    access.setPathLen(String.valueOf(basicConstraints.getPathLenConstraint()));
                    access.setCA(basicConstraints.isCA());
                    if (basicConstraints.isCA()){
                        ret = 2;
                    }
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

                    Vector<Attribute> v = subjectDirectoryAttributes.getAttributes();
                    for (Attribute attribute : v) {
                        ASN1ObjectIdentifier attrType = attribute.getAttrType();
                        String attrValue = attribute.getAttrValues().toString();
                        if (attrType == BCStyle.PLACE_OF_BIRTH) access.setSubjectDirectoryAttribute(Constants.POB, attrValue);
                        else if (attrType == BCStyle.COUNTRY_OF_CITIZENSHIP) access.setSubjectDirectoryAttribute(Constants.COC, attrValue);
                        else if (attrType == BCStyle.GENDER) access.setGender(attrValue); else if (attrType == BCStyle.DATE_OF_BIRTH) access.setDateOfBirth(attrValue);

                    }
                }

            }

            if (certificate.getSubjectDN() == certificate.getIssuerDN()) {
                ret = 0;
            }

            return ret;

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
            PublicKey subjectPublicKey = keyPair.getPublic();

            //subject
//            X500NameBuilder x500NameBuilder = new X500NameBuilder();
//            ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]{BCStyle.C, BCStyle.ST, BCStyle.L, BCStyle.O, BCStyle.OU, BCStyle.CN};
//            String[] values = new String[] {access.getSubjectCountry(), access.getSubjectState(), access.getSubjectLocality(),
//                                            access.getSubjectOrganization(), access.getSubjectOrganizationUnit(), access.getSubjectCommonName()};
//            x500NameBuilder.addMultiValuedRDN(oids,values);
//            X500Name subject = x500NameBuilder.build();
//            X500Name subject = new X500Name(access.getSubject());
//            System.out.println("save: " + subject.toString());
            //issuer
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);


            String country = access.getSubjectCountry();
            String state = access.getSubjectState();
            String locality = access.getSubjectLocality();
            String organisation = access.getSubjectOrganization();
            String organisationUnit = access.getSubjectOrganizationUnit();

            String commonName = access.getSubjectCommonName();

            nameBuilder.addRDN(BCStyle.CN, commonName);
            if (!organisationUnit.isEmpty())
                nameBuilder.addRDN(BCStyle.OU, organisationUnit);
            if (!organisation.isEmpty())
                nameBuilder.addRDN(BCStyle.O, organisation);
            if (!state.isEmpty())
                nameBuilder.addRDN(BCStyle.ST, state);
            if (!country.isEmpty())
                nameBuilder.addRDN(BCStyle.C, country);
            if (!locality.isEmpty())
                nameBuilder.addRDN(BCStyle.L, locality);
            X500Name issuer = nameBuilder.build();
            X500Name subject = issuer;

            //DateTo DateFrom
            Date notBefore = access.getNotBefore();
            Date notAfter = access.getNotAfter();

            //Serial Number
            BigInteger serialNumber = new BigInteger(access.getSerialNumber());


            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                   issuer,
                   serialNumber,
                   notBefore,
                   notAfter,
                   subject,
                   subjectPublicKey
            );

            if (access.getVersion() == Constants.V3) {


                //basic constraints
                if (!access.getPathLen().isEmpty()) {
                    BasicConstraints basicConstraints;
                    if (access.isCA()) {
                        basicConstraints = new BasicConstraints(Integer.parseInt(access.getPathLen()));
                    } else {
                        basicConstraints = new BasicConstraints(access.isCA());
                    }
                    certificateBuilder.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), basicConstraints.getEncoded());
                }

                //subject key identifier
                if (access.getEnabledSubjectKeyID()) {
                    SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKey);
                    certificateBuilder.addExtension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID), subjectKeyIdentifier.getEncoded());
                }

                //subject directory attributes
                String dateOfBirth = access.getDateOfBirth();
                String placeOfBirth = access.getSubjectDirectoryAttribute(Constants.POB);
                String countryOfCitizenship = access.getSubjectDirectoryAttribute(Constants.COC);
                String gender = access.getGender();

                Vector<Attribute> attributes = new Vector<>();

                if (dateOfBirth.length() > 0)
                    attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new DERGeneralString(dateOfBirth))));

                if (placeOfBirth.length() > 0)
                    attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DERGeneralString(placeOfBirth))));

                if (countryOfCitizenship.length() > 0)
                    attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DERGeneralString(countryOfCitizenship))));

                if (gender.length() > 0)
                    attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DERGeneralString(gender))));
                if (attributes.size() > 0) {
                    SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);
                    certificateBuilder.addExtension(Extension.subjectDirectoryAttributes, access.isCritical(Constants.SDA), subjectDirectoryAttributes.getEncoded());
                }
            }

            JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm());
            ContentSigner contentSigner = jcaContentSignerBuilder.build(privateKey);

            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));


            ks.setKeyEntry(s, privateKey, pass.toCharArray(), new Certificate[]{certificate});
            updateKeyStoreFile();
            return true;

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

        try (FileInputStream fis = new FileInputStream(s1)){
            if (ks.containsAlias(s)){
                GuiV3.reportError("Vec postoji par kljuceva/sertifikat sa zadatim imenom");
                return false;
            }

            // otvorimo udaljeni keystore
            KeyStore remoteKeyStore = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());

            // ucitamo sadrzaj udaljenog keystore-a
            remoteKeyStore.load(fis, s2.toCharArray());

            // smatramo da se nalazi samo jedan par kljuceva u fajlu
            // stoga dohvatamo taj jedan i sacuvamo ga
            String alias = remoteKeyStore.aliases().nextElement();
            Key key = remoteKeyStore.getKey(alias, s2.toCharArray());

            // sacuvamo entry
            ks.setKeyEntry(s, key, s2.toCharArray(), remoteKeyStore.getCertificateChain(alias));

            // sacuvamo novo stanje keystore-a
            updateKeyStoreFile();
//            KeyStore blaKS = KeyStore.getInstance("pkcs12");
//            FileInputStream fis = new FileInputStream(s1);
//            blaKS.load(fis, s2.toCharArray());
//            Enumeration<String> aliases_list =  blaKS.aliases();
//            while (aliases_list.hasMoreElements()) {
//                String curr = aliases_list.nextElement();
//                Key key = blaKS.getKey(curr, s2.toCharArray());
//                Certificate[] certificates = blaKS.getCertificateChain(curr);
//                ks.setKeyEntry(s, key, s2.toCharArray(), certificates);
//                updateKeyStoreFile();  //my method, keystore file has to be up to date to local keystore
//            }
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
            blaKS.load(null,null);
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
            ContentSigner contentSigner = jcaContentSignerBuilder.build((PrivateKey) ks.getKey(s1, pass.toCharArray()));
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
            PEMParser pemParser = new PEMParser(fileReader);
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
            this.csr = csr;
            String ret =  csr.getSubject().toString().replaceAll(", ", ",")
                    .replaceAll("=,", "= ,")
                    .replaceAll("  ", " ");
            System.out.println(ret);
            return ret;
            //todo might need to reformat final string for GUI purposes
        } catch (IOException e) {
            e.printStackTrace();
            reportError(e);
        }
        return null;
    }

    @Override
    public boolean signCSR(String file, String alias, String algorithm) {
        try(FileOutputStream fos = new FileOutputStream(file)) {

            //prepare for making a certificate
            BigInteger serialNumber =  new BigInteger(access.getSerialNumber());
            Date notBefore = access.getNotBefore();
            Date notAfter = access.getNotAfter();
            X509Certificate issuerCert = (X509Certificate) ks.getCertificate(alias);
            X500Name issuerName = new JcaX509CertificateHolder(issuerCert).getSubject(); //might be bad
            X500Name subjectName = this.csr.getSubject();
            SubjectPublicKeyInfo subjectPublicKeyInfo = this.csr.getSubjectPublicKeyInfo();

            //make a certificate
            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, subjectName, subjectPublicKeyInfo);
            //basic constraints
            if (!access.getPathLen().isEmpty()) {
                BasicConstraints basicConstraints;
                if (access.isCA()) {
                    basicConstraints = new BasicConstraints(Integer.parseInt(access.getPathLen()));
                } else {
                    basicConstraints = new BasicConstraints(access.isCA());
                }
                certificateBuilder.addExtension(Extension.basicConstraints, access.isCritical(Constants.BC), basicConstraints.getEncoded());
            }

            //subject key identifier
            if (access.getEnabledSubjectKeyID()) {
                SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);
                certificateBuilder.addExtension(Extension.subjectKeyIdentifier, access.isCritical(Constants.SKID), subjectKeyIdentifier.getEncoded());
            }

            //subject directory attributes
            String dateOfBirth = access.getDateOfBirth();
            String placeOfBirth = access.getSubjectDirectoryAttribute(Constants.POB);
            String countryOfCitizenship = access.getSubjectDirectoryAttribute(Constants.COC);
            String gender = access.getGender();

            Vector<Attribute> attributes = new Vector<>();

            if (dateOfBirth.length() > 0)
                attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new DERGeneralString(dateOfBirth))));

            if (placeOfBirth.length() > 0)
                attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DERGeneralString(placeOfBirth))));

            if (countryOfCitizenship.length() > 0)
                attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DERGeneralString(countryOfCitizenship))));

            if (gender.length() > 0)
                attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DERGeneralString(gender))));
            if (attributes.size() > 0) {
                SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);
                certificateBuilder.addExtension(Extension.subjectDirectoryAttributes, access.isCritical(Constants.SDA), subjectDirectoryAttributes.getEncoded());
            }


        //pkcs7
            JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(algorithm);
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias,pass.toCharArray());
            ContentSigner contentSigner = jcaContentSignerBuilder.build(privateKey);
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            List<JcaX509CertificateHolder> certificateChain = new ArrayList<>();
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(certificate.getEncoded());
            certificateChain.add(new JcaX509CertificateHolder(certificate));
            for(Certificate c :  ks.getCertificateChain(alias)) {
                certificateChain.add(new JcaX509CertificateHolder((X509Certificate) c));
            }
            cmsSignedDataGenerator.addCertificates(new CollectionStore(certificateChain));
            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData);
            fos.write(cmsSignedData.getEncoded());
            return true;

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException | CertificateException | CMSException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public boolean importCAReply(String file, String alias) {
        try (FileInputStream fis = new FileInputStream(file)) {
            CMSSignedData cmsSignedData = new CMSSignedData(fis);
            Store<X509CertificateHolder> certificateHolderStore = cmsSignedData.getCertificates();
            Collection<X509CertificateHolder> collection = certificateHolderStore.getMatches(null);
            X509Certificate[] certificateChain = new X509Certificate[collection.size()];
            int i=0;
            for (X509CertificateHolder h: collection) {
                certificateChain[i++] = new JcaX509CertificateConverter().getCertificate(h);
            }
//            for (int i = 0; i<array.length; i++) {
//                certificateChain[i] = new JcaX509CertificateConverter().getCertificate(array[i]);
//            }

            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pass.toCharArray());
            ks.setKeyEntry(alias, privateKey, pass.toCharArray(), certificateChain);

            updateKeyStoreFile();
            return true;

        } catch (IOException | CMSException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
            reportError(e);
        }
        return false;
    }

    @Override
    public boolean canSign(String s) {
        System.out.println("canSign");
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
            if ((certificate.getBasicConstraints() == -1 ) || (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))) return false; else return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
//        try {
//            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
//            if ( certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())){
//                Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
//                if (criticalExtensionOIDs != null) {
//                    for (String oid : criticalExtensionOIDs) {
//                        if (oid == org.bouncycastle.asn1.x509.Extension.basicConstraints.toString()) {
//                            byte[] extensionValue = certificate.getExtensionValue("2.5.29.19");
//                            if (extensionValue != null) {
//                                byte[] subjectOctets = ASN1OctetString.getInstance(extensionValue).getOctets();
//                                BasicConstraints basicConstraints = BasicConstraints.getInstance(subjectOctets);
//                                if (basicConstraints.isCA()) {
//                                    return true;
//                                } else {
//                                    return false;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//            reportError(e);
//        }
//        return false;
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        try {
            X509Certificate certificate = (X509Certificate) ks.getCertificate(s);
//            X509CertificateHolder certificateHolder = new X509CertificateHolder(org.bouncycastle.asn1.x509.Certificate.getInstance(certificate));
   //         System.out.println("ovo: " + certificateHolder.getSubject().toString());
           // return certificateHolder.getSubject().toString() + "," + "SA=" + certificateHolder.getSignatureAlgorithm().toString();
            //certificate.getSubjectPrincipal.getName - also an option

            String ret = (certificate.getSubjectX500Principal().getName() + "," + "SA=" + certificate.getSigAlgName()).replaceAll(", ", ",")
                    .replaceAll("=,", "= ,")
                    .replaceAll("  ", " ");
            System.out.println(ret);
            return ret;

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
            System.out.println("getCertPublicKey: "+ certificate.getPublicKey().getAlgorithm());
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
            System.out.println("getCertPublicKeyParameter");
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
