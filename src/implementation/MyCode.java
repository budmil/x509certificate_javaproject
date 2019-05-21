package implementation;

import code.GuiException;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemWriter;

public class MyCode extends x509.v3.CodeV3 {

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
            access.reportError(e);
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            ks = KeyStore.getInstance("pkcs12");
            ks.load(null,null);
            ks.store(new FileOutputStream(file_to_store_ks), pass.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            return ks.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public void resetLocalKeystore() {

    }

    @Override
    public int loadKeypair(String s) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {

        return false;
    }

    @Override
    public boolean removeKeypair(String s) {        //done

        try {

            ks.deleteEntry(s);
            updateKeyStoreFile();       //my method, keystore file has to be up to date to local keystore
            return true;

        } catch (KeyStoreException e) {
            access.reportError(e);
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
            access.reportError(e);
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
            access.reportError(e);
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
            access.reportError(e);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    access.reportError(e);
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
        return false;
    }

    @Override
    public String importCSR(String s) {
        return null;
    }

    @Override
    public boolean signCSR(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCAReply(String s, String s1) {
        return false;
    }

    @Override
    public boolean canSign(String s) {
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        return null;
    }
}
