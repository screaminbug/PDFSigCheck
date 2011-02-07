/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */



package hr.tstrelar.pdfsigcheck.helpers;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;

public class SignatureInfo {
	private AcroFields af;
	private Map<String, DocumentRevision> signatureRevisions = 
		new HashMap<String, DocumentRevision>();
	private KeyStore kall;
	private Logger log = Logger.getLogger(this.getClass().getCanonicalName());
	
	
	public SignatureInfo(String fileName) throws IOException, KeyStoreException {
		loadLocalKeyStore();
		init(fileName);
		
	}
	
	public SignatureInfo(String fileName, String localCertStore)
	               throws CertificateException, FileNotFoundException,
	                      KeyStoreException, NoSuchAlgorithmException,
	                      IOException {
		if (localCertStore == null) {
			loadLocalKeyStore();
		} else {
			log.info("Using your specified certificate");
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			Collection<? extends Certificate> col = 
				cf.generateCertificates(new FileInputStream(localCertStore));
			this.kall = KeyStore.getInstance(KeyStore.getDefaultType());
			kall.load(null, null);
			for (Certificate cert : col) {
				if (cert instanceof X509Certificate) {
					kall.setCertificateEntry(((X509Certificate) cert)
							.getSerialNumber()
							.toString(Character.MAX_RADIX), cert);
				}
		    
			}
		}
		init(fileName);
	}
	
	private void loadLocalKeyStore() throws KeyStoreException {
		log.info("Using global CA key store.");
		this.kall = PdfPKCS7.loadCacertsKeyStore();
	}
	
	private void init(String fileName) throws IOException {
		PdfReader reader = new PdfReader(fileName);
		af = reader.getAcroFields();
		log.info("Found " + getTotalRevisions() + " revision(s)");
		for (String s : af.getSignatureNames()) {
			signatureRevisions.put(s, new DocumentRevision(af, kall, s));
			log.fine("Signature name: " + s);
		}
	}
	
	public List<String> getSignatureNames() {
	    return new ArrayList<String>(signatureRevisions.keySet());
	}
	
	public DocumentRevision getRevision(String signatureName) {
	    return signatureRevisions.get(signatureName);
	}
	
	public int getTotalRevisions() {
		return af.getTotalRevisions();
	}

}


