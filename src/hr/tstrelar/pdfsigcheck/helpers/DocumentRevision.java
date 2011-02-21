/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

package hr.tstrelar.pdfsigcheck.helpers;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfPKCS7.X509Name;

public class DocumentRevision {
	private AcroFields af;
	private String signatureName;
	private PdfPKCS7 pk;
	private KeyStore kall;
	private Logger logger = Logger.getLogger(this.getClass().getCanonicalName());
	
	protected DocumentRevision(AcroFields af, KeyStore kall, String signatureName) {
		this.af = af;
		this.kall = kall; 
		this.signatureName = signatureName;
		pk = af.verifySignature(signatureName);
		
	}
	
	public void extract() {
		 try {
			   FileOutputStream out = null;
			   InputStream ip = null;
			   try {
				   out = new FileOutputStream("revision_" + signatureName + ".pdf");
				   byte bb[] = new byte[8192];
				   ip = af.extractRevision(signatureName);
				   int n = 0;
				   while ((n = ip.read(bb)) > 0)
				      out.write(bb, 0, n);
				   
			   } finally {
				   if (out != null) out.close();
				   if (ip != null) ip.close();
			   }
		   } catch (IOException ioex) {
			   logIt(Level.SEVERE, ioex.getLocalizedMessage());
		   }
	}
	
	public X509Name getSubject() {
		return PdfPKCS7.getSubjectFields(pk.getSigningCertificate());
	}
	
	public boolean isDocumentModified() throws SignatureException {
		boolean verify = pk.verify();
		Level level = verify ? Level.INFO : Level.WARNING;
		logIt(level, "Verify OK: " + verify);
		return !verify;
	}
	
	public Object verify() {
		logIt(Level.INFO, pk.getSigningCertificate().toString());
		Calendar cal = pk.getSignDate();
	    Certificate pkc[] = pk.getCertificates();

	    Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
	   
	    Object retValue = null;
	    if (fails == null) {
		    logIt(Level.INFO, 
				   "Certificates verified against the KeyStore");		       
	    } else {
		    logIt(Level.WARNING, 
		 		   "Certificate failed: " + fails[1]);
	        retValue = fails[1];
	    }
	   
	    return retValue;
	}
	
	public String getSignatureName() {
		return signatureName;
	}
	
	public boolean signatureCoversWholeDocument() {
		boolean covers = af.signatureCoversWholeDocument(signatureName);
		logIt(Level.INFO, 
				"Signature covers whole document: " + covers);
		return covers;
	}
	
	
	public int getRevisionNumber() {
		int revNum = af.getRevision(signatureName);
		logIt(Level.INFO, "Revision number " + revNum);
		return revNum;
	}
	
	private void logIt(Level level, String msg) {
		logger.log(level, signatureName + ": " + msg);		
	}

}
