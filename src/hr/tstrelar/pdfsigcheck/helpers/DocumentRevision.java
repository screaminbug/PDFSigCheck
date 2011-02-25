/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

package hr.tstrelar.pdfsigcheck.helpers;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
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
	private static int revisionNo;
	
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
	
	public Object verify(String certFile) throws FileNotFoundException {
		logIt(Level.INFO, ((X509Certificate) pk.getSigningCertificate()).toString());
	
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
	    
	    if (certFile!=null) {
	    	writeFiles(certFile);
	    }
	    revisionNo++;
	   
	    return retValue;
	}
	
	public Object verify() {  //ne treba FileNotFoundException jer nema fajla
		Object retValue = null;
		try {
			retValue = verify(null);
		} catch (FileNotFoundException e) {
			assert(false); //nemoguće da ovdje bude exception
		}
	    return retValue;
		
	}
	
	private void writeFiles(String certFile) {
		Certificate[] certChain = pk.getSignCertificateChain();
		int i=0;
		String certFileName;
		String certFileExt = "";
		if (certFile.contains(".")) {
			int columnIdx = certFile.indexOf('.');
			certFileName = certFile.substring(0, columnIdx);
			certFileExt = certFile.substring(columnIdx);
		} else {
			certFileName = certFile;
		}
		try {
			for (Certificate cert : certChain) {
				System.out.println(cert.toString());
				if (i==0) {
					doWrite(new File(certFileName+ "_rev" + revisionNo + certFileExt), 
							cert.getEncoded());
				} else { 
					doWrite(new File(certFileName + i + "_rev" + revisionNo + certFileExt), 
							cert.getEncoded());	
								
				}
				i++;
			}
		} catch (IOException ioex) {
			logIt(Level.SEVERE, ioex.getLocalizedMessage());
		} catch (CertificateEncodingException ceex) {
			logIt(Level.SEVERE, ceex.getLocalizedMessage());
		}
	}
	
	private void doWrite(File file, byte[] data) throws IOException {
		FileOutputStream fos = null;
		BufferedOutputStream out = null;
		
		try {
			fos = new FileOutputStream(file);
			out = new BufferedOutputStream(fos);		
			out.write(data);
		} finally {
			out.flush();
			out.close();
			fos.close();
		}
			
		
		
				
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
