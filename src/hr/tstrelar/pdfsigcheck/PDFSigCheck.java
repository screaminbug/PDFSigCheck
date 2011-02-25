/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

package hr.tstrelar.pdfsigcheck;

import hr.tstrelar.pdfsigcheck.helpers.DocumentRevision;
import hr.tstrelar.pdfsigcheck.helpers.SignatureInfo;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Scanner;

public class PDFSigCheck {

	/**
	 * @param args
	 */
	private static SignatureInfo checker;
	private static int EXCEPTION_THROWN = -1;
	private static int ARGUMENTS_ERROR = -2;
	private static final String OUT_ARGUMENT = "o=";
	
	public static void main(String[] args) {
		int returnValue = 0;
		String pdfFile = null;
		String storeFile = null;
		String certFile = null;
		try {
					
			switch (args.length) {
			case 0:
				// uvijek vrati 0 za interactive ako nema drugih exceptiona
				interactive();
				System.exit(0); 
			case 3:
			case 2:
				for (int i=1; i<args.length; i++) {
					if (args[i].contains(OUT_ARGUMENT)) {
						certFile = args[i].substring(OUT_ARGUMENT.length()).trim();
					} else {
						storeFile = args[i];
					}
				}				
			case 1:
				pdfFile = args[0];		
				break;
			
			default:
				System.err.println("Too many parameters!");
				System.exit(ARGUMENTS_ERROR);
			}
			
			checker = new SignatureInfo(pdfFile, storeFile);
			
			List<String> names = checker.getSignatureNames();
			for (String name : names) {
				DocumentRevision rev = checker.getRevision(name);
				int modified = rev.isDocumentModified() ? 1 : 0;
				int doesntCoverWhole = rev.signatureCoversWholeDocument() ? 0 : 1;
				int verifyFail = rev.verify(certFile) == null ? 0 : 1;
				returnValue = verifyFail << 2 | modified  << 1 | doesntCoverWhole;
				if (returnValue != 0) {
					break;
				}
			}
			
			
				
		} catch (Exception ex) { //TODO: napraviti catch za svaki exception posebno
			System.err.println(ex.getLocalizedMessage());
			returnValue = EXCEPTION_THROWN; //TODO: dodijeliti svakom exceptionu svoj return value
		} finally {
			System.exit(returnValue);
		}

	}
	
	public static void interactive() throws IOException, SignatureException, 
						            CertificateException, KeyStoreException, 
						            NoSuchAlgorithmException {
		Scanner sc = new Scanner(System.in);
		System.out.print("PDF filename: ");
		String pdfFile = sc.nextLine();
		System.out.print("Self signed cert (blank for global CA store): ");
		String ssCertFile = sc.nextLine();

	    if (ssCertFile.equals("")) {
	    	System.out.println("Using global Key Store...");
	    	checker = new SignatureInfo(pdfFile);
	    }
	    else {
	    	System.out.println("Using your certificate...");
	    	checker = new SignatureInfo(pdfFile, ssCertFile);
	    }
	    System.out.println("Found revisions:");
		
	    List<String> signatureNames = checker.getSignatureNames();
	    
		for (String s : signatureNames) {
			System.out.println(s);
		}
		
		System.out.println();
		System.out.println("Choose signature name (blank for all): ");
		
		String sigName = sc.nextLine();
		DocumentRevision chosenRev;
		if (sigName.equals("")) {				
			System.out.println("Checking all revisions");
			for (String name : signatureNames) {
				printAndVerify(checker.getRevision(name));
				
			}				
		} else {
			chosenRev = checker.getRevision(sigName);
			printAndVerify(chosenRev);
		}
			
		
	}
	
	public static void printAndVerify(DocumentRevision rev) throws SignatureException {
		if (rev == null) {
			System.out.println("No such signature name.");
			return;
		}
		System.out.println();
		System.out.println("**** " + rev.getSignatureName() + " ****");
		System.out.println("Subject: " + rev.getSubject());
		System.out.println("Revision " + rev.getRevisionNumber()
				+ " of " + checker.getTotalRevisions());
		System.out.println("Signature"  
				+ (rev.signatureCoversWholeDocument()
						? " covers " : " DOES NOT cover ")
				+ "whole document.");
		System.out.println("Document was " 
				+ (rev.isDocumentModified()
				        ? "modified" : "not modified"));	
		System.out.println("Checking validity...");
		
		Object fail = rev.verify();
		if (fail == null) {
			System.out.println("The signature is VALID");
		} else {
			System.out.println(fail);
		}
		
	}

}
