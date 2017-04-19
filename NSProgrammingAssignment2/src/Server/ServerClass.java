package Server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import AuthenticationConstants.ACs;	// Authentication Constants

public class ServerClass {
	
	private static boolean sendMsg(PrintWriter out,String msg){
		out.println(msg);
		out.flush();
		return true;
	}
	
	private static boolean terminateConnection(PrintWriter out){
		out.println(ACs.TERMINATEMSG);
		return false;
	}
	
	private static boolean authenticateClient(String encryptedID, String clientPBKey, Cipher rsaCipher) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		//TODO: apply public key on sncryptedID and compare to expected value
//		if(encryptedID.equals(ACs.CLIENTID)){
//			return true;
//		}
		
		byte[] clientPBKeyBytes = DatatypeConverter.parseBase64Binary(clientPBKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clientPBKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		byte[] encryptedIDBytes = DatatypeConverter.parseBase64Binary(encryptedID);
		rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
		if(rsaCipher.doFinal(encryptedIDBytes).equals(ACs.CLIENTID.getBytes()) ){
			return true;
		}
		
		return false;
	}
	
	private static boolean authenticationProtocol(BufferedReader in, PrintWriter out, Cipher rsaCipher, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		System.out.println("Starting authentication protocol");
		
		if(!(in.readLine()).equals(ACs.AUTHENTICATIONMSG )){
			System.out.println("Authenticaion message error!");
			return terminateConnection(out);
		}
		
	    rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
	    
		// TODO: encrypt server ID
		sendMsg(out,DatatypeConverter.printBase64Binary(rsaCipher.doFinal(ACs.SERVERID.getBytes("UTF-16"))));
		
		if(!(in.readLine().equals(ACs.REQUESTSIGNEDCERT ))){
			System.out.println("Request Signed Certificate Error!");
			return terminateConnection(out);
		}
		
		String serverCertPath = "D:\\Backup\\SUTD\\ISTD\\Computer Systems Engineering\\CSE-Programming-Assignments\\CSE Programming Assignment 2\\1001670.der";
		byte[] certBytes = Files.readAllBytes(new File(serverCertPath).toPath());
		
		// Prepping client to receive certificate in bytes
		out.println(Integer.toString(certBytes.length) );	
		out.flush();
		// Sending signed cert of server - includes public key of client
		out.println(certBytes);
		out.flush();
		
		// Reads in the clientsID encrypted with client's private key
		
		String encryptedClientID = in.readLine();	
		
		sendMsg(out,ACs.REQUESTCLIENTPUBLICKEY);
		
		String clientPublicKey = in.readLine();
		
		if(!authenticateClient(encryptedClientID, clientPublicKey, rsaCipher)){
			System.out.println("Client Authentication Error!");
			return terminateConnection(out);
		}
		
		sendMsg(out,ACs.SERVERREADYTORECEIVE);
		
		System.out.println("Completed authentication protocol");
		
		return true;
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		//String hostName = args[0];
		//int portNum = Integer.parseInt(args[1]);
		
		int portNum = 7777;	// socket address
		ServerSocket serverSocket;
		Socket clientSocket;		
		serverSocket = new ServerSocket(portNum);
		
		/*
		File serverPrivateKey = new File("/Users/G/openssl/privateServer.der");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(
																serverPrivateKey.toPath() ));
		*/
		
		Path keyPath = Paths.get("/Users/G/Documents/workspace/NSProgrammingAssignment2/src/Server/privateServer.der");
		byte[] privateKeyByteArray = Files.readAllBytes(keyPath);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
		
		
		System.out.println(keySpec);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		
		// Create encryption cipher
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		System.out.println("Accepting client connections now ...");
		clientSocket = serverSocket.accept();
		System.out.println("Client connection established!");
		// in will receive input as byte[]
		BufferedReader in = new BufferedReader(
								new InputStreamReader(
										new DataInputStream(clientSocket.getInputStream())));
		PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
		
		boolean proceed = authenticationProtocol(in,out,rsaCipher, privateKey);
		
		if(!proceed){
			System.out.println("Authentication protocol failed!");
		}
		
		System.out.println("Waiing for encrypted file from client");
		
		serverSocket.close();
		
		
		
		
	}
}

class OpenConnections implements Runnable{

	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}
	
}
