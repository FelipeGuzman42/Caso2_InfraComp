package main;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;


public class ProtocoloCliente {


	private static String identificacion;
	private static String localizacion;
	private static final String AES = "AES";
	private static final String BLOWFISH = "Blowfish";
	private static final String RSA = "RSA";
	private static final String HMACSHA1 = "HMACSHA1";
	private static final String HMACSHA256 = "HMACSHA256";
	private static final String HMACSHA384 = "HMACSHA384";
	private static final String HMACSHA512 = "HMACSHA512";
	private static KeyPair keyPair;
	private static PublicKey llavePublicaServ;
	private final static String PADDING = "AES/ECB/PKCS5Padding/xor";


	public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClassNotFoundException {

		//Lee del teclado
		System.out.println("Escriba el mensaje para enviar: ");
		String fromUser = stdIn.readLine();

		//Env�a por la red
		pOut.println(fromUser);

		String fromServer="";

		//Lee lo que llega por la red
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor:" + fromServer);
		}	


		System.out.println("Ingrese identificacion:");
		identificacion = stdIn.readLine();
		System.out.println("Ingrese localizacion:");
		localizacion = stdIn.readLine();

		System.out.println("Seleccione que algoritmo dese usar \n Para Cifrado Simetrico \n 1) AES \n 2) BlOWFISH");

		String respuestaFinal = "ALGORITMOS:";


		int algSim = Integer.parseInt(stdIn.readLine());
		if(algSim == 1)
		{
			respuestaFinal = respuestaFinal+ AES+":"+RSA+":";
		}else
		{
			respuestaFinal = respuestaFinal+ BLOWFISH+":"+RSA+":";
		}

		System.out.println("Seleccione que algoritmo dese usar \n Para Cifrado HMAC \n 1) HmacSHA1 \n 2) HmacSHA256 \n 3) HmacSHA384 \n 4) HmacSHA512");

		int algHmac = Integer.parseInt(stdIn.readLine());
		if(algHmac == 1)
		{
			respuestaFinal = respuestaFinal+ HMACSHA1;
		}else if(algHmac == 2)
		{
			respuestaFinal = respuestaFinal+ HMACSHA256;
		}else if(algHmac == 3 )
		{
			respuestaFinal = respuestaFinal+ HMACSHA384;

		}else if(algHmac == 4)
		{
			respuestaFinal = respuestaFinal+ HMACSHA512;

		}

		//Recordar borrarlo
		System.out.println("Se enviaron los algoritmos: "+respuestaFinal);
		//Envia Algortimos que se van a usar
		pOut.println(respuestaFinal);

		//Lee lo que llega por la red dice si hubo un error o no en la entrada con algotimos
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor:" + fromServer);
		}


		//Generar certificado
		generarLlave(RSA);//Generar llaves
		java.security.cert.X509Certificate certificado = gc(keyPair);
		byte[] certificadoEnBytes = certificado.getEncoded( );
		String certificadoEnString = Base64.toBase64String(certificadoEnBytes);//Parse del certificado a String

		//Reccodar borrarlo
		System.out.println("Se envi�: "+certificadoEnString);

		//Envia Cerificado que se van a usar
		pOut.println(certificadoEnString);

		//Lee lo que llega por la red, se recibio o no el certificado
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor:" + fromServer);
		}


		//Lee lo que llega por la red, corresponde al certificado
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor:" + fromServer);
		}

		byte[] certificadoServ =  Base64.decode(fromServer);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		InputStream iS =  new ByteArrayInputStream(certificadoServ);
		certificado = (X509Certificate)cf.generateCertificate(iS);
		llavePublicaServ = certificado.getPublicKey();

		if(llavePublicaServ != null)
		{
			//Recordar Borrar
			System.out.println("Se envi�: OK");
			//Envian respuesta al servidor 
			pOut.println("OK");

		}else {
			//Recordar Borrar
			System.out.println("Se envi�: ERROR");
			//Envian respuesta al servidor 
			pOut.println("ERROR");
		}


		//Lee lo que llega por la red
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor C(K_C+,K_SC):" + fromServer);
		}

		byte[] descifrado = descifrarAsimetrico((Key)keyPair.getPrivate(), RSA, Base64.decode(fromServer));
		SecretKey sK = new SecretKeySpec(descifrado, RSA);		

		//Lee lo que llega por la red
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor C(K_SC,<reto>):" + fromServer);
		}

		System.out.println(fromServer);

		byte[] descifradoConSecretKey = descifrarSimetrico(sK, Base64.decode(fromServer));

		String texto = Base64.toBase64String(descifradoConSecretKey);
		byte[] cifradoParaServidor = cifrarAsimetrico((Key)llavePublicaServ,RSA,texto);

		pOut.println(Base64.toBase64String(cifradoParaServidor));

		//Lee lo que llega por la red
		if((fromServer=pIn.readLine())!= null)
		{
			System.out.println("Respuesta del Servidor:" + fromServer);
		}
	}


	public static byte[] cifrarAsimetrico(Key llave, String algoritmo, String texto) {

		byte[] textoCifrado;

		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			byte[] textoClaro = texto.getBytes();

			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoClaro);

			return textoCifrado;
		}catch (Exception e){
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrarSimetrico(SecretKey llave, byte[] texto)
	{
		byte[] textoClaro;

		try {
			Cipher cifrador = Cipher.getInstance(PADDING);
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		}catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;	
		}

		return textoClaro;
	}

	public static byte[] descifrarAsimetrico(Key llave, String algoritmo, byte[] texto) {

		byte[] textoClaro;

		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);	
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		}catch (Exception e){
			System.out.println("Exception: " + e.getMessage());
			return null;
		}

		return textoClaro;
	}

	public static void generarLlave(String algoritm) throws NoSuchAlgorithmException
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritm);
		generator.initialize(1024);
		keyPair =  generator.generateKeyPair();

	}

	public static X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException
	{
		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(Calendar.YEAR, 10);

		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
				new X500Name("CN=localhost"),
				BigInteger.valueOf(1),
				Calendar.getInstance().getTime(),
				endCalendar.getTime(),
				new X500Name("CN=localhost"),
				SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());

		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
		X509Certificate crt = (X509Certificate)(new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).getCertificate(x509CertificateHolder));
		return crt;
	}


}
