package main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;

public class Cliente {

	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	public static final int PUERTO = 3400;
	
	public static final String SERVIDOR = "localhost";

	public static final String HOLA = "HOLA";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String OK = "OK";
	public static final String ERROR = "ERROR";

	public static final String llave_publica="K_C";

	private String llave_privada="K_C";

	private Socket canal;

	/**
	 * Flujo que envía los datos al servidor a través del socketServidor.
	 */
	private PrintWriter outWriter;

	/**
	 * Flujo de donde se leen los datos que llegan del servidor a través del socketServidor.
	 */
	private BufferedReader inReader;

	/**
	 * Estado del jugador.
	 */
	private String estado;

	private boolean finEncuentro;


	public Cliente( )
	{
		estado = HOLA;
		finEncuentro = false;
	}


	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClassNotFoundException {

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector =null;

		System.out.println("Cliente...");

		try {
			socket = new Socket(SERVIDOR,PUERTO);

			escritor =  new PrintWriter(socket.getOutputStream(),true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));


		}catch(IOException e)
		{
			e.printStackTrace();
			System.exit(-1);
		}

		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in)); 

		ProtocoloCliente.procesar(stdIn,lector,escritor);

		
		
		stdIn.close();
		escritor.close();
		lector.close();
		socket.close();

	}


}



