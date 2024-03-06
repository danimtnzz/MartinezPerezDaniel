package dam.psp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Servidor {

	static KeyStore ks;

	public static void main(String[] args) throws IOException {
		ExecutorService executorService = Executors.newFixedThreadPool(100);
		try (ServerSocket sSocket = new ServerSocket(9000)) {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(Servidor.class.getResourceAsStream("/keystore.p12"), "practicas".toCharArray());
			System.out.println("Server listening on port 9000");
			while (true) {
				Socket cliente = sSocket.accept();
				System.out.println("cliente conectado: " + cliente.getInetAddress());
				cliente.setSoTimeout(5000);
				executorService.execute(() -> {
					try {
						manejarPeticion(cliente);
					} catch (Exception e) {
						e.printStackTrace();
					}
				});
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} finally {
			executorService.shutdown();
		}
	}

	// funcion utilizada en los métodos para enviar al cliente los errores
	private static void enviarWriteUTF(Socket cliente, String solicitud) {
		try {
			new DataOutputStream(cliente.getOutputStream()).writeUTF(solicitud);
		} catch (SocketTimeoutException e) {
			try {
				new DataOutputStream(cliente.getOutputStream()).writeUTF("ERROR:Read timed out");
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void manejarPeticion(Socket cliente) throws IOException {
		DataInputStream in = new DataInputStream(cliente.getInputStream());
		try {
			String solicitud = in.readUTF();
			if (solicitud != null && solicitud.startsWith("hash")) {
				manejarHash(in, cliente);
			} else if (solicitud != null && solicitud.startsWith("cert")) {
				manejarCert(in, cliente);
			} else if (solicitud != null && solicitud.startsWith("cifrar")) {
				manejarCifrar(in, cliente);
			} else {
				enviarWriteUTF(cliente, "ERROR:'" + solicitud + "' no se reconoce como una petición válida");
			}
		} catch (SocketTimeoutException e) {
			enviarWriteUTF(cliente, "ERROR:Read timed out");
		} catch (EOFException e) {
			enviarWriteUTF(cliente, "ERROR:Se esperaba una petición");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void manejarHash(DataInputStream in, Socket cliente) {
		try {
			MessageDigest md;
			String algoritmo = in.readUTF();
			md = MessageDigest.getInstance(algoritmo);
			byte[] bytes = in.readAllBytes();
			if (bytes.length > 0) {
				String cadena = Base64.getEncoder().encodeToString(md.digest(bytes));
				enviarWriteUTF(cliente, "OK:" + cadena);
			} else
				enviarWriteUTF(cliente, "ERROR:Se esperaban datos");
		} catch (SocketTimeoutException e) {
			enviarWriteUTF(cliente, "ERROR:Read timed out");
		} catch (EOFException e) {
			enviarWriteUTF(cliente, "ERROR:Se esperaba un algoritmo");
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	private static void manejarCert(DataInputStream in, Socket cliente) {
		try {
			String respuestaEncriptadaBase64 = in.readUTF();
			byte[] respuestaEncriptadaBytes = Base64.getDecoder().decode(respuestaEncriptadaBase64);
			String respuestaDecodificada = new String(respuestaEncriptadaBytes, StandardCharsets.UTF_8);
			if (!respuestaDecodificada.startsWith("OK:")) {
				enviarWriteUTF(cliente, "ERROR:Respuesta mal formada");
				return;
			}
			String hashBase64 = respuestaDecodificada.substring(3);
			String solicitud = in.readUTF();
			if (!solicitud.startsWith("cert:")) {
				enviarWriteUTF(cliente, "ERROR:Solicitud mal formada");
				return;
			}
			String[] partes = solicitud.split(":");
			String alias = partes[1];
			String certificadoBase64 = partes[2];
			if (alias == null || alias.isEmpty()) {
				enviarWriteUTF(cliente, "ERROR:Se esperaba un alias");
				return;
			}
			if (certificadoBase64 == null || certificadoBase64.isEmpty()) {
				enviarWriteUTF(cliente, "ERROR:Se esperaba un certificado");
				return;
			}
			try {
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				byte[] certificadoBytes = Base64.getDecoder().decode(certificadoBase64);
				Certificate cert = f.generateCertificate(new ByteArrayInputStream(certificadoBytes));

				Servidor.ks.setCertificateEntry(alias, cert);

				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(certificadoBase64.getBytes());
				String hashCalculado = Base64.getEncoder().encodeToString(md.digest());

				if (hashCalculado.equals(hashBase64)) {
					enviarWriteUTF(cliente, "OK");
				} else {
					enviarWriteUTF(cliente, "ERROR:Hash no coincide");
				}
			} catch (CertificateException e) {
				enviarWriteUTF(cliente, "ERROR:Se esperaba Base64");
			} catch (KeyStoreException | NoSuchAlgorithmException e) {
				enviarWriteUTF(cliente, "ERROR:Error en el KeyStore o algoritmo no encontrado");
			}
		} catch (IOException e) {
			enviarWriteUTF(cliente, "ERROR:Error de entrada/salida");
		}
	}

	private static void manejarCifrar(DataInputStream in, Socket cliente) {
		String alias = "";
		try {
			alias = in.readUTF();
			Certificate cert = Servidor.ks.getCertificate(alias);
			if (cert == null)
				enviarWriteUTF(cliente, "ERROR:'" + alias + "' no es un certificado");
			else {
				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
				int n;
				byte[] bloque = new byte[256];
				DataOutputStream out = new DataOutputStream(cliente.getOutputStream());
				int contador = 0;
				while ((n = in.read(bloque)) != -1) {
					contador++;
					byte[] cifrado = c.doFinal(bloque, 0, n);
					out.writeUTF("OK:" + Base64.getEncoder().encodeToString(cifrado));
				}
				if (contador == 0) {
					enviarWriteUTF(cliente, "ERROR:Se esperaban datos");
				}
			}
		} catch (SocketTimeoutException e) {
			enviarWriteUTF(cliente, "ERROR:Read timed out");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {
			enviarWriteUTF(cliente, "ERROR:Se esperaba un alias");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			enviarWriteUTF(cliente, "ERROR:'" + alias + "' no contiene una clave RSA");
		}

	}

}
