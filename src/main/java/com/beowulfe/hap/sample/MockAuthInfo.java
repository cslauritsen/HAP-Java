package com.beowulfe.hap.sample;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.beowulfe.hap.HomekitAuthInfo;
import com.beowulfe.hap.HomekitServer;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * This is a simple implementation that should never be used in actual production. The mac, salt, and privateKey
 * are being regenerated every time the application is started. The user store is also not persisted. This means pairing
 * needs to be re-done every time the app restarts.
 *
 * @author Andy Lintner
 */
public class MockAuthInfo implements HomekitAuthInfo, java.io.Serializable {
	
	private static final String PIN = "031-45-154";
	
	private final String mac;
	private final BigInteger salt;
	private final byte[] privateKey;
	private final ConcurrentMap<String, byte[]> userKeyMap = new ConcurrentHashMap<>();
	
	public MockAuthInfo() throws IOException, InvalidAlgorithmParameterException {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new FileReader("auth.mac"))) {
                for (String line = br.readLine(); line != null; line = br.readLine()) {
                    sb.append(line);
                }
                System.out.println("Loaded auth.mac");
            }
            catch (Exception e) {
                sb.setLength(0);
		sb.append(HomekitServer.generateMac());
            }
            mac = sb.toString();
            try (FileWriter fw = new FileWriter("auth.mac")) {
                fw.write(mac);
            }
            
            BigInteger tmpBigInt = null;
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("auth.salt"))) {
                tmpBigInt = (BigInteger) ois.readObject();
                System.out.println("Loaded auth.salt");
            }
            catch (Exception e) {
                tmpBigInt = HomekitServer.generateSalt();
            }
            salt = tmpBigInt;
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("auth.salt"))) {
                oos.writeObject(salt);
            }
            
            byte[] tmpKey = null;
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("auth.key"))) {
                tmpKey = (byte[]) ois.readObject();
                System.out.println("Loaded auth.key");
            }
            catch (Exception e) {
                tmpKey = HomekitServer.generateKey();
            }
            privateKey = tmpKey;
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("auth.key"))) {
                oos.writeObject(privateKey);
            }
            System.out.println("The PIN for pairing is "+PIN);
	}


	@Override
	public String getPin() {
		return PIN;
	}

	@Override
	public String getMac() {
		return mac;
	}

	@Override
	public BigInteger getSalt() {
		return salt;
	}

	@Override
	public byte[] getPrivateKey() {
		return privateKey;
	}

	@Override
	public void createUser(String username, byte[] publicKey) {
		userKeyMap.putIfAbsent(username, publicKey);
		System.out.println("Added pairing for "+username);
	}

	@Override
	public void removeUser(String username) {
		userKeyMap.remove(username);
		System.out.println("Removed pairing for "+username);
	}

	@Override
	public byte[] getUserPublicKey(String username) {
		return userKeyMap.get(username);
	}

}
