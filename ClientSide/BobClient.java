
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
//import org.apache.commons.codec.binary.Base64;
//import org.bouncycastle.util.encoders.Hex;
import java.util.ArrayList;
import java.util.Collections;


import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.util.Random;

class HashPassword {
    
    public static String encryptThisString(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  
            // return the HashText 
            return hashtext; 
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
    
   
}


class RC4 {
    public static String Encrypt(String plainText,String key){
        String cipher="";
        ArrayList<Character> keys = generateKeys(key);
        int i=0;
        for(char c:plainText.toCharArray()){
            cipher+=(char)(keys.get(i%keys.size())^c);
        }
        return cipher;
    }
    private static ArrayList<Character> generateKeys(String key){
        ArrayList<Character> s=new ArrayList<>(256);
        ArrayList<Character> keys=new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            s.add(i,(char)i) ;
            keys.add(i,key.charAt(i%key.length()));
        }
        int    j = 0; 
        for (int i = 0;i<256;++i){ 
            j = (j + s.get(i) + keys.get(i))% 256; 
            Collections.swap(s,i,j); 
        } 
    
        int i=0,index;
        j = 0;
        for (int k = 0; k < 256; k++) {
            i = (i + 1)% 256; 
            j = (j + s.get(i))% 256; 
            Collections.swap(s,i,j); 
            index = (s.get(i) + s.get(j))% 256; 
            keys.set(i,s.get(index));
        } 
        return keys;
    }
}



class BobClient{
    private static final String ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"
	public static void main(String[] args) throws Exception
	{
		
		DatagramSocket ds=new DatagramSocket();
                DatagramPacket dp;
                DatagramPacket dpreceive;
                String commonPwd = "six666";
                String enteredPW = null;
		byte[] buff=new byte[1024];
		Scanner scan=new Scanner(System.in);
                
                System.out.println("Bob(Client) is ONLINE");
                System.out.println("----------------------");
                
                boolean ok = true;
                
                while(ok == true)
                {
                    System.out.println("Enter password : ");
                    enteredPW = scan.nextLine();
                    if(enteredPW.equals(commonPwd)){
                        ok = false;
                    }
                }
                
                String authenthicate = "Bob";
                InetAddress ip=InetAddress.getByName("127.0.01");
                dp =new DatagramPacket(authenthicate.getBytes(),authenthicate.length(),ip,2334);
                ds.send(dp);
                
                //Bob(Client) receives E(H(PW), p, g, ga mod p) from Alice(Host) and organise the data into an array
                dpreceive = new DatagramPacket(buff,buff.length);
                ds.receive(dpreceive);
                
                
		String str1 = new String(dpreceive.getData());
                System.out.println("Server Messaged--> "+ str1);
                
                
                RC4 rc4 = new RC4();
                String key = "akey";
                String decrypt = rc4.Encrypt(str1,key);
                
                
                System.out.println("Decrypted --->> " + decrypt);
                
                String[] decryptStr = decrypt.split("\\s+");
                String hashPw = decryptStr[0];
                
                BigInteger prime = new BigInteger(decryptStr[1]);
                BigInteger generator = new BigInteger(decryptStr[2]);
                BigInteger gA_mod_p = new BigInteger(decryptStr[3]);
                
                
                //computing Bob's E(H(PW), gb mod p) values...
                System.out.println("H(PW) ---> " + hashPw);
                System.out.println("Prime ---> " + prime);
                System.out.println("Generator ---> " + generator);
                System.out.println("gA mod p(Ya) ---> " + gA_mod_p);
                
                //this is Xb (random b)
                int randB = ((int) (Math.random()*(10 - 1))) + 1;
                BigInteger randomB = BigInteger.valueOf(randB);
                System.out.println("Random B : " + randomB);

                
                //compute g power b 
                BigInteger g_power_b = generator.pow(randB);
                System.out.println("g^b : " + g_power_b);

                
                // compute Yb = gB mod p 
                BigInteger gB_mod_p = generator.modPow(randomB,prime);
                System.out.println("gB mod p(Yb) : " + gB_mod_p);
                
                
                //str to send to Host containing H(PW), gB mod p(Yb)
                String strToHost = hashPw +  " " + gB_mod_p;
                System.out.println("HashPW and Gb mod P ---->> " + strToHost);
                
                
                
                //encrypt strToHost
                String cipher = rc4.Encrypt(strToHost,hashPw);
                System.out.println( "Cipher --->> " + cipher );
                
                
                //send the encrypted text to Host
                buff = new byte[1024];
                InetAddress inetAdr = InetAddress.getByName("127.0.0.1");
                
                buff = cipher.getBytes();
                DatagramPacket send = new DatagramPacket(buff,buff.length,inetAdr,dpreceive.getPort()); // encapsulate the public key in a datapacker
                ds.send(send);
                
                
                //compute the shared key...(K = Ya^Xb mod p)
                // Ya^Xb...Ya = gA_mod_p 
                BigInteger sharedKeyB = gA_mod_p.modPow(randomB, prime);
                String sharedKeyB_str = sharedKeyB.toString();
                HashPassword hp = new HashPassword();
                String sharedKeyBob = hp.encryptThisString(sharedKeyB_str);
                System.out.println("Shared Key : " + sharedKeyBob);
                
                //receive the E(K,Na) from ALice
                buff=new byte[1024];
                dpreceive = new DatagramPacket(buff,buff.length);
                ds.receive(dpreceive);
                
		String str2 = new String(dpreceive.getData());
                System.out.println("Server Messaged--> "+ str2);
                
                //decrypt to get Na
                String alice_KandNa = rc4.Encrypt(str2,hashPw);
                System.out.println("K and Na (Alice) : " + alice_KandNa);
                String[] arrKandNa_Alice = alice_KandNa.split("\\s+");
                
                int Na_alice = Integer.parseInt(arrKandNa_Alice[0]);
                int Na_bob = Na_alice + 1 ;
                int nonceB =  ((int) (Math.random()*(200 - 151))) + 151;
                System.out.println("Nb --->> " + nonceB);
                System.out.println("Na + 1 ---->> " + Na_bob);
                System.out.println("Na ------->> " + Na_alice);
                
                //String contains e(K,Na+1,Nb)
                String containNb = arrKandNa_Alice[1]+" "+ Na_bob +" "+ nonceB ;
                System.out.println("E(K,Na + 1,Nb) : " + containNb);
                
                //encrypt E(K,Na + 1,Nb)
                String cipher1 = rc4.Encrypt(containNb,hashPw);
                System.out.println( "Cipher --->> " + cipher1 );
                
                //receive E(K,Na + 1,Nb)
                buff = new byte[1024];
                buff = cipher1.getBytes();
                send = new DatagramPacket(buff,buff.length,inetAdr,dpreceive.getPort()); // encapsulate the public key in a datapacker
                ds.send(send);
                
                //receive Nb + 1
                buff=new byte[1024];
                dpreceive = new DatagramPacket(buff,buff.length);
                ds.receive(dpreceive);
                
                String str3 = new String(dpreceive.getData());
                System.out.println("Server Messaged--> "+ str3);
                
                String decrypt_str3 = rc4.Encrypt(str3,hashPw);
                
                String[] nonceBPlus = decrypt_str3.split("\\s+");
                int nonceBplusOne = Integer.parseInt(nonceBPlus[0]);
                System.out.println("Nb + 1 --->> " + nonceBplusOne);
                
                System.out.println("-----------------------------------");
                System.out.println("-----------------------------------");
 
                while(true)
                {
                    if(nonceBplusOne != (nonceB + 1))
                    {
                        System.out.println("CONNECTION TERMINATED...");
                        ds.close();
                        break;
                    }
                    
                    
                    byte[] bOne = new byte[1024];
                    System.out.println("Enter your message : ");
                    String sendMessage = scan.nextLine();
                    if (sendMessage.equals("exit"))
                    {
                        System.out.println("Client has left...");
                        ds.close();
                        break;
                    }
              
                    //compute hash = (K||M||K)
                    //HashPassword hp = new HashPassword();
                    String hashed = hp.encryptThisString(sharedKeyBob +"~"+ sendMessage +"~"+ sharedKeyBob);
                    //System.out.println("Hash --->> " + hashed);

                    //compute C = E(K,M||Hash)
                    String chatMessageAndHash = sendMessage+"~"+ hashed;
                    String keyMessageHash = sharedKeyBob + "~" + chatMessageAndHash + "~";
                    //System.out.println("(K,M||Hash) -->> " + keyMessageHash);

                    String encryptKeyMsgHash = rc4.Encrypt(keyMessageHash,sharedKeyBob);
                    //System.out.println("E(K,M||Hash) --->> " + encryptKeyMsgHash);


                    bOne = encryptKeyMsgHash.getBytes();
                    //InetAddress inetAdr = InetAddress.getLocalHost();
                    DatagramPacket serverSend = new DatagramPacket(bOne,bOne.length,inetAdr,dpreceive.getPort());
                    ds.send(serverSend);

                   
                    
                    
                    buff=new byte[1024];
                    
                    DatagramPacket clientReceive=new DatagramPacket(buff,buff.length);
                    ds.receive(clientReceive);
                    str1=new String(clientReceive.getData());
                    
                    //decrypt the received string 
                    String decryptReceivedStr = rc4.Encrypt(str1,sharedKeyBob);
                    String[] decryptReceivedStrArr = new String[3];
                    decryptReceivedStrArr = decryptReceivedStr.split("\\~+");
                    
//                    for (int i = 0 ; i < decryptReceivedStrArr.length; i++)
//                    {
//                        System.out.print("index "+ i + ": " + decryptReceivedStrArr[i] + " ");
//                    }
                    System.out.println("");
                    
                    //Obtain M(Hash)
                    String M_Hash = decryptReceivedStrArr[1] + decryptReceivedStrArr[2];
                    System.out.println("M_Hash >> " + M_Hash);
                    
                    String message = decryptReceivedStrArr[1];
                    //System.out.println("Message >> " + message);
                    
                    String hash = decryptReceivedStrArr[2];
                    System.out.println("Hash >> " + hash );
                    
                    //compute hash' = (K||M||K)
                    //HashPassword hp = new HashPassword();
                    String hashPrime = hp.encryptThisString(sharedKeyBob + "~" + decryptReceivedStrArr[1] + "~" + sharedKeyBob) ;
                    System.out.println("HashPrime >> " + hashPrime);
                    
                    if(hash.equals(hashPrime))
                    {
                        System.out.println("*******************************************************");
                        System.out.println("Server Messaged--> "+message);
                        System.out.println("*******************************************************");
                        if(message.equals("exit"))
                        {
                            System.out.println("Host has left...");
                            ds.close();
                            break;
                        }
                    }
                    
                    //System.out.println("Server Messaged--> "+str1);
                    //if(message.equals("bye"))
                    //{
                    //    ds.close();
                    //    break;
                    //}       
                    
                }
                
        }
}