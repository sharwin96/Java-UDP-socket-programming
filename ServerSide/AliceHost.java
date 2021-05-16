

import java.lang.Math; 
import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
//import java.util.Base64;
import java.util.Random; 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
//import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Collections;


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



public class AliceHost{
        
        private Scanner x;
        private String dhP,dhG,encryptPassword;
        private long publicKey;
        private static final String ENCRYPTION_ALGORITHM = "ARCFOUR"; // or "RC4"
        
        public String getP()
        {
            return dhP;
        }
        
        public String getG()
        {
            return dhG;
        }
        
        public String encryptPassword()
        {
            return encryptPassword;
        }
        
        public long getPublicKey()
        {
            return publicKey;
        }
        
        public void openFile(){
            
            try{
                String workingDir = System.getProperty("user.dir");
                x = new Scanner(new File (workingDir +"\\dhParamaters.txt"));
            }catch (Exception e){
                System.out.println("File does not exist");
            }
            
        }
        
        
        public void readFile(){
            
            while(x.hasNext()){
                dhP = x.next();
                dhG = x.next();
                encryptPassword = x.next();
                
            }
        }
        
        public void closeFile(){
            x.close();
        }
        
        public void sendPacket(DatagramSocket socket,DatagramPacket receive,String strSend) throws IOException{
            byte[] buff = new byte[1024];
            InetAddress inetAdr = InetAddress.getByName("127.0.01");
            //String strSend = null;
            //strSend = input;
            buff = strSend.getBytes();
            DatagramPacket send = new DatagramPacket(buff,buff.length,inetAdr,receive.getPort()); // encapsulate the public key in a datapacker
            socket.send(send);
        }
    
    
	public static void main(String[] args) throws Exception
	{
		DatagramSocket ds=new DatagramSocket(2334);
                DatagramPacket dpreceive;
                DatagramPacket dpSend ; 
                InetAddress inetAdr = InetAddress.getByName("127.0.0.1");
		byte[] buff=new byte[1024];
                AliceHost host = new AliceHost();
                String prime,generator,hashPwd;
                long gValue;
                long pValue;
                int randA = 0;
                BigInteger randomA ; // private key of the host
                long publicKeyA; // public key of the host
		
                //read the txt file
                System.out.println("Loading...");
                host.openFile();
                host.readFile();
                host.closeFile();
                
                System.out.println("Reading Parameters ...");
                prime = host.getP();
                generator = host.getG();
                hashPwd = host.encryptPassword();
                System.out.println("prime is " + prime );
                System.out.println("generator is " + generator );
                //System.out.println("hash password is " + hashPwd);
                BigInteger generator_val = new BigInteger(generator);
                BigInteger prime_val = new BigInteger(prime);
                
                //this is Xa (random a)
                randA = ((int) (Math.random()*(10 - 2))) + 2;
                randomA = BigInteger.valueOf(randA);
                
                
                System.out.println("Alice(Host) is ONLINE");
                System.out.println("----------------------");
                System.out.println();
                
                
		//while(true){
			dpreceive=new DatagramPacket(buff,buff.length);
			ds.receive(dpreceive);
			String str=new String(dpreceive.getData(),0,dpreceive.getLength());
			System.out.println("Client Messaged--> "+str);
			//if(str.equals("bye"))
			//{
			//	System.out.println("Server Is Exiting .... BYE");
                        //        ds.close();
			//	break;
			//}
                        if (str.equals("Bob"))
                        {
                            // Calculate the public and private keys 
                            // Converting the p and g values from String to BigInteger 
                            
                            System.out.println("Prime : " + prime_val);
                            System.out.println("Generator : " + generator_val);
                            
                            
                            System.out.println("Random A : " + randomA);
                            
                            //compute g power a
                            BigInteger g_power_a = generator_val.pow(randA);
                            System.out.println("g^a : " + g_power_a);
                            
                            // compute gA mod p
                            BigInteger gA_mod_p = generator_val.modPow(randomA,prime_val);
                            System.out.println("gA mod p(Ya) : " + gA_mod_p);
                            
                            //string containing the H(PW),prime number , generator, gA mod P(public key) (PLAINTEXT)
                            String sendStr = host.encryptPassword()+" "+ host.getP()+" "+ host.getG()+" "+ gA_mod_p + " ";
                            
                            //encrypting sendStr...
                            RC4 rc4 = new RC4();
                            String key = "akey";
                            String cipher = rc4.Encrypt(sendStr,key);
                            //rc4_to_plain.generate_chiper(sendStr);
                            
                            System.out.println("Encrypted -->> " + cipher);
                            
                            host.sendPacket(ds,dpreceive,cipher);
                        }
                        
                        buff=new byte[1024];
                        
                        dpreceive =new DatagramPacket(buff,buff.length);
                        ds.receive(dpreceive);
                        String str1=new String(dpreceive.getData(),0,dpreceive.getLength());

                        System.out.println("Client Messaged--> "+str1);

                        RC4 rc4 = new RC4();
                        String key1 = host.encryptPassword();
                        String cipher1 = rc4.Encrypt(str1,key1);
                        System.out.println("Decrypted --->> " + cipher1);

                        String[]cipherArray = cipher1.split("\\s+");
                        BigInteger publicKeyBob = new BigInteger(cipherArray[1]);

                        //compute the shared key
                        BigInteger sharedKeyA = publicKeyBob.modPow(randomA, prime_val);
                        String sharedKeyA_str = sharedKeyA.toString();
                        HashPassword hp = new HashPassword();
                        String sharedKeyAlice = hp.encryptThisString(sharedKeyA_str);

                        System.out.println("Shared Key : " + sharedKeyAlice);
                        
                        //Generate nonce Na
                        int nonceA =  ((int) (Math.random()*(150 - 50))) + 50;
                        System.out.println("Na ---->> " + nonceA);
                        String nonceAndKey = nonceA + " " + sharedKeyAlice + " ";
                        
                        String cipher2 = rc4.Encrypt(nonceAndKey,key1);
                        //rc4_to_plain.generate_chiper(sendStr);

                        System.out.println("Encrypted -->> " + cipher2);
                        
                        host.sendPacket(ds,dpreceive,cipher2);
                        
                        //receive E(K,Na + 1,Nb)
                        buff=new byte[1024];
                        
                        dpreceive =new DatagramPacket(buff,buff.length);
                        ds.receive(dpreceive);
                        String str2=new String(dpreceive.getData(),0,dpreceive.getLength());

                        System.out.println("Client Messaged--> "+str2);
                        
                        //decrypt E(K,Na + 1,Nb)
                        String key2 = host.encryptPassword();
                        String cipher3 = rc4.Encrypt(str2,key2);
                        System.out.println("Decrypted --->> " + cipher3);
                        
                        String[] decryptedCipher3 = cipher3.split("\\s+");
                        int checkNonce = nonceA + 1;
                        int nonceAPlusOne = Integer.parseInt(decryptedCipher3[1]);
                        if (checkNonce == nonceAPlusOne)
                        {
                            int nonceB = Integer.parseInt(decryptedCipher3[2]);
                            int nonceBplusOne = nonceB + 1;
                            
                            String nonceBplusOne_str = nonceBplusOne + " ";
                            String cipher4 = rc4.Encrypt(nonceBplusOne_str,key1);
                            System.out.println("Nb ---->>> " + nonceB);
                            System.out.println("Nb + 1 ---->>> " + nonceBplusOne);
                            host.sendPacket(ds,dpreceive,cipher4);
                            
                            System.out.println("-----------------------------------");
                            System.out.println("-----------------------------------");
                        }
                        else{
                            System.out.println("Login Failed...");
                            ds.close();
                            //break;
                        }
                        
                        
                        while(true)
                        {
                            buff=new byte[1024];

                            DatagramPacket serverReceive =new DatagramPacket(buff,buff.length);
                            ds.receive(serverReceive);
                            String receive = new String(serverReceive.getData(),0,serverReceive.getLength());
                            if (receive.equals("exit")){
                                    System.out.println("Client has left...");
                                    ds.close();
                                    break;
                            }

                            //decrypt the received string 
                            String decryptReceivedStr = rc4.Encrypt(receive,sharedKeyAlice);
                            String[] decryptReceivedStrArr = new String[3];
                            decryptReceivedStrArr = decryptReceivedStr.split("\\~+");

//                            for (int i = 0 ; i < decryptReceivedStrArr.length; i++)
//                            {
//                                System.out.print("index "+ i + ": " +decryptReceivedStrArr[i] + " ");
//                            }
                            System.out.println("");
                            
                            //Obtain M(Hash)
                            String M_Hash = decryptReceivedStrArr[1] + decryptReceivedStrArr[2];
                            System.out.println("M_Hash >> " + M_Hash);

                            String message = decryptReceivedStrArr[1];
                            //System.out.println("Message --->> " + message);

                            String hash = decryptReceivedStrArr[2];
                            System.out.println("Hash >> " + hash );

                            //compute hash' = (K||M||K)
                            //HashPassword hp = new HashPassword();
                            String hashPrime = hp.encryptThisString(sharedKeyAlice + "~" + decryptReceivedStrArr[1] + "~" + sharedKeyAlice) ;
                            System.out.println("HashPrime >> " + hashPrime);

                            if(hash.equals(hashPrime))
                            {
                                System.out.println("*******************************************************");
                                System.out.println("Client Messaged--> "+message);
                                System.out.println("*******************************************************");
                            }


                            // to send to the client
                            //create a packet to send message
                            byte[] bOne = new byte[1024];
                            System.out.println("Enter your message : ");
                            Scanner input = new Scanner(System.in);
                            String sendMessage = input.nextLine();
                            if (sendMessage.equals("exit")){
                                    System.out.println("Server Is Exiting .... BYE");
                                    ds.close();
                                    break;
                            }

                            //compute hash = (K||M||K)
                            //HashPassword hp = new HashPassword();
                            String hashed = hp.encryptThisString(sharedKeyAlice +"~"+ sendMessage +"~"+ sharedKeyAlice);
                            //System.out.println("Hash --->> " + hash);

                            //compute C = E(K,M||Hash)
                            String chatMessageAndHash = sendMessage+"~"+ hashed;
                            String keyMessageHash = sharedKeyAlice + "~" + chatMessageAndHash + "~";
                            //System.out.println("(K,M||Hash) -->> " + keyMessageHash);

                            String encryptKeyMsgHash = rc4.Encrypt(keyMessageHash,sharedKeyAlice);
                            //System.out.println("E(K,M||Hash) --->> " + encryptKeyMsgHash);


                            bOne = encryptKeyMsgHash.getBytes();
                            //InetAddress inetAdr = InetAddress.getLocalHost();
                            DatagramPacket serverSend = new DatagramPacket(bOne,bOne.length,inetAdr,dpreceive.getPort());
                            ds.send(serverSend);
                        }  
              
	}
}
