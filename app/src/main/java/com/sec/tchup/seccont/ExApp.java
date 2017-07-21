package com.sec.tchup.seccont;

import android.app.Application;

import java.io.*;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Created by Tom on 21/07/2017.
 */

public class ExApp extends Application {
    public class InitError extends Exception {}
    static final String LKfn = "LK";
    static final String Algo = "AES";
    static final int MN = 0x155a78ca;

    SecretKey LK;
    boolean IsInit = false;
    boolean IsAuth = false;

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            InputStream LKis = openFileInput(LKfn);
            ObjectInputStream LKois = new ObjectInputStream(LKis);
            if (LKois.readLong() == MN) IsInit = true;
        } catch (IOException e) {
        }
    }

    private void writeInt(int i, OutputStream os) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(i);
        os.write(b.array());
    }

    private void writeBuff(byte[] buff, OutputStream os) throws IOException {
        writeInt(buff.length, os);
        os.write(buff);
    }

    private int readInt(InputStream is) throws IOException {
        byte[] buff = new byte[4];
        is.read(buff);
        ByteBuffer b = ByteBuffer.wrap(buff);
        return b.getInt();
    }

    private byte[] readBuff(InputStream is) throws IOException {
        byte[] buff = new byte[readInt(is)];
        is.read(buff);
        return buff;
    }

    public void DoInit(short[] Code, short[] Puk) throws InitError {
        SecureRandom secRndm = new SecureRandom();
        try {
            //rempli le fichier d'init
            // - magic number
            // - le nombre d'essais (encodé par moi)
            // - clef FK
            // - encodé avec FK : - le nombre d'iterations LIT
            //                    - le sel LS
            // - encodé avec CK : - le magic number
            //                    - la clef LK
            // - encodé avec PK : - le magic number
            //                    - la clef LK

            SecretKey FK = buildLK(secRndm);
            OutputStream LKos = openFileOutput(LKfn, MODE_PRIVATE);
            writeInt(MN, LKos); //magic number
            writeInt(encodeNbEssais(3), LKos);
            writeBuff(FK.getEncoded(), LKos);  //clef du fichier

            byte[] LS = buildLS(secRndm);
            int LIT = buildLIT(secRndm);
            SecretKey CK = buildLK(Code, LS, LIT);
            LK = buildLK(secRndm);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            Cipher c = Cipher.getInstance(Algo);
            c.init(Cipher.ENCRYPT_MODE, FK);
            CipherOutputStream cos = new CipherOutputStream(os, c);
            writeInt(LIT, cos);
            writeBuff(LS, cos);
            cos.close();
            writeBuff(os.toByteArray(), LKos);

            os = new ByteArrayOutputStream();
            c.init(Cipher.ENCRYPT_MODE, CK);
            cos = new CipherOutputStream(os, c);
            writeInt(MN, cos); //magic number
            writeBuff(LK.getEncoded(), cos);  //clef LK
            cos.close();
            writeBuff(os.toByteArray(), LKos);

            CK = buildLK(Puk, LS, LIT);
            os = new ByteArrayOutputStream();
            c.init(Cipher.ENCRYPT_MODE, CK);
            cos = new CipherOutputStream(os, c);
            writeInt(MN, cos); //magic number
            writeBuff(LK.getEncoded(), cos);  //clef LK
            cos.close();
            writeBuff(os.toByteArray(), LKos);

            LKos.close();
            IsInit = true;
            IsAuth = true;
        }
        catch (Exception e) {
            throw new InitError();
        }
    }

    private int decodeNbEssais(int nbEssais) {
        switch (nbEssais) {
            case 17: return 3;
            case -12: return 2;
            case 59: return 1;
            default: return 0;
        }
    }

    private int encodeNbEssais(int nbEssais) {
        switch (nbEssais) {
            case 3: return 17;
            case 2: return -12;
            case 1: return 59;
            default: return -114;
        }
    }

    public boolean TryAuthAndReadLK(short[] Code) throws InitError {
        Cipher c;
        ByteArrayInputStream is;
        CipherInputStream cis;
        int nbEssais;
        SecretKey CK;
        byte[] buff;
        try {
            if (!IsInit) return false;
            InputStream LKis = openFileInput(LKfn);
            try {
                readInt(LKis);
                nbEssais = decodeNbEssais(readInt(LKis));
                if (nbEssais == 0)
                    return false;
                SecretKey FK = new SecretKeySpec(readBuff(LKis), Algo);
                buff = readBuff(LKis);
                is = new ByteArrayInputStream(buff);
                c = Cipher.getInstance(Algo);
                c.init(Cipher.DECRYPT_MODE, FK);
                cis = new CipherInputStream(is, c);
                int LIT = readInt(cis);
                byte[] LS = readBuff(cis);
                CK = buildLK(Code, LS, LIT);
                buff = readBuff(LKis);
            } finally {
                LKis.close();
            }
            is = new ByteArrayInputStream(buff);
            c.init(Cipher.DECRYPT_MODE, CK);
            cis = new CipherInputStream(is, c);
            if (readInt(cis) != MN) {
                nbEssais--;
                RandomAccessFile raf = new RandomAccessFile(getFileStreamPath(LKfn), "rw");
                raf.readInt();
                raf.writeInt(encodeNbEssais(nbEssais));
                raf.close();
                return false;
            } else {
                LK = new SecretKeySpec(readBuff(cis), Algo);
                IsAuth = true;
                if (nbEssais < 3) {
                    RandomAccessFile raf = new RandomAccessFile(getFileStreamPath(LKfn), "rw");
                    raf.readInt();
                    raf.writeInt(encodeNbEssais(3));
                    raf.close();
                }
                return true;
            }
        }
        catch (Exception e) {
            throw new InitError();
        }
    }

    public void DesAuth() {
        LK = null;
        IsAuth = false;
    }

    private byte[] buildLS(SecureRandom secRndm) {
        byte[] buff = new byte[16];
        secRndm.nextBytes(buff);
        return buff;
    }

    private int buildLIT(SecureRandom secRndm) {
        return secRndm.nextInt(0xff) + 0x400;
    }

    final int outputKeyLength = 256;
    private SecretKey buildLK(SecureRandom secRndm) throws NoSuchAlgorithmException {
        // Generate a 256-bit key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(Algo);
        keyGenerator.init(outputKeyLength, secRndm);
        return keyGenerator.generateKey();
    }

    private SecretKey buildLK(short[] Code, byte[] LS, int LIT) throws NoSuchAlgorithmException, InvalidKeySpecException {

        char[] CodeC = new char[Code.length];
        for(int i = 0 ; i < Code.length ; i++){
            CodeC[i] = (char)((int)'a' + Code[i]);
        }
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(CodeC, LS, LIT, outputKeyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), Algo);
    }

    public short[] String2Code(CharSequence s) {
        short[] ret = new short[s.length()];
        for(int i = 0 ; i < s.length() ; i++){
            ret[i] = (short)(s.charAt(i) - '0');
        }
        return ret;
    }
}
