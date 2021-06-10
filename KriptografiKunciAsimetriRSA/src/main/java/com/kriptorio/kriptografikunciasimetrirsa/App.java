package com.kriptorio.kriptografikunciasimetrirsa;
// Dibuat Oleh : M.Irvan Dimetrio(18360018)

import java.security.Key;
import java.security.KeyPair;
import java.util.Scanner;
import org.apache.commons.codec.binary.Base64;

/**
 * Algoritma RSA dengan paket library Bouncy Castle. Key pair berada di memori
 *
 */
public class App {

    public static void main(String[] args) {
        Key kunciPublik = null;
        Key kunciPrivate = null;
        String isWantDemoAgain;
        System.out.println("Demo Kriptografi Asimetris RSA on memory \n");
        RSAwithBC rsaBC = new RSAwithBC(2048);
        Scanner inputKeyboard = new Scanner(System.in);
        do {
// Pembangkitan pasangan kunci
            System.out.println("Ingin membuat pasangan kunci di memori (y/n) ? ");
            String isCreatePairKey = inputKeyboard.nextLine();
            if (isCreatePairKey.equalsIgnoreCase("y")) {
                KeyPair pasanganKunci = rsaBC.generatePairKey();
                kunciPublik = pasanganKunci.getPublic();
                kunciPrivate = pasanganKunci.getPrivate();
                System.out.println("Kunci Publik : \n" + Base64.encodeBase64(kunciPublik.getEncoded())
                        + "\n");
                System.out.println("Kunci Private : \n"
                        + Base64.encodeBase64(kunciPrivate.getEncoded()) + "\n");
            }
// Proses enkripsi pesan
            System.out.println("Ingin melakukan enkripsi RSA (y/n) ? ");
            String isWantEncrypt = inputKeyboard.nextLine();
            if (isWantEncrypt.equalsIgnoreCase("y")) {
                System.out.println("Masukkan plaintext : ");
                String plaintext = inputKeyboard.nextLine();
                String chipertext = rsaBC.encrypt(kunciPublik, plaintext);
                System.out.println("Chipertext : " + chipertext + "\n");
            }
// Proses Dekripsi sebuah String menggunakan RSA
            System.out.println("Ingin melakukan dekripsi RSA (y/n) ? ");
            String isWantDecrypt = inputKeyboard.nextLine();
            if (isWantDecrypt.equalsIgnoreCase("y")) {
                System.out.println("Masukkan ciphertext : ");
                String ciphertext = inputKeyboard.nextLine();
                String decryptedText = rsaBC.decrypt(kunciPrivate, ciphertext);
                System.out.println("Hasil Dekripsi : " + decryptedText + "\n");
            }
            System.out.println("Ingin melakukan demo kriptografi RSA lagi (y/n) ");
            isWantDemoAgain = inputKeyboard.nextLine();
        } while (isWantDemoAgain.equalsIgnoreCase("y"));
        inputKeyboard.close();
    }
} 
