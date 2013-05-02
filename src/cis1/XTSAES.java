package cis1;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import javax.swing.JOptionPane;

/**
 * Class XTSAES adalah kelas yang berisi method-method untuk menjalankan
 * enkripsi dan dekripsi sesuai algoritma XTSAES
 *
 * @author Anang Ferdi Kusuma (1006665952)
 * @author Arief Yudha Satria (1006665984)
 * @author Evan Ariansyah H (1006671381)
 */
public class XTSAES {

    private static byte[] tweak =
            Util.hex2byte("0123456789abcdef0123456789abcdef");
    private AES aes;
    private File i;
    private File k;
    private File o;
    private byte[] key1;
    private byte[] key2;
    private byte[][] tTable;
    private byte[] input;
    private byte[][] inputBlock;
    private byte[] tweakAfterEncrypt;
    private int mode;
    private String rawKey;

    /**
     * Default constructor
     *
     * @param input adalah file input.
     * @param key adalah file key.
     * @param output adalah file output.
     * @param mode adalah pilihan mode untuk enkripsi atau dekripsi.
     */
    public XTSAES(File input, File key, File output, int mode) {
        this.aes = new AES();
        this.i = input;
        this.k = key;
        this.o = output;
        this.mode = mode;
    }

    /**
     * Method start menjalankan proses enkripsi atau dekripsi.
     */
    public void start() {
        try {
            //Baca key dari file.
            BufferedReader br = new BufferedReader(new FileReader(k));
            rawKey = br.readLine();
            key1 = Util.hex2byte(rawKey.substring(0, 32));
            key2 = Util.hex2byte(rawKey.substring(32, 64));
            aes.setKey(key2);
            br.close();

            //Baca input dari file.
            DataInputStream dis = new DataInputStream(new FileInputStream(i));
            input = new byte[dis.available()];
            dis.read(input);
            inputBlock = new byte[(int) Math.ceil(input.length / 16.0)][16];
            int jj = 0;
            for (int i = 0; i < inputBlock.length; i++) {
                for (int j = 0; j < inputBlock[i].length; j++) {
                    jj = i * 16 + j;
                    if (jj < input.length) {
                        inputBlock[i][j] = input[i * 16 + j];
                    }
                }
            }
            byte[] lastBlock = inputBlock[inputBlock.length - 1];
            tTable = new byte[inputBlock.length][16];
            tweakAfterEncrypt = aes.encrypt(tweak);
            dis.close();

            //Mengisi tTable.
            fillTTable();

            //Baca output dari file.
            DataOutputStream dos = new DataOutputStream(
                    new FileOutputStream(o));
            int buntut = input.length % 16;
            int sisa = 16 - buntut;
            if (mode == Tugas1Kripto.ENCRYPT) {
                for (jj = 0; jj < inputBlock.length - 2; jj++) {
                    dos.write(xtsBlockEncrypt(inputBlock[jj], jj));
                }
                System.out.println((inputBlock.length - 2) + " " + jj);
                //Array of byte tempat menyimpan cmcp. 
                byte[] pm1 = inputBlock[jj];
                byte[] pmcp = inputBlock[jj + 1];
                byte[] cmcp = xtsBlockEncrypt(pm1, jj);
                byte[] cm = new byte[buntut];
                System.arraycopy(cmcp, 0, cm, 0, cm.length);
                for (int iii = 0; iii < sisa; iii++) {
                    pmcp[buntut + iii] = cmcp[buntut + iii];
                }
                byte[] cmmin1 = xtsBlockEncrypt(pmcp, jj + 1);
                dos.write(cmmin1);
                dos.write(cm);
            } else {
                for (jj = 0; jj < inputBlock.length - 2; jj++) {
                    dos.write(xtsBlockDecrypt(inputBlock[jj], jj));
                }
                byte[] pm1 = inputBlock[jj];
                byte[] pmcp = inputBlock[jj + 1];
                byte[] cmcp = xtsBlockDecrypt(pm1, jj + 1);
                byte[] cm = new byte[buntut];
                System.arraycopy(cmcp, 0, cm, 0, cm.length);
                for (int ii = 0; ii < sisa; ii++) {
                    pmcp[buntut + ii] = cmcp[buntut + ii];
                }
                byte[] cmmin1 = xtsBlockDecrypt(pmcp, jj);
                dos.write(cmmin1);
                dos.write(cm);
            }
            dos.close();
            JOptionPane.showMessageDialog(null, "Proses berhasil dilakukan!",
                    "Berhasil", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Method xtsBlockEncrypt melakukan enkripsi untuk setiap blok.
     *
     * @param plain adalah plaintext.
     * @param j adalah nomor blok.
     * @return cipher block
     */
    private byte[] xtsBlockEncrypt(byte[] plain, int j) {
        byte[] pp = xor(plain, tTable[j]);
        aes.setKey(key1);
        byte[] cc = aes.encrypt(pp);
        byte[] cj = xor(cc, tTable[j]);
        return cj;
    }

    /**
     * Method xtsBlockDecrypt melakukan dekripsi untuk setiap blok.
     *
     * @param cipher adalah ciphertext.
     * @param j adalah nomor blok.
     * @return plain block.
     */
    private byte[] xtsBlockDecrypt(byte[] cipher, int j) {
        byte[] cc = xor(cipher, tTable[j]);
        aes.setKey(key1);
        byte[] pp = aes.decrypt(cc);
        byte[] pj = xor(pp, tTable[j]);
        return pj;
    }

    /**
     * Method fillTable Mengisi tTable yaitu table yang berisi elemen-elemen
     * encrypt(i) dikali alpha^j
     */
    private void fillTTable() {
        tTable[0] = new byte[16];
        tTable[0] = tweakAfterEncrypt;
        for (int jj = 1; jj < inputBlock.length; jj++) {
            byte[] temp = new byte[16];
            temp[0] = (byte) ((tTable[jj - 1][0] << 1) % 128
                    ^ 135 * (tTable[jj - 1][15] >>> 7));
            for (int kk = 1; kk < 16; kk++) {
                temp[kk] = (byte) ((tTable[jj - 1][kk] << 1) % 128
                        ^ (tTable[jj - 1][kk - 1] >>> 7));
            }
            tTable[jj] = temp;
        }
    }

    /**
     * Method xor melakukan operasi xor.
     *
     * @param a byte pertama.
     * @param b byte kedua.
     * @return byte hasil xor.
     */
    private byte[] xor(byte[] a, byte[] b) {
        byte[] res = new byte[a.length];
        for (int jj = 0; jj < res.length; jj++) {
            res[jj] = (byte) (a[jj] ^ b[jj]);
        }
        return res;
    }

    /**
     * Method validate melakukan validasi pada setiap masukan.
     *
     * @return true jika valid, false jika tidak valid.
     */
    private boolean validate() {
        if (input.length <= 16) {
            JOptionPane.showMessageDialog(null, "Input file too short",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        } else if (rawKey.length() != 64 || !Util.isHex(rawKey)) {
            JOptionPane.showMessageDialog(null, "Invalid key", "Error",
                    JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }
}
