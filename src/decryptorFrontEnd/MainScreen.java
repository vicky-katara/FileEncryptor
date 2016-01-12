/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package decryptorFrontEnd;
import commonComponents.CustomDialog;
import cryptoUtil.CryptoUtil;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import javax.swing.JFileChooser;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Iterator;
/**
 *
 * @author Vicky Katara
 */
public class MainScreen extends javax.swing.JFrame {

    /**
     * Creates new form NewJFrame
     */
    public MainScreen() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        browseButton = new javax.swing.JButton();
        filePathTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        DecryptButton = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("File");

        browseButton.setText("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                browseButtonActionPerformed(evt);
            }
        });

        filePathTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filePathTextFieldActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel2.setText("File Decryptor");

        jLabel3.setText("Password");

        passwordField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passwordFieldActionPerformed(evt);
            }
        });

        DecryptButton.setText("Decrypt");
        DecryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DecryptButtonActionPerformed(evt);
            }
        });

        jButton1.setText("Close");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("<Main");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addGap(86, 86, 86)
                        .addComponent(jLabel2))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jLabel3))
                        .addGap(43, 43, 43)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(DecryptButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 100, Short.MAX_VALUE)
                                .addComponent(jButton1))
                            .addComponent(filePathTextField)
                            .addComponent(passwordField, javax.swing.GroupLayout.DEFAULT_SIZE, 230, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(browseButton)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton2)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(browseButton)
                    .addComponent(filePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 17, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(DecryptButton)
                    .addComponent(jButton1))
                .addGap(38, 38, 38))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void filePathTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filePathTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_filePathTextFieldActionPerformed

    private void passwordFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passwordFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passwordFieldActionPerformed

    private void DecryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DecryptButtonActionPerformed
        // TODO add your handling code here:
        if(filePathTextField.getText().length()==0){
            CustomDialog.main(new String[]{"Please select a valid File"});
        }
        if(passwordField.getPassword().length<6){
            CustomDialog.main(new String[]{"Password must be 6 characters of more"});
        }
        Iterator<byte[]> iter_bytes = getStreamFromFile(filePathTextField.getText());
        ArrayList<String> decryptedLines = decryptStream(iter_bytes);
        System.out.println("The "+decryptedLines.size()+" decrypted line(s) is/are:"+decryptedLines);
        String originalFilePath = filePathTextField.getText();
        String encFilePath = originalFilePath.replace("encrypted", "decrypted");
        writeToFile(encFilePath, decryptedLines);
    }//GEN-LAST:event_DecryptButtonActionPerformed

    ArrayList<String> decryptStream(Iterator<byte[]> inputIterator){
        CryptoUtil cryptoUtil=new CryptoUtil();
        String key=new String(passwordField.getPassword());
        ArrayList<String> decryptedLines = new ArrayList<String>();
        try{
            while(inputIterator.hasNext())
                decryptedLines.add(cryptoUtil.decrypt_n(key, inputIterator.next()));
        }
        catch(Exception e){e.printStackTrace();}
        return decryptedLines;
    }
    
    Iterator<byte[]> getStreamFromFile(String filePath){
        try{
            BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(filePath)));
            return getIteratorOfByteArray(br.lines().iterator());
        }
        catch(FileNotFoundException fnfe) {
            fnfe.printStackTrace();
        }
        catch(IOException ioe) {
            ioe.printStackTrace();
        }
        return null;
    }
    
    Iterator<byte[]> getIteratorOfByteArray(Iterator<String> string_iterator){
        ArrayList<byte[]> byteArrArr = new ArrayList<byte[]>();
        while(string_iterator.hasNext())
            byteArrArr.add(byte_arr_from_string_rep(string_iterator.next()));
        return byteArrArr.iterator();
    }
    
    byte[] byte_arr_from_string_rep(String byteString){
        try{
            String[] stringByte = byteString.replace("[", "").replace("]", "").split(", ");
            byte[] byteArr= new byte[stringByte.length];
            for(int index=0;index < byteArr.length; index++)
                    byteArr[index] = Byte.parseByte(stringByte[index]);
            return byteArr;
        }
        catch(NumberFormatException nfe){
            nfe.printStackTrace();
        }
        return null;
    }
    
    void writeToFile(String filePath, ArrayList<String> encryptedLines){
        try{
            BufferedWriter bw = new BufferedWriter(new FileWriter(filePath));
            for(String line:encryptedLines)
                bw.write(line+"\n");
            bw.close();
        }
        catch(IOException ioe){ioe.printStackTrace();}
    }
    
    private void browseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_browseButtonActionPerformed
        // TODO add your handling code here:
        JFileChooser fileChooser = new JFileChooser();
        if( fileChooser.showOpenDialog(null)==JFileChooser.APPROVE_OPTION )
            filePathTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
    }//GEN-LAST:event_browseButtonActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        this.dispose();
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        commonComponents.MainFrontEnd.main(null);
        this.dispose();
    }//GEN-LAST:event_jButton2ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainScreen().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton DecryptButton;
    private javax.swing.JButton browseButton;
    private javax.swing.JTextField filePathTextField;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPasswordField passwordField;
    // End of variables declaration//GEN-END:variables
}
