import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Swing {

    private final static String  aesKey = "ZK34+THR+hP7546ww1utSz39mQRAyzCb3uinQPVTtoAhkuGrJg5QTVMHxKwCZK/GvVHHD4blyrE4IWeEE4SnFvKYLvLEhc15yN5k1jVD4BOUeSDjMHIlunpiCVeIwY547MKekpTE7cbOUH9wMmFpvyl1A0wYs9uh97XHf76Clrk=";

    private final static String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcC2kVgzBvgGFKvIW6g3OhAV2SBaPxHJ0A/qsh/jq4bK8i9Ta3p8D5VTfeWJd4PSRqPxjKLgmxC9eEY+YOXinP/v2l5IY5tO0KD9flAjE+npCFoyXtB8coJIucqsBKMY399IJYHAC531BnpDHZbEc2pm/O/9doIRzKgITxcgejFwIDAQAB";

    private JTextArea jTextArea;

    private JScrollPane jScrollPane;


    public Swing() {
        JFrame frame=new JFrame("Base64解码小工具");
        frame.setLayout(new CardLayout());
        JPanel rootJPanel = new JPanel(new CardLayout());
        JPanel jPane2 = new JPanel();
        //设置解密按钮
        JButton jButton = new JButton("base解密");
        jButton.setBackground(Color.cyan);
        jButton.addActionListener(new myLister());
        JButton jsonFormt = new JButton("json格式化");
        jsonFormt.setBackground(Color.cyan);
        jsonFormt.addActionListener(new jsonListener());
        JButton encryptBtn = new JButton("解密");
        encryptBtn.setBackground(Color.cyan);
        encryptBtn.addActionListener(e -> {
            String text = jTextArea.getText();
            if (text != null && text.length() > 0) {
                String encrypt = encrypt(text);
                jTextArea.setText(encrypt);
            }
        });

        JButton clearBtn = new JButton("清除");
        clearBtn.setBackground(Color.cyan);
        clearBtn.addActionListener(e -> jTextArea.setText(""));
        jPane2.add(jButton);
        jPane2.add(jsonFormt);
        jPane2.add(clearBtn);
        jPane2.add(encryptBtn);
        //内容模块
        jTextArea = new JTextArea("", 30, 40);
        jTextArea.setForeground(Color.BLACK);
        jTextArea.setFont(new Font("楷体",Font.BOLD,18));
        jTextArea.setBackground(Color.getHSBColor(85, 125, 200));
        jScrollPane = new JScrollPane(jTextArea);
        Dimension preferredSize = jTextArea.getPreferredSize();
        jScrollPane.setBounds(100, 60, preferredSize.width, preferredSize.height);
        jPane2.add(jScrollPane);

        rootJPanel.add(jPane2, "card2");

        CardLayout cl=(CardLayout)(rootJPanel.getLayout());
        cl.show(rootJPanel, "card2");
        frame.add(rootJPanel);
        frame.setResizable(false);
        Image image = new ImageIcon("image/icon.png").getImage();
        frame.setIconImage(image);
        frame.setBounds(300,200,500,730);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);



    }

    class myLister implements  ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            String text = jTextArea.getText();
            if (text != null && !text.equals("") && text.length() > 0) {
                byte[] result = Base64.getDecoder().decode(text.getBytes());
                try {
                    jTextArea.setText(new String(result,"UTF-8"));
                } catch (UnsupportedEncodingException e1) {
                    e1.printStackTrace();
                }
            }

        }
    }

    class jsonListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            String text = jTextArea.getText();
            if (text != null && !text.equals("") && text.length() > 0) {
                jTextArea.setText(JsonFormatTool.formatJson(text));
            }
        }
    }

    public static void main(String[] args) {

        Swing swing = new Swing();


    }

    /**
     * Java8中的Base64编码
     * @param str
     * @return
     */
    public static String encodeByJava8(String str) {
        try {
            return Base64.getEncoder().encodeToString(str.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * Java8中的Base64解码
     * @param str
     * @return
     */
    public static String decodeByJava8(String str) {
        byte[] result = Base64.getDecoder().decode(str.getBytes());
        return new String(result);
    }

    /**
     * 解密
     * @param text
     * @return
     */
    public String encrypt(String text) {
        String encrypt = null;
        try {
            System.out.println(text);
            encrypt = AesECBUtil.decrypt(text, RSACoderUtil.decryptAesKey(aesKey, pubKey));
            System.out.println(encrypt);
        } catch (Exception e) {
        } finally {
            if (encrypt == null) {
                encrypt = null;
            }
        }
        return encrypt;
    }

}
