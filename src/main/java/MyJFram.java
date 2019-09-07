import javax.swing.JFrame;

public class MyJFram extends JFrame {

    public MyJFram() {
        setDefaultLookAndFeelDecorated(true);
        //设置显示窗口标题
        setTitle("Java 第一个 GUI 程序");
        //设置窗口显示尺寸
        setSize(400,200);
        //置窗口是否可以关闭
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //创建一个标签
        //设置窗口是否可见
        setVisible(true);
    }
}
