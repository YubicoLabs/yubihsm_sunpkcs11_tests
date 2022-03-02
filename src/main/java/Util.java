import java.util.Arrays;

public class Util {
    public static void assertEquals(String msg, Object value, Object expected) {
        if(!value.equals(expected)) {
            System.out.println(msg + ". Expected '" + expected.toString() + "', found '" + value + "'");
            System.exit(100);
        }
    }

    public static void assertTrue(String msg, boolean value)  {
        if(!value) {
            System.out.println(msg);
            System.exit(200);
        }
    }

    public static void assertByteArrayEquals(String msg, byte[] value, byte[] expected) {
        if(!Arrays.equals(value, expected)) {
            System.out.println(msg);
            System.exit(300);
        }
    }
}
