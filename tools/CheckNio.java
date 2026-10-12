// Diagnose JVM local selector failure; no device or application data is accessed.
public class CheckNio {
    public static void main(String[] args) throws Exception {
        System.out.println("tmp=" + System.getProperty("java.io.tmpdir"));
        System.out.println("provider=" + java.nio.channels.spi.SelectorProvider.provider());
        try (var server = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress());
             var socket = new java.net.Socket(java.net.InetAddress.getLoopbackAddress(), server.getLocalPort());
             var accepted = server.accept()) {
            System.out.println("TCP loopback OK");
        }
        try (var selector = java.nio.channels.Selector.open()) {
            System.out.println("selector OK " + selector);
        }
    }
}
