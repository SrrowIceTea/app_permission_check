package com.vscanner.privacydemo;

// 仅用于授权测试：Gadget 变体的合成阳性/阴性对照，不读取真实个人数据。
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class AuditProbeActivity extends Activity {
    private TextView display;
    private String token, fixtureHost, udpHost, runId;
    private boolean skipUdp;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        display = new TextView(this);
        setContentView(display);
        token = getIntent().getStringExtra("audit_token");
        if (token == null || !token.matches("VSCAN_TEST_[A-Za-z0-9_]{1,64}")) {
            emit("REFUSED", "synthetic audit_token required");
            return;
        }
        fixtureHost = getIntent().getStringExtra("fixture_host");
        if (fixtureHost == null || fixtureHost.isEmpty()) fixtureHost = "10.0.2.2";
        udpHost = getIntent().getStringExtra("udp_host");
        if (udpHost == null || udpHost.isEmpty()) udpHost = fixtureHost;
        runId = getIntent().getStringExtra("audit_run_id");
        if (runId == null) runId = "manual";
        skipUdp = getIntent().getBooleanExtra("skip_udp", false);
        new Thread(() -> {
            probe("storage_crypto", () -> storageCrypto());
            probe("http", () -> http(false));
            probe("https", () -> http(true));
            probe("tcp", () -> tcp());
            if (skipUdp) emit("udp_UNSUPPORTED", "USB reverse cannot transport UDP");
            else probe("udp", () -> udp());
            probe("dns", () -> dns());
            emit("DONE", token);
        }, "owned-audit-probe").start();
    }

    private interface Action { String run() throws Exception; }
    private void probe(String name, Action action) {
        try { emit(name + "_OK", action.run()); }
        catch (Exception e) { emit(name + "_FAIL", e.getClass().getSimpleName() + ":" + e.getMessage()); }
    }
    private void emit(String event, String detail) {
        String line = "AUDIT_PROBE " + event + " " + detail + " token=" + token + " run=" + runId;
        Log.i("AuditProbe", line);
        runOnUiThread(() -> display.append(line + "\n"));
    }

    private String storageCrypto() throws Exception {
        byte[] data = token.getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream stream = openFileOutput("audit-plaintext.txt", MODE_PRIVATE)) {
            stream.write(data);
        }
        boolean saved = getSharedPreferences("audit_probe", MODE_PRIVATE).edit()
                .putString("synthetic_canary", token).commit();
        if (!saved) throw new IllegalStateException("preferences commit failed");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128, new SecureRandom());
        SecretKey key = generator.generateKey();
        Cipher weak = Cipher.getInstance("AES/ECB/PKCS5Padding");
        weak.init(Cipher.ENCRYPT_MODE, key);
        byte[] weakCiphertext = weak.doFinal(data);
        try (FileOutputStream stream = openFileOutput("audit-ecb.bin", MODE_PRIVATE)) {
            stream.write(weakCiphertext);
        }
        // Strong-mode control: this does not claim the whole application is secure.
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher strong = Cipher.getInstance("AES/GCM/NoPadding");
        strong.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = strong.doFinal(data);
        try (FileOutputStream stream = openFileOutput("audit-gcm.bin", MODE_PRIVATE)) {
            stream.write(ciphertext);
        }
        Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        if (!token.equals(new String(decrypt.doFinal(ciphertext), StandardCharsets.UTF_8))) {
            throw new IllegalStateException("roundtrip failed");
        }
        return "private-file+committed-prefs+ECB+GCM-control+decrypt-roundtrip";
    }

    private String http(boolean tls) throws Exception {
        URL url = new URL((tls ? "https://" : "http://") + fixtureHost + ":"
                + (tls ? "18891" : "18890") + "/probe");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(6000);
        connection.setReadTimeout(6000);
        if (tls) {
            // Trust ONLY the ephemeral local lab certificate; no global CA/pinning bypass.
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            try (InputStream input = getAssets().open("audit-local-ca.pem")) {
                store.setCertificateEntry("owned-lab", CertificateFactory.getInstance("X.509")
                        .generateCertificate(input));
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), new SecureRandom());
            ((HttpsURLConnection) connection).setSSLSocketFactory(context.getSocketFactory());
        }
        try {
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.getOutputStream().write(token.getBytes(StandardCharsets.UTF_8));
            int status = connection.getResponseCode();
            if (status != 200) throw new IllegalStateException("HTTP status=" + status);
            connection.getInputStream().close();
            return "status=" + status;
        } finally { connection.disconnect(); }
    }

    private String tcp() throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(fixtureHost, 18889), 5000);
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(token.getBytes(StandardCharsets.UTF_8));
            byte[] response = new byte[256];
            int count = socket.getInputStream().read(response);
            if (count <= 0) throw new IllegalStateException("empty TCP reply");
            return "echo_bytes=" + count;
        }
    }
    private String udp() throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            byte[] data = token.getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(data, data.length, InetAddress.getByName(udpHost), 18888));
            DatagramPacket reply = new DatagramPacket(new byte[256], 256);
            socket.receive(reply);
            if (reply.getLength() == 0) throw new IllegalStateException("empty UDP reply");
            return "echo_bytes=" + reply.getLength();
        }
    }
    private String dns() throws Exception {
        // Reserved .test domain, synthetic query only. NXDOMAIN is expected, not a leak verdict.
        try { InetAddress.getAllByName(token.toLowerCase().replace('_', '-') + ".test"); }
        catch (java.net.UnknownHostException expected) { return "NXDOMAIN expected"; }
        return "resolver returned an address";
    }
}
