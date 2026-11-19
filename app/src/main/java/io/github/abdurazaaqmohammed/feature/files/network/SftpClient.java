package io.github.abdurazaaqmohammed.feature.files.network;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.FileAttributes;
import net.schmizz.sshj.sftp.FileMode;
import net.schmizz.sshj.sftp.OpenMode;
import net.schmizz.sshj.sftp.RemoteFile;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.sftp.RemoteResourceInfo;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.transport.kex.KeyExchange;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;

/**
 * SFTP (SSH) storage. The connection root is the account's home directory.
 * Host keys use trust-on-first-use: {@link #probeHostKey} reports the key a server
 * presents so the UI can ask before pinning it; later connections must present the
 * same key or fail with {@link HostKeyChangedException}.
 * Authentication is either a password or a private key (PEM/OpenSSH, optionally
 * protected by a passphrase).
 */
public final class SftpClient implements RemoteClient {
    private static final int BUFFER_SIZE = 1024 * 1024;

    private final SSHClient ssh;
    private final SFTPClient sftp;
    private final String hostKeyFingerprint;
    /** Backing file for a PEM key; sshj re-reads it while signing, so it lives until the client closes. */
    private File keyTempFile;

    /** Credentials for a login: a password, or a private key plus its passphrase. */
    public static final class Auth {
        public final String password;
        public final String privateKey;
        public final String passphrase;

        private Auth(String password, String privateKey, String passphrase) {
            this.password = password == null ? "" : password;
            this.privateKey = privateKey == null ? "" : privateKey;
            this.passphrase = passphrase == null ? "" : passphrase;
        }

        public static Auth password(String password) { return new Auth(password, null, null); }

        public static Auth key(String privateKey, String passphrase) {
            return new Auth(null, privateKey, passphrase);
        }

        public boolean usesKey() { return !privateKey.trim().isEmpty(); }
    }

    /** What the server presented during a host-key probe, for the confirmation prompt. */
    public static final class HostKeyInfo {
        public final String host;
        public final int port;
        public final String algorithm;
        public final int bits;
        public final String fingerprint;

        HostKeyInfo(String host, int port, String algorithm, int bits, String fingerprint) {
            this.host = host;
            this.port = port;
            this.algorithm = algorithm;
            this.bits = bits;
            this.fingerprint = fingerprint;
        }

        /** e.g. "Ed25519 · SHA256:abc…"; used as the dialog body line. */
        public String describe() {
            if (algorithm == null || algorithm.isEmpty()) return "SHA256:" + fingerprint;
            String algo = bits > 0 ? algorithm + " " + bits : algorithm;
            return algo + " · SHA256:" + fingerprint;
        }
    }

    /** The server's key no longer matches the pinned one; the caller may ask the user to accept it. */
    public static final class HostKeyChangedException extends IOException {
        public final String host;
        public final int port;
        public final String pinned;
        public final String presented;

        HostKeyChangedException(String host, int port, String pinned, String presented) {
            super("Host key changed for " + host + ":" + port + " (pinned " + pinned + ", presented " + presented + ")");
            this.host = host;
            this.port = port;
            this.pinned = pinned;
            this.presented = presented;
        }
    }

    public SftpClient(String host, int port, String username, String password, String knownHostKey) throws IOException {
        this(host, port, username, Auth.password(password), knownHostKey);
    }

    public SftpClient(String host, int port, String username, Auth auth, String knownHostKey) throws IOException {
        if (username == null || username.trim().isEmpty())
            throw new IllegalArgumentException("SFTP requires a username");
        ensureBouncyCastle();
        ssh = newClient();
        ssh.setConnectTimeout(15_000);
        ssh.setTimeout(60_000);
        String known = knownHostKey == null ? "" : knownHostKey.trim();
        String[] presented = {null};
        boolean[] rejected = {false};
        ssh.addHostKeyVerifier(new HostKeyVerifier() {
            @Override public boolean verify(String hostname, int hostPort, PublicKey key) {
                String fingerprint = fingerprint(key);
                presented[0] = fingerprint;
                if (known.isEmpty() || known.equals(fingerprint)) return true; // TOFU pin
                rejected[0] = true;
                return false;
            }
            @Override public List<String> findExistingAlgorithms(String hostname, int hostPort) {
                return Collections.emptyList();
            }
        });
        KeyProvider keyAuth = null;
        if (auth.usesKey()) {
            try {
                keyAuth = keyProvider(auth.privateKey, auth.passphrase);
                // Decrypt now, so a wrong passphrase is reported as a key problem instead of a vague auth failure.
                keyAuth.getPrivate();
            } catch (Exception e) {
                closeQuietly();
                throw new IOException("Cannot read the private key: " + e.getMessage()
                        + (auth.passphrase.isEmpty() ? "" : " (check the key passphrase)"), e);
            }
        }
        try {
            ssh.connect(host, port);
        } catch (IOException e) {
            closeQuietly();
            if (rejected[0]) throw new HostKeyChangedException(host, port, known, presented[0]);
            throw new IOException("SFTP connect " + host + ":" + port + ": " + e.getMessage(), e);
        }
        hostKeyFingerprint = presented[0];
        try {
            if (keyAuth != null) ssh.authPublickey(username, keyAuth);
            else ssh.authPassword(username, auth.password);
            sftp = ssh.newSFTPClient();
        } catch (IOException e) {
            closeQuietly();
            throw new IOException("SFTP login " + username + "@" + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    /** Connects only far enough to read the host key; the user confirms it before a real login. */
    public static HostKeyInfo probeHostKey(String host, int port) throws IOException {
        ensureBouncyCastle();
        SSHClient probe = newClient();
        probe.setConnectTimeout(15_000);
        PublicKey[] presented = {null};
        probe.addHostKeyVerifier(new HostKeyVerifier() {
            @Override public boolean verify(String hostname, int hostPort, PublicKey key) {
                presented[0] = key;
                return true;
            }
            @Override public List<String> findExistingAlgorithms(String hostname, int hostPort) {
                return Collections.emptyList();
            }
        });
        try {
            probe.connect(host, port);
            if (presented[0] == null) throw new IOException("Server presented no host key");
            int bits = presented[0] instanceof RSAPublicKey rsa ? rsa.getModulus().bitLength() : 0;
            return new HostKeyInfo(host, port, algorithmName(presented[0]), bits, fingerprint(presented[0]));
        } catch (IOException e) {
            throw new IOException("SFTP host key " + host + ":" + port + ": " + e.getMessage(), e);
        } finally {
            try { if (probe.isConnected()) probe.disconnect(); } catch (Exception ignored) {}
        }
    }

    /**
     * Android ships a stripped BouncyCastle without X25519, so curve25519 key exchange fails with
     * "no such algorithm: X25519". Drop those proposals and let the DH/ECDH groups negotiate.
     */
    private static SSHClient newClient() {
        DefaultConfig config = new DefaultConfig();
        List<Factory.Named<KeyExchange>> supported = new ArrayList<>();
        for (Factory.Named<KeyExchange> factory : config.getKeyExchangeFactories()) {
            String name = factory.getName();
            if (name != null && name.toLowerCase(Locale.ROOT).contains("curve25519")) continue;
            supported.add(factory);
        }
        if (!supported.isEmpty()) config.setKeyExchangeFactories(supported);
        return new SSHClient(config);
    }

    private static void ensureBouncyCastle() {
        // sshj needs BouncyCastle for modern key exchange; MainActivity registers it too.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    private static String algorithmName(PublicKey key) {
        String algorithm = key.getAlgorithm();
        if ("EdDSA".equalsIgnoreCase(algorithm) || "Ed25519".equalsIgnoreCase(algorithm)) return "Ed25519";
        if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) return "ECDSA";
        return algorithm;
    }

    /**
     * Writes the key to a private cache file so sshj can parse it. sshj reads the file lazily while
     * signing, so the file must outlive this call and is only removed when the client closes.
     */
    private KeyProvider keyProvider(String pem, String passphrase) throws IOException {
        File file = File.createTempFile("sftp_key", ".pem");
        keyTempFile = file;
        try {
            try (FileOutputStream out = new FileOutputStream(file)) {
                out.write(pem.trim().getBytes(StandardCharsets.UTF_8));
                out.write('\n');
            }
            return passphrase.isEmpty()
                    ? ssh.loadKeys(file.getAbsolutePath())
                    : ssh.loadKeys(file.getAbsolutePath(), passphrase.toCharArray());
        } catch (IllegalArgumentException e) {
            throw new IOException("Unsupported private key: " + e.getMessage(), e);
        }
    }

    /** SHA-256 fingerprint (Base64) of the key the server presented; persist it with the profile. */
    public String hostKeyFingerprint() { return hostKeyFingerprint; }

    private static String fingerprint(PublicKey key) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key.getEncoded()));
        } catch (Exception e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }

    /** "" is the home directory; every other path stays relative to it. */
    private static String remotePath(String path) {
        String normalized = RemotePath.normalize(path);
        return normalized.isEmpty() ? "." : normalized;
    }

    private static IOException io(String operation, String path, Exception cause) {
        return new IOException("SFTP " + operation + " '" + path + "': " + cause.getMessage(), cause);
    }

    @Override public List<RemoteEntry> list(String directory) throws IOException {
        try {
            List<RemoteEntry> entries = new ArrayList<>();
            String parent = RemotePath.normalize(directory);
            for (RemoteResourceInfo info : sftp.ls(remotePath(directory))) {
                String name = info.getName();
                if (name.equals(".") || name.equals("..")) continue;
                FileAttributes attrs = info.getAttributes();
                entries.add(new RemoteEntry(RemotePath.child(parent, name),
                        info.isDirectory(), attrs.getSize(), attrs.getMtime() * 1000L));
            }
            return entries;
        } catch (IOException e) { throw io("list", directory, e); }
    }

    @Override public RemoteEntry stat(String path) throws IOException {
        try {
            FileAttributes attrs = sftp.statExistence(remotePath(path));
            if (attrs == null) return null;
            return new RemoteEntry(RemotePath.normalize(path), attrs.getType() == FileMode.Type.DIRECTORY,
                    attrs.getSize(), attrs.getMtime() * 1000L);
        } catch (IOException e) { throw io("stat", path, e); }
    }

    @Override public void download(String path, OutputStream destination) throws IOException {
        RemoteFile file = null;
        try {
            file = sftp.open(remotePath(path), EnumSet.of(OpenMode.READ));
            try (InputStream source = file.new RemoteFileInputStream()) { copy(source, destination); }
        } catch (IOException e) { throw io("download", path, e); }
        finally { closeFile(file); }
    }

    @Override public void upload(String path, InputStream source, long size) throws IOException {
        WebDavClient.requireNonRoot(path);
        FileAttributes existing;
        try { existing = sftp.statExistence(remotePath(path)); }
        catch (IOException e) { throw io("upload", path, e); }
        if (existing != null) throw new IOException("SFTP upload '" + path + "': target already exists");
        RemoteFile file = null;
        try {
            file = sftp.open(remotePath(path), EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.TRUNC));
            try (OutputStream destination = file.new RemoteFileOutputStream()) { copy(source, destination); }
        } catch (IOException e) { throw io("upload", path, e); }
        finally { closeFile(file); }
    }

    @Override public void mkdir(String path) throws IOException {
        WebDavClient.requireNonRoot(path);
        try { sftp.mkdir(remotePath(path)); }
        catch (IOException e) { throw io("mkdir", path, e); }
    }

    @Override public void rename(String path, String destination) throws IOException {
        WebDavClient.requireNonRoot(path);
        WebDavClient.requireNonRoot(destination);
        try { sftp.rename(remotePath(path), remotePath(destination)); }
        catch (IOException e) { throw io("rename", path + " -> " + destination, e); }
    }

    @Override public void delete(String path, boolean directory) throws IOException {
        WebDavClient.requireNonRoot(path);
        try {
            if (directory) deleteRecursive(path);
            else sftp.rm(remotePath(path));
        } catch (IOException e) { throw io("delete", path, e); }
    }

    private void deleteRecursive(String path) throws IOException {
        for (RemoteResourceInfo info : sftp.ls(remotePath(path))) {
            String name = info.getName();
            if (name.equals(".") || name.equals("..")) continue;
            String child = RemotePath.child(RemotePath.normalize(path), name);
            if (info.isDirectory()) deleteRecursive(child);
            else sftp.rm(remotePath(child));
        }
        sftp.rmdir(remotePath(path));
    }

    /** sshj 0.38.0 exposes no statvfs; storage space stays unknown. */
    @Override public RemoteSpace space() { return null; }

    @Override public void close() {
        try { sftp.close(); } catch (Exception ignored) {}
        closeQuietly();
    }

    private void closeQuietly() {
        try { if (ssh.isConnected()) ssh.disconnect(); } catch (Exception ignored) {}
        if (keyTempFile != null) {
            //noinspection ResultOfMethodCallIgnored
            keyTempFile.delete();
            keyTempFile = null;
        }
    }

    private static void closeFile(RemoteFile file) {
        if (file != null) try { file.close(); } catch (Exception ignored) {}
    }

    private static void copy(InputStream source, OutputStream destination) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int n;
        while ((n = source.read(buffer)) != -1) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("Transfer cancelled");
            destination.write(buffer, 0, n);
        }
    }
}
