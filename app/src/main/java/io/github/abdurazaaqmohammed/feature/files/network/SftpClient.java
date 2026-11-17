package io.github.abdurazaaqmohammed.feature.files.network;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.FileAttributes;
import net.schmizz.sshj.sftp.FileMode;
import net.schmizz.sshj.sftp.OpenMode;
import net.schmizz.sshj.sftp.RemoteFile;
import net.schmizz.sshj.sftp.RemoteResourceInfo;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

/**
 * SFTP (SSH) storage. The connection root is the account's home directory.
 * Host keys use trust-on-first-use: the first connection pins the server's
 * SHA-256 fingerprint (see {@link #hostKeyFingerprint()}); later connections
 * must present the same key or fail with "Host key changed".
 */
public final class SftpClient implements RemoteClient {
    private static final int BUFFER_SIZE = 1024 * 1024;

    private final SSHClient ssh;
    private final SFTPClient sftp;
    private final String hostKeyFingerprint;

    public SftpClient(String host, int port, String username, String password, String knownHostKey) throws IOException {
        if (username == null || username.trim().isEmpty())
            throw new IllegalArgumentException("SFTP requires a username");
        // sshj needs BouncyCastle for modern key exchange; MainActivity registers it too.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());
        ssh = new SSHClient();
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
        try {
            ssh.connect(host, port);
        } catch (IOException e) {
            closeQuietly();
            if (rejected[0]) throw new IOException("Host key changed for " + host + ":" + port
                    + " (pinned " + known + ", presented " + presented[0] + ")", e);
            throw new IOException("SFTP connect " + host + ":" + port + ": " + e.getMessage(), e);
        }
        hostKeyFingerprint = presented[0];
        try {
            ssh.authPassword(username, password == null ? "" : password);
            sftp = ssh.newSFTPClient();
        } catch (IOException e) {
            closeQuietly();
            throw new IOException("SFTP login " + username + "@" + host + ":" + port + ": " + e.getMessage(), e);
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
