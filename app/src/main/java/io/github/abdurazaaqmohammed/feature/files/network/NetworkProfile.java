package io.github.abdurazaaqmohammed.feature.files.network;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

import okhttp3.HttpUrl;

public final class NetworkProfile {
    public String name = "";
    public String protocol = "webdav";
    public String address = "";
    public String username = "";
    public String password = "";
    public String domain = "";
    /** TOFU-pinned SSH host key fingerprint (SHA-256, Base64); persisted with the profile. */
    public String hostKey = "";
    /** SFTP only: "password" or "key". */
    public String authMethod = "password";
    /** SFTP key auth: the PEM/OpenSSH private key text (never written anywhere but the encrypted store). */
    public String privateKey = "";
    /** SFTP key auth: the passphrase protecting the private key, if any. */
    public String keyPassphrase = "";

    public boolean usesKeyAuth() { return protocol.equals("sftp") && "key".equals(authMethod); }
    transient String previousName;

    public String pinId() { return protocol + ":" + name; }
    public String storageIdentity() { return canonicalAddress() + "\u0000" + username + "\u0000" + domain; }

    public void validate() {
        if (protocol.equals("webdav")) {
            HttpUrl url = HttpUrl.get(address);
            if (!url.username().isEmpty() || !url.password().isEmpty() || url.query() != null || url.fragment() != null)
                throw new IllegalArgumentException("Enter an HTTP(S) collection URL without credentials, query or fragment");
        } else if (protocol.equals("smb")) {
            URI uri = smbUri();
            RemotePath.validateName(share());
            if (!"smb".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || uri.getPort() == 0
                    || uri.getPort() > 65535 || uri.getPort() < -1)
                throw new IllegalArgumentException("Enter smb://host/share (optional :port)");
        } else if (protocol.equals("sftp")) {
            URI uri = sftpUri();
            String path = uri.getPath();
            if (!"sftp".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || uri.getPort() == 0
                    || uri.getPort() > 65535 || uri.getPort() < -1
                    || (path != null && !path.isEmpty() && !path.equals("/")))
                throw new IllegalArgumentException("Enter sftp://host (optional :port, default 22)");
            if (usesKeyAuth() && privateKey.trim().isEmpty())
                throw new IllegalArgumentException("Paste or import a private key, or switch to password authentication");
        } else throw new IllegalArgumentException("Unknown network protocol");
        if (name.trim().isEmpty()) name = address;
    }

    private URI smbUri() {
        try { return new URI(address); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid SMB URL", e); }
    }

    /** Accepts sftp://host[:port] or a bare host[:port]; the port defaults to 22. */
    private URI sftpUri() {
        try { return new URI(address.contains("://") ? address : "sftp://" + address); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid SFTP address", e); }
    }

    public String share() {
        String path = smbUri().getPath();
        if (path == null || !path.startsWith("/")) throw new IllegalArgumentException("An SMB share is required");
        String share = path.substring(1);
        if (share.endsWith("/")) share = share.substring(0, share.length() - 1);
        return share;
    }

    public RemoteClient connect() throws IOException {
        validate();
        if (protocol.equals("webdav")) return new WebDavClient(address, username, password);
        if (protocol.equals("sftp")) {
            URI uri = sftpUri();
            String host = uri.getHost();
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
            SftpClient.Auth auth = usesKeyAuth()
                    ? SftpClient.Auth.key(privateKey, keyPassphrase)
                    : SftpClient.Auth.password(password);
            return new SftpClient(host, uri.getPort() == -1 ? 22 : uri.getPort(), username, auth, hostKey);
        }
        URI uri = smbUri();
        String host = uri.getHost();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return new SmbClient(host, uri.getPort() == -1 ? 445 : uri.getPort(), share(), username, password, domain);
    }

    public String canonicalAddress() {
        validate();
        if (protocol.equals("webdav")) {
            HttpUrl url = HttpUrl.get(address);
            return url.newBuilder().encodedPath(url.encodedPath().endsWith("/")
                    ? url.encodedPath() : url.encodedPath() + "/").build().toString();
        }
        if (protocol.equals("sftp")) {
            URI uri = sftpUri();
            try {
                return new URI("sftp", null, uri.getHost().toLowerCase(Locale.ROOT),
                        uri.getPort() == -1 ? 22 : uri.getPort(), "/", null, null).toASCIIString();
            } catch (URISyntaxException e) { throw new IllegalArgumentException("Invalid SFTP address", e); }
        }
        URI uri = smbUri();
        try {
            return new URI("smb", null, uri.getHost().toLowerCase(Locale.ROOT),
                    uri.getPort() == 445 ? -1 : uri.getPort(), "/" + share() + "/", null, null).toASCIIString();
        } catch (URISyntaxException e) { throw new IllegalArgumentException("Invalid SMB URL", e); }
    }
}
