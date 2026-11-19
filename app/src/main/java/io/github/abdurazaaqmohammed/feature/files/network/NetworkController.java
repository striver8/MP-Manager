package io.github.abdurazaaqmohammed.feature.files.network;

import io.github.abdurazaaqmohammed.feature.ftp.FTPFileWrapper;
import io.github.abdurazaaqmohammed.feature.ftp.FtpProfile;
import io.github.abdurazaaqmohammed.ui.main.RemoteFilesArrayAdapter;

import io.github.abdurazaaqmohammed.util.misc.ErrorUtil;

import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;
import android.widget.ProgressBar;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import io.github.abdurazaaqmohammed.ui.main.MainActivity;
import io.github.abdurazaaqmohammed.MPManager.R;
import io.github.abdurazaaqmohammed.ui.main.MainFilesArrayAdapter;
import io.github.abdurazaaqmohammed.data.prefs.SidebarPins;
import io.github.abdurazaaqmohammed.data.prefs.UiPrefs;
import io.github.abdurazaaqmohammed.util.io.FileUtils;
import io.github.abdurazaaqmohammed.util.io.ParallelTransfer;
import io.github.abdurazaaqmohammed.privilege.impl.RootStaging;
import io.github.abdurazaaqmohammed.util.io.SafFile;
import io.github.abdurazaaqmohammed.util.io.SafFs;
import io.github.codehasan.colorpicker.extensions.Extensions;

public final class NetworkController {
    private final MainActivity activity;
    private final ExecutorService workers = Executors.newFixedThreadPool(2);
    private final Set<RemoteClient> clients = Collections.synchronizedSet(new HashSet<>());
    private volatile boolean closed;
    private Runnable pendingConnection;
    private NetworkConnectionsDialog connections;
    /**
     * The settings behind every live connection, keyed by connection id, so a
     * parallel transfer can open helper sessions with the same credentials.
     */
    private final ConcurrentHashMap<String, NetworkProfile> profileByConnection = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RemoteSpace.Report> spaceReports = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> spaceCheckTimes = new ConcurrentHashMap<>();
    private final ActivityResultLauncher<String> localPermission;

    public NetworkController(MainActivity activity) {
        this.activity = activity;
        localPermission = activity.registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> {
            Runnable pending = pendingConnection;
            pendingConnection = null;
            if (closed || activity.isDestroyed()) return;
            if (granted) { if (pending != null) pending.run(); }
            else Extensions.showMessage(activity, R.string.network_permission_denied);
        });
    }

    public void showConnections() { showConnectionDialog("ftp"); }

    public void showConnectionDialog(String protocol) {
        if (closed) return;
        if (connections == null || !connections.isShowing()) connections = new NetworkConnectionsDialog(activity, this);
        connections.show(protocol);
    }

    /** Compatibility entry point: discovery is part of the SMB tab, not another dialog. */
    public void showDiscovery() { showConnectionDialog("smb"); }

    public void withLocalNetworkPermission(Runnable action) {
        if (closed) return;
        if (Build.VERSION.SDK_INT >= 37 && ContextCompat.checkSelfPermission(activity,
                NetworkAccess.PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            boolean alreadyRequested = pendingConnection != null;
            pendingConnection = action;
            if (!alreadyRequested) localPermission.launch(NetworkAccess.PERMISSION);
            return;
        }
        action.run();
    }

    public void withPermissionForAddress(String address, Runnable action) {
        if (Build.VERSION.SDK_INT >= 37 && ContextCompat.checkSelfPermission(activity,
                NetworkAccess.PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            boolean[] local = {false};
            runOperation(activity.getString(R.string.connect), () -> local[0] = NetworkAccess.requiresPermission(address),
                    () -> { if (local[0]) withLocalNetworkPermission(action); else action.run(); });
        } else if (!closed) action.run();
    }

    public void loadSaved(Consumer<List<NetworkProfile>> loaded) {
        if (closed) return;
        workers.execute(() -> {
            try {
                List<NetworkProfile> profiles = new NetworkProfileStore(activity).load();
                activity.handler.post(() -> {
                    if (!closed && !activity.isDestroyed()) loaded.accept(profiles);
                });
            } catch (Exception e) { showError(e); }
        });
    }

    private void persist(NetworkProfile profile, boolean pin) throws Exception {
        new NetworkProfileStore(activity).put(profile);
        spaceReports.remove(profile.pinId());
        if (profile.previousName != null) spaceReports.remove(profile.protocol + ":" + profile.previousName);
        if (pin) SidebarPins.add(activity, profile.pinId());
        else SidebarPins.remove(activity, profile.pinId());
    }

    public void save(NetworkProfile profile, boolean pin, Runnable onSuccess) {
        runOperation(activity.getString(R.string.save), () -> persist(profile, pin), () -> {
            activity.refreshSidebarAsync(activity.getSidebarSectionOrder());
            if (onSuccess != null) onSuccess.run();
        });
    }

    public void deleteProfile(NetworkProfile profile, Runnable onSuccess) {
        runOperation(activity.getString(R.string.delete), () -> new NetworkProfileStore(activity).remove(profile), () -> {
            spaceReports.remove(profile.pinId());
            activity.refreshSidebarAsync(activity.getSidebarSectionOrder());
            if (onSuccess != null) onSuccess.run();
        });
    }

    public void connectProfile(String pinId, boolean pane1) {
        loadSaved(profiles -> {
            for (NetworkProfile profile : profiles) if (profile.pinId().equals(pinId)) {
                connect(profile, false, false, pane1);
                return;
            }
            Extensions.showMessage(activity, R.string.network_saved_connection_missing);
        });
    }

    public void editProfile(String pinId) {
        loadSaved(profiles -> {
            for (NetworkProfile profile : profiles) if (profile.pinId().equals(pinId)) {
                showConnectionDialog(profile.protocol);
                connections.loadProfile(profile);
                return;
            }
            Extensions.showMessage(activity, R.string.network_saved_connection_missing);
        });
    }

    public void editFtpProfile(String name) {
        for (FtpProfile profile : activity.getFtp().clientProfiles()) {
            if (profile.getName().equals(name)) {
                showConnectionDialog("ftp");
                connections.loadFtpProfile(profile);
                return;
            }
        }
        Extensions.showMessage(activity, R.string.network_saved_connection_missing);
    }

    public void connect(NetworkProfile profile, boolean remember, boolean pin, boolean pane1) {
        if (Build.VERSION.SDK_INT >= 37 && ContextCompat.checkSelfPermission(activity,
                NetworkAccess.PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            boolean[] local = {false};
            runOperation(activity.getString(R.string.connecting_to, profile.name),
                    () -> local[0] = NetworkAccess.requiresPermission(profile.canonicalAddress()), () -> {
                        if (local[0]) {
                            withLocalNetworkPermission(() -> connectReady(profile, remember, pin, pane1));
                        } else connectReady(profile, remember, pin, pane1);
                    });
            return;
        }
        connectReady(profile, remember, pin, pane1);
    }

    private void connectReady(NetworkProfile profile, boolean remember, boolean pin, boolean pane1) {
        // SFTP: never trust an unseen host key silently. Probe it and ask the user first.
        if (profile.protocol.equals("sftp") && (profile.hostKey == null || profile.hostKey.trim().isEmpty())) {
            verifyHostKey(profile, remember, pin, pane1);
            return;
        }
        openConnection(profile, remember, pin, pane1);
    }

    private void verifyHostKey(NetworkProfile profile, boolean remember, boolean pin, boolean pane1) {
        java.net.URI uri = java.net.URI.create(profile.canonicalAddress());
        String rawHost = uri.getHost() == null ? "" : uri.getHost();
        final String host = rawHost.startsWith("[") && rawHost.endsWith("]")
                ? rawHost.substring(1, rawHost.length() - 1) : rawHost;
        final int port = uri.getPort() == -1 ? 22 : uri.getPort();
        final String endpoint = host + ":" + port;
        SftpClient.HostKeyInfo[] info = {null};
        runConnect(activity.getString(R.string.network_sftp_checking_host), R.string.network_sftp_checking_host,
                () -> info[0] = SftpClient.probeHostKey(host, port),
                () -> showHostKeyDialog(profile, endpoint, info[0].describe(), "", false, remember, pin, pane1),
                this::showError);
    }

    /** Shows the presented key; accepting pins it and continues the connection. */
    private void showHostKeyDialog(NetworkProfile profile, String endpoint, String detail, String pinned,
                                   boolean changed, boolean remember, boolean pin, boolean pane1) {
        if (closed || activity.isDestroyed()) return;
        int message = changed ? R.string.network_sftp_host_key_changed : R.string.network_sftp_host_key_new;
        activity.dialogUtil.getDialogBuilder().setTitle(R.string.network_sftp_host_key_title)
                .setMessage(activity.getString(message, endpoint, detail, pinned))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(changed ? R.string.network_sftp_host_key_update : R.string.network_sftp_host_key_trust,
                        (d, w) -> {
                            int sha = detail.indexOf("SHA256:");
                            if (sha >= 0) profile.hostKey = detail.substring(sha + 7);
                            openConnection(profile, remember, pin, pane1);
                        })
                .show();
    }

    private void openConnection(NetworkProfile profile, boolean remember, boolean pin, boolean pane1) {
        RemoteFile[] root = {null};
        runConnect(activity.getString(R.string.connecting_to, profile.name), R.string.network_transfer_safety, () -> {
            RemoteClient client = profile.connect();
            if (client instanceof SftpClient sftp) {
                // Keep the pinned key in sync with what the server actually presented.
                String fingerprint = sftp.hostKeyFingerprint();
                if (fingerprint != null && !fingerprint.isEmpty()) profile.hostKey = fingerprint;
            }
            try {
                RemoteEntry entry = client.stat("");
                if (entry == null || !entry.directory) throw new IOException("Connection root is not a folder");
                checkpoint();
                if (remember) persist(profile, pin);
                synchronized (clients) {
                    if (closed) throw new IOException("Connection closed");
                    clients.add(client);
                }
                RemoteFile.Connection connection = new RemoteFile.Connection(client,
                        profile.canonicalAddress(), profile.pinId(), profile.storageIdentity());
                profileByConnection.put(connection.id, profile);
                root[0] = RemoteFile.root(connection);
            } catch (Exception e) { client.close(); throw e; }
        }, () -> {
            activity.loadFolderInPane(root[0], pane1, true);
            if (remember) activity.refreshSidebarAsync(activity.getSidebarSectionOrder());
        }, failure -> {
            if (failure instanceof SftpClient.HostKeyChangedException changed && !activity.isDestroyed()) {
                // A changed key is a security event: show both fingerprints and require an explicit choice.
                String endpoint = changed.host + ":" + changed.port;
                showHostKeyDialog(profile, endpoint, "SHA256:" + changed.presented, "SHA256:" + changed.pinned, true, remember, pin, pane1);
            } else showError(failure);
        });
    }

    /** Like {@link #runOperation} but lets a failure be handled in place (e.g. a host-key prompt). */
    private void runConnect(String title, int message, Operation operation, Runnable onSuccess, Consumer<Exception> onFailure) {
        if (closed) return;
        Future<?>[] task = {null};
        AlertDialog progress = activity.dialogUtil.getDialogBuilder().setTitle(title)
                .setMessage(message).setView(new ProgressBar(activity))
                .setNegativeButton(android.R.string.cancel, (d, w) -> { if (task[0] != null) task[0].cancel(true); })
                .create();
        progress.setOnCancelListener(d -> { if (task[0] != null) task[0].cancel(true); });
        progress.show();
        task[0] = workers.submit(() -> {
            Exception failure = null;
            try { checkpoint(); operation.run(); checkpoint(); }
            catch (Exception e) { failure = e; }
            final Exception error = failure;
            activity.handler.post(() -> {
                if (closed || activity.isDestroyed()) return;
                progress.dismiss();
                if (task[0].isCancelled()) return;
                if (error != null) onFailure.accept(error);
                else if (onSuccess != null) onSuccess.run();
            });
        });
    }

    public RemoteSpace spaceForProfile(NetworkProfile profile) {
        RemoteSpace.Report report = spaceReports.get(profile.pinId());
        return report != null && report.identity().equals(profile.storageIdentity()) ? report.space() : null;
    }
    public boolean hasCheckedSpace(NetworkProfile profile) {
        RemoteSpace.Report report = spaceReports.get(profile.pinId());
        return report != null && report.identity().equals(profile.storageIdentity());
    }

    /** Refresh only live sessions, off-main and at most once a minute per connection. */
    public void refreshSpace(RemoteFile.Connection connection) {
        if (closed || connection.storageId == null) return;
        long now = SystemClock.elapsedRealtime();
        Long previous = spaceCheckTimes.putIfAbsent(connection.id, now);
        if (previous != null && (now - previous < 60_000 || !spaceCheckTimes.replace(connection.id, previous, now))) return;
        workers.execute(() -> {
            try {
                RemoteSpace space = connection.client.space();
                if (closed) return;
                spaceReports.put(connection.storageId, new RemoteSpace.Report(connection.storageIdentity, space));
                activity.handler.post(() -> {
                    if (!closed && !activity.isDestroyed()) activity.refreshSidebarAsync(activity.getSidebarSectionOrder());
                });
            } catch (Exception ignored) { /* Optional information must never break browsing. */ }
        });
    }

    @FunctionalInterface public interface Operation { void run() throws Exception; }

    public void runOperation(String title, Operation operation, Runnable onSuccess) {
        if (closed) return;
        Future<?>[] task = {null};
        AlertDialog progress = activity.dialogUtil.getDialogBuilder().setTitle(title)
                .setMessage(R.string.network_transfer_safety).setView(new ProgressBar(activity))
                .setNegativeButton(android.R.string.cancel, (d, w) -> { if (task[0] != null) task[0].cancel(true); })
                .create();
        progress.setOnCancelListener(d -> { if (task[0] != null) task[0].cancel(true); });
        progress.show();
        task[0] = workers.submit(() -> {
            Exception failure = null;
            try { checkpoint(); operation.run(); checkpoint(); }
            catch (Exception e) { failure = e; }
            final Exception error = failure;
            activity.handler.post(() -> {
                if (closed || activity.isDestroyed()) return;
                progress.dismiss();
                if (task[0].isCancelled()) return;
                if (error != null) showError(error);
                else if (onSuccess != null) onSuccess.run();
            });
        });
    }

    private void showError(Exception error) {
        activity.handler.post(() -> {
            if (!closed && !activity.isDestroyed()) new ErrorUtil(activity).showError(error);
        });
    }

    private static void checkpoint() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("Transfer cancelled");
    }

    public void create(RemoteFile folder, String name, boolean directory, boolean pane1) {
        runOperation(activity.getString(R.string.create), () -> {
            String path = RemotePath.child(folder.entry.path, name);
            if (folder.connection.client.stat(path) != null) throw new IOException("Destination already exists");
            if (directory) folder.connection.client.mkdir(path);
            else folder.connection.client.upload(path, new ByteArrayInputStream(new byte[0]), 0);
        }, () -> activity.loadFolderInPane(folder, pane1, false));
    }

    /** Called by the regular pane's existing copy/move worker, including SAF sources. */
    public void transferInto(List<Object> items, RemoteFile destination, boolean move,
                             FileUtils.TransferListener listener) throws IOException {
        try {
            for (Object item : items) {
                checkpoint();
                if (listener != null) listener.checkpoint();
                if (!(item instanceof File) || item instanceof FTPFileWrapper)
                    throw new IOException("Extract archive entries to a local folder before uploading");
            }
            // One session is one socket: a batch is only faster if several
            // connections push at the same time. The extra sessions are opened
            // here and closed when the batch ends; if the server refuses them we
            // simply run with fewer workers, down to the old serial behaviour.
            NetworkProfile profile = profileByConnection.get(destination.connection.id);
            int threads = ParallelTransfer.clamp(UiPrefs.getTransferThreads(activity));
            int helpers = profile == null ? 0
                    : Math.min(threads, Math.max(1, items.size())) - 1;
            List<RemoteClient> extra = helpers > 0
                    ? openTransferHelpers(profile, helpers) : Collections.emptyList();
            final List<RemoteClient> pool = new ArrayList<>(1 + extra.size());
            pool.add(destination.connection.client);
            pool.addAll(extra);
            final AtomicInteger next = new AtomicInteger();
            List<ParallelTransfer.Task> tasks = new ArrayList<>(items.size());
            for (Object item : items) {
                final File source = (File) item;
                tasks.add(() -> {
                    checkpoint();
                    if (listener != null) listener.checkpoint();
                    RemoteClient worker = pool.get(Math.floorMod(next.getAndIncrement(), pool.size()));
                    uploadSource(source, worker, destination.entry.path, listener);
                    checkpoint();
                    if (listener != null) listener.checkpoint();
                    if (move) deleteSource(source);
                });
            }
            try {
                ParallelTransfer.run(threads, tasks, null);
            } finally {
                closeHelpers(extra);
            }
        } finally { activity.handler.post(activity::refreshAllPanes); }
    }

    /**
     * Opens up to {@code wanted} additional sessions for one transfer.
     *
     * <p>A server that limits concurrent logins refuses the extra ones; a
     * failure here is not an error, it just means the batch runs on fewer
     * connections, which is exactly what it did before.
     */
    private List<RemoteClient> openTransferHelpers(NetworkProfile profile, int wanted) {
        List<RemoteClient> opened = new ArrayList<>(wanted);
        for (int i = 0; i < wanted; i++) {
            try {
                RemoteClient client = profile.connect();
                synchronized (clients) {
                    if (closed) {
                        client.close();
                        break;
                    }
                    clients.add(client);
                }
                opened.add(client);
            } catch (Exception e) {
                break;
            }
        }
        return opened;
    }

    /**
     * The connection itself plus as many helper sessions as the transfer
     * settings allow, for one download.
     */
    private List<RemoteClient> transferPool(RemoteFile source) {
        NetworkProfile profile = profileByConnection.get(source.connection.id);
        int threads = ParallelTransfer.clamp(UiPrefs.getTransferThreads(activity));
        List<RemoteClient> extra = profile == null || threads < 2
                ? Collections.emptyList()
                : openTransferHelpers(profile, threads - 1);
        List<RemoteClient> pool = new ArrayList<>(1 + extra.size());
        pool.add(source.connection.client);
        pool.addAll(extra);
        return pool;
    }

    private void closeHelpers(List<RemoteClient> helpers) {
        if (helpers == null || helpers.isEmpty()) return;
        synchronized (clients) {
            clients.removeAll(helpers);
        }
        for (RemoteClient client : helpers) {
            try {
                client.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void uploadSource(File source, RemoteClient destination, String parent,
                              FileUtils.TransferListener listener) throws IOException {
        checkpoint();
        if (listener != null) listener.checkpoint();
        if (!(source instanceof SafFile) && Files.isSymbolicLink(source.toPath()))
            throw new IOException("Symbolic links cannot be uploaded");
        String path = RemotePath.child(parent, source.getName());
        if (destination.stat(path) != null) throw new IOException("Destination already exists: " + source.getName());
        if (source.isDirectory()) {
            List<? extends File> children;
            if (source instanceof SafFile) children = SafFs.children((SafFile) source);
            else {
                File[] listed = source.listFiles();
                children = listed == null ? null : Arrays.asList(listed);
            }
            if (children == null) throw new IOException("Cannot read source folder: " + source.getName());
            destination.mkdir(path);
            for (File child : children) uploadSource(child, destination, path, listener);
        } else {
            if (listener != null) listener.onFile(source, new File("/network/" + path));
            try (InputStream input = RootStaging.openInputStream(activity, source)) {
                InputStream monitored = new FilterInputStream(input) {
                    @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                        if (listener != null) listener.checkpoint();
                        int count = super.read(buffer, offset, length);
                        if (count > 0 && listener != null) listener.onBytes(count);
                        return count;
                    }
                };
                // Provider metadata may not expose a reliable length: use chunked PUT.
                destination.upload(path, monitored, source instanceof SafFile ? -1 : source.length());
            }
        }
    }

    private void deleteSource(File source) throws IOException {
        if (source instanceof SafFile) {
            if (!SafFs.delete((SafFile) source)) throw new IOException("Uploaded, but could not delete source");
        } else if (!FileUtils.deleteTree(source, null)) throw new IOException("Uploaded, but could not delete source");
    }

    public void copyOut(RemoteFile source, boolean sourcePane1, boolean move) {
        File destination = sourcePane1 ? activity.pane2Folder : activity.pane1Folder;
        MainFilesArrayAdapter other = activity.paneFilesAdapter(!sourcePane1);
        RecyclerView opposite = activity.findViewById(sourcePane1 ? R.id.listViewPane2 : R.id.listViewPane1);
        boolean supported = opposite.getAdapter() instanceof MainFilesArrayAdapter
                || opposite.getAdapter() instanceof RemoteFilesArrayAdapter;
        runOperation(activity.getString(move ? R.string.move : android.R.string.copy), () -> {
            if (!supported || destination == null || destination instanceof FTPFileWrapper
                    || (other != null && other.isInZip))
                throw new IOException("Choose a destination folder, not an archive");
            if (destination instanceof RemoteFile remote && remote.connection.address.equals(source.connection.address)
                    && (remote.entry.path.equals(source.entry.path) || remote.entry.path.startsWith(source.entry.path + "/")))
                throw new IOException("Cannot copy a folder into itself");
            if (destination instanceof RemoteFile || destination instanceof SafFile) {
                File staging = makeStagingFolder();
                try {
                    File local = new File(staging, source.getName());
                    List<RemoteClient> pool = transferPool(source);
                    try {
                        RemoteTransfers.downloadTree(pool, source.entry, local, null);
                    } finally {
                        closeHelpers(pool.subList(1, pool.size()));
                    }
                    checkpoint();
                    if (destination instanceof RemoteFile remote) {
                        RemoteTransfers.upload(remote.connection.client, remote.entry.path, local);
                    } else {
                        List<SafFile> children = SafFs.children((SafFile) destination);
                        if (children == null) throw new IOException("Cannot read destination folder");
                        for (SafFile child : children) if (child.getName().equals(source.getName()))
                            throw new IOException("Destination already exists");
                        SafFs.copyFromRecursive(local, (SafFile) destination, null);
                    }
                } finally { FileUtils.deleteTree(staging, null); }
            } else {
                File target = new File(destination, source.getName());
                List<RemoteClient> pool = transferPool(source);
                try {
                    RemoteTransfers.downloadTree(pool, source.entry, target, null);
                } finally {
                    closeHelpers(pool.subList(1, pool.size()));
                }
            }
            checkpoint();
            if (move) source.connection.client.delete(source.entry.path, source.isDirectory());
        }, activity::refreshAllPanes);
    }

    public boolean canCopyOut(RemoteFile source, boolean sourcePane1) {
        File destination = sourcePane1 ? activity.pane2Folder : activity.pane1Folder;
        MainFilesArrayAdapter other = activity.paneFilesAdapter(!sourcePane1);
        if (destination == null || destination instanceof FTPFileWrapper
                || (other != null && other.isInZip)) return false;
        if (destination instanceof RemoteFile remote) {
            return !remote.connection.address.equals(source.connection.address)
                    || (!remote.entry.path.equals(source.entry.path) && !remote.entry.path.startsWith(source.entry.path + "/"));
        }
        return other != null;
    }

    private File makeStagingFolder() throws IOException {
        File staging = new File(activity.getCacheDir(), "network_" + UUID.randomUUID());
        if (!staging.mkdir()) throw new IOException("Cannot create download cache");
        return staging;
    }

    /** A downloaded copy is intentionally local; edits require explicitly copying it back. */
    public void open(RemoteFile source, Consumer<File> opener) {
        File[] downloaded = {null};
        runOperation(activity.getString(R.string.network_downloading), () -> {
            File staging = makeStagingFolder();
            try {
                downloaded[0] = new File(staging, source.getName());
                RemoteTransfers.download(source.connection.client, source.entry, downloaded[0]);
            } catch (Exception e) { FileUtils.deleteTree(staging, null); throw e; }
        }, () -> opener.accept(downloaded[0]));
    }

    public void close() {
        closed = true;
        pendingConnection = null;
        profileByConnection.clear();
        if (connections != null) connections.close();
        workers.shutdownNow();
        // Socket/logoff teardown must not block Android's UI thread.
        new Thread(() -> {
            synchronized (clients) {
                for (RemoteClient client : clients) try { client.close(); } catch (Exception ignored) {}
                clients.clear();
            }
        }, "network-close").start();
    }
}
