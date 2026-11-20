package io.github.abdurazaaqmohammed.feature.files.network;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.github.abdurazaaqmohammed.util.io.ChunkedCopy;
import io.github.abdurazaaqmohammed.util.io.FileUtils;
import io.github.abdurazaaqmohammed.util.io.ParallelTransfer;

/** Recursive transfers with fail-on-conflict and delete-source-only-after-success semantics. */
public final class RemoteTransfers {
    private RemoteTransfers() {}

    public static void download(RemoteClient source, RemoteEntry entry, File destination) throws IOException {
        downloadTree(Collections.singletonList(source), entry, destination, null);
    }

    /**
     * Downloads a tree, spreading the leaf files over the supplied connections.
     *
     * <p>A single FTP/SFTP/WebDAV session is one socket, so a directory of many
     * files only gets faster if several sessions pull at once — this is the
     * remote half of the multi-threaded transfer. The folder structure is
     * created up front on this thread (it is metadata only), then every file is
     * fetched by whichever connection is free.
     */
    public static void downloadTree(List<RemoteClient> connections, RemoteEntry root, File destination,
                                    FileUtils.TransferListener listener) throws IOException {
        if (connections == null || connections.isEmpty()) throw new IOException("No connection");
        if (destination.exists()) throw new IOException("Destination already exists: " + destination.getName());
        List<RemoteEntry> files = new ArrayList<>();
        List<File> targets = new ArrayList<>();
        collect(connections.get(0), root, destination, files, targets, listener);
        if (files.isEmpty()) return;

        // A single large file is not a list: splitting it by byte range is the
        // only way several sessions help, and it needs a server that supports ranges.
        if (files.size() == 1 && connections.get(0).supportsRanges()
                && ChunkedCopy.worthSplitting(files.get(0).size, connections.size())) {
            downloadChunked(connections, files.get(0), targets.get(0), listener);
            return;
        }

        final AtomicInteger next = new AtomicInteger();
        List<ParallelTransfer.Task> tasks = new ArrayList<>(files.size());
        for (int i = 0; i < files.size(); i++) {
            final RemoteEntry entry = files.get(i);
            final File target = targets.get(i);
            tasks.add(() -> {
                RemoteClient worker = connections.get(Math.floorMod(next.getAndIncrement(), connections.size()));
                downloadFile(worker, entry, target, listener);
            });
        }
        ParallelTransfer.run(Math.min(connections.size(), files.size()), tasks, null);
    }

    /** Creates folders and records every leaf, so the parallel phase is pure byte movement. */
    private static void collect(RemoteClient source, RemoteEntry entry, File destination,
                                List<RemoteEntry> files, List<File> targets,
                                FileUtils.TransferListener listener) throws IOException {
        if (listener != null) listener.checkpoint();
        if (entry.directory) {
            if (!destination.mkdir() && !destination.isDirectory())
                throw new IOException("Cannot create destination folder");
            for (RemoteEntry child : source.list(entry.path)) {
                requireChild(entry.path, child);
                collect(source, child, new File(destination, child.name()), files, targets, listener);
            }
        } else {
            files.add(entry);
            targets.add(destination);
        }
    }

    private static void downloadFile(RemoteClient source, RemoteEntry entry, File destination,
                                     FileUtils.TransferListener listener) throws IOException {
        if (destination.exists()) throw new IOException("Destination already exists: " + destination.getName());
        if (listener != null) {
            listener.checkpoint();
            listener.onFile(new File("/network/" + entry.path), destination);
        }
        File temporary = File.createTempFile(".mp-download-", ".part", destination.getParentFile());
        try {
            try (FileOutputStream output = new FileOutputStream(temporary)) {
                source.download(entry.path, output);
                output.getFD().sync();
            }
            if (entry.size > 0 && temporary.length() != entry.size)
                throw new IOException("Downloaded size does not match; source may have changed");
            Files.move(temporary.toPath(), destination.toPath());
        } finally {
            //noinspection ResultOfMethodCallIgnored
            temporary.delete();
        }
        if (entry.modified > 0) destination.setLastModified(entry.modified);
    }

    /** One large file, one reserved range per connection, written in parallel. */
    private static void downloadChunked(List<RemoteClient> connections, RemoteEntry entry, File destination,
                                        FileUtils.TransferListener listener) throws IOException {
        if (destination.exists()) throw new IOException("Destination already exists: " + destination.getName());
        if (listener != null) {
            listener.checkpoint();
            listener.onFile(new File("/network/" + entry.path), destination);
        }
        long size = entry.size;
        long[] ranges = ChunkedCopy.ranges(size, connections.size());
        File temporary = File.createTempFile(".mp-download-", ".part", destination.getParentFile());
        try {
            final AtomicInteger next = new AtomicInteger();
            List<ParallelTransfer.Task> tasks = new ArrayList<>(ranges.length / 2);
            for (int i = 0; i < ranges.length; i += 2) {
                final long start = ranges[i];
                final long length = ranges[i + 1] - ranges[i];
                tasks.add(() -> {
                    if (listener != null) listener.checkpoint();
                    RemoteClient worker = connections.get(Math.floorMod(next.getAndIncrement(), connections.size()));
                    try (RandomAccessFile output = new RandomAccessFile(temporary, "rw")) {
                        worker.downloadRange(entry.path, start, length, new RangedFileOutput(output, start));
                    }
                });
            }
            ParallelTransfer.run(Math.min(connections.size(), tasks.size()), tasks, null);
            try (RandomAccessFile output = new RandomAccessFile(temporary, "r")) {
                output.getFD().sync();
                if (output.length() != size)
                    throw new IOException("Downloaded size does not match; source may have changed");
            }
            Files.move(temporary.toPath(), destination.toPath());
        } finally {
            //noinspection ResultOfMethodCallIgnored
            temporary.delete();
        }
        if (entry.modified > 0) destination.setLastModified(entry.modified);
    }

    /** Writes into one file at a fixed offset, so ranged workers never move the cursor. */
    private static final class RangedFileOutput extends OutputStream {
        private final RandomAccessFile file;
        private final long start;
        private long sent;

        RangedFileOutput(RandomAccessFile file, long start) {
            this.file = file;
            this.start = start;
        }

        @Override public void write(int b) throws IOException {
            byte[] one = {(byte) b};
            write(one, 0, 1);
        }

        @Override public void write(byte[] buffer, int offset, int length) throws IOException {
            file.seek(start + sent);
            file.write(buffer, offset, length);
            sent += length;
        }
    }

    public static void upload(RemoteClient destination, String parent, File source) throws IOException {
        if (Files.isSymbolicLink(source.toPath())) throw new IOException("Symbolic links cannot be uploaded");
        String path = RemotePath.child(parent, source.getName());
        if (destination.stat(path) != null) throw new IOException("Destination already exists: " + source.getName());
        if (source.isDirectory()) {
            File[] children = source.listFiles();
            if (children == null) throw new IOException("Cannot read source folder");
            destination.mkdir(path);
            for (File child : children) upload(destination, path, child);
        } else {
            try (FileInputStream input = new FileInputStream(source)) {
                destination.upload(path, input, source.length());
            }
        }
    }

    public static void moveToLocal(RemoteClient source, RemoteEntry entry, File destination) throws IOException {
        download(source, entry, destination);
        source.delete(entry.path, entry.directory);
    }

    static void requireChild(String directory, RemoteEntry child) throws IOException {
        if (child.path.equals(directory) || !RemotePath.parent(child.path).equals(directory))
            throw new IOException("Server returned a child outside the requested directory");
        RemotePath.validateName(child.name());
    }
}
