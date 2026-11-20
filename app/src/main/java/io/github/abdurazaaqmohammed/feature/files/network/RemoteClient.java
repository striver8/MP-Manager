package io.github.abdurazaaqmohammed.feature.files.network;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/** Blocking API: callers must use a worker thread. Streams remain caller-owned. */
public interface RemoteClient extends Closeable {
    List<RemoteEntry> list(String directory) throws IOException;
    /** Returns null only for a missing resource; authentication/errors must throw. */
    RemoteEntry stat(String path) throws IOException;
    void download(String path, OutputStream destination) throws IOException;
    /** Creates a new file. Existing destinations are never silently overwritten. */
    void upload(String path, InputStream source, long size) throws IOException;
    void mkdir(String path) throws IOException;
    void rename(String path, String destination) throws IOException;
    void delete(String path, boolean directory) throws IOException;
    /** Optional quota/volume information. Unsupported servers return null. */
    default RemoteSpace space() throws IOException { return null; }

    /**
     * True when this server can read and write byte ranges, so one large file can
     * be moved by several workers at once.
     */
    default boolean supportsRanges() { return false; }

    /** Reads the remote range {@code [offset, offset + length)} into the stream. */
    default void downloadRange(String path, long offset, long length, OutputStream destination)
            throws IOException {
        throw new IOException("Ranged downloads are not supported by this server");
    }

    /**
     * Creates {@code path} reserved at exactly {@code size} bytes. Workers then
     * fill their own ranges with {@link #uploadRange}.
     */
    default void createReserved(String path, long size) throws IOException {
        upload(path, new java.io.ByteArrayInputStream(new byte[0]), 0);
    }

    /**
     * Writes {@code length} bytes read from {@code source} at remote offset
     * {@code offset}. The stream is expected to start exactly at that range; the
     * offset only tells the server where to put the bytes.
     */
    default void uploadRange(InputStream source, long offset, long length, String path) throws IOException {
        throw new IOException("Ranged uploads are not supported by this server");
    }
}
