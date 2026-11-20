package io.github.abdurazaaqmohammed.util.io;

import java.io.EOFException;
import java.io.File;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Copies one large file by giving each worker a fixed range of it.
 *
 * <p>A whole-file copy is one byte stream, so the earlier multi-threading only
 * helped when there were several files in the batch. A single big file is the
 * case that does not: its bytes were still moved by one thread. This splits the
 * file into equal ranges, and each worker reads its own range from the source
 * channel and writes it at the same offset into the destination channel. No
 * worker touches another range, so the copy is exact and interruptible.
 *
 * <p>Ranges are capped at {@link #MIN_CHUNK}: past a few megabytes one
 * streaming reader already saturates the device storage, and a second worker
 * on the same channel only adds the cost of opening the destination.
 */
public final class ChunkedCopy {

    /** Below this size a single thread costs less than splitting. */
    public static final long MIN_SIZE = 8L * 1024 * 1024;

    /** Smallest range a worker should get; keeps ranges from drowning in setup. */
    public static final long MIN_CHUNK = 4L * 1024 * 1024;

    /** Buffer each worker reads its range with. */
    private static final int CHUNK_IO = 1024 * 1024;

    private ChunkedCopy() {}

    /** Whether splitting this file over {@code threads} workers can pay for itself. */
    public static boolean worthSplitting(long size, int threads) {
        return threads > 1 && size >= MIN_SIZE;
    }

    /**
     * Ranges of {@code size} bytes over {@code workers} workers, in pairs of
     * start/end. Workers are as even as possible and never shorter than
     * {@link #MIN_CHUNK} when the file is large enough.
     */
    public static long[] ranges(long size, int workers) {
        int n = (int) Math.max(2, Math.min(workers, size / MIN_CHUNK));
        n = Math.min(n, ParallelTransfer.MAX_THREADS);
        long[] ranges = new long[n * 2];
        long per = size / n;
        long start = 0L;
        for (int i = 0; i < n; i++) {
            long length = per + (i < size % n ? 1L : 0L);
            ranges[i * 2] = start;
            ranges[i * 2 + 1] = start + length;
            start += length;
        }
        return ranges;
    }

    /**
     * Copies {@code source} to {@code destination} with the file split over
     * {@code threads} workers. Every byte written is reported to the listener,
     * so the progress dialog still moves during one big file.
     */
    public static void copy(File source, File destination, int threads,
                            FileUtils.TransferListener listener) throws IOException {
        long size = source.length();
        if (!worthSplitting(size, threads)) {
            FileUtils.copyFile(source, destination, listener);
            return;
        }
        long[] ranges = ranges(size, threads);
        final FileChannel sourceChannel = FileChannel.open(source.toPath(), StandardOpenOption.READ);
        final FileChannel destinationChannel;
        try {
            destinationChannel = FileChannel.open(destination.toPath(),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            closeQuietly(sourceChannel);
            throw e;
        }
        try {
            // Reserve the space up front so a range that starts after another
            // worker's still lands on a correctly sized file.
            destinationChannel.truncate(0L);
            List<ParallelTransfer.Task> tasks = new ArrayList<>(ranges.length / 2);
            for (int i = 0; i < ranges.length / 2; i++) {
                final long start = ranges[i * 2];
                final long end = ranges[i * 2 + 1];
                tasks.add(() -> copyRange(sourceChannel, destinationChannel, start, end, listener));
            }
            ParallelTransfer.run(threads, tasks, null);
            if (destinationChannel.size() != size)
                throw new IOException("Copy size mismatch or source changed during copy");
            destinationChannel.force(true);
        } catch (IOException | TransferCancelledException e) {
            // Do not leave a truncated file that the caller reads as success.
            destination.delete();
            throw e;
        } finally {
            closeQuietly(sourceChannel);
            closeQuietly(destinationChannel);
        }
    }

    private static void copyRange(FileChannel source, FileChannel destination, long start, long end,
                                  FileUtils.TransferListener listener) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(CHUNK_IO);
        long copied = start;
        while (copied < end) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("Transfer cancelled");
            if (listener != null) listener.checkpoint();
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), end - copied));
            int read = source.read(buffer, copied);
            if (read < 0) throw new EOFException("Source ended before its range was copied");
            if (read == 0) throw new IOException("Source read made no progress during copy");
            buffer.flip();
            while (buffer.hasRemaining()) {
                if (listener != null) listener.checkpoint();
                int written = destination.write(buffer, copied);
                if (written <= 0) throw new IOException("Destination write made no progress during copy");
                copied += written;
                if (listener != null) listener.onBytes(written);
            }
        }
    }

    private static void closeQuietly(FileChannel channel) {
        if (channel == null) return;
        try { channel.close(); } catch (IOException ignored) {}
    }
}
