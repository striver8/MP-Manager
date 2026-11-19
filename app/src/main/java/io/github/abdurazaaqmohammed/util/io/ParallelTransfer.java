package io.github.abdurazaaqmohammed.util.io;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs independent copy tasks on a small fixed pool.
 *
 * <p>A batch of files is a set of unrelated byte streams: one worker can own
 * one file while another owns the next, which is the transfer model MT Manager
 * exposes as "multi-threaded copy". Serially the batch pays every per-file
 * latency (open, close, fsync, FUSE round trips) end to end; with four workers
 * those latencies overlap instead of adding up.
 *
 * <p>Semantics are the serial ones the callers already had: the first real
 * failure stops the batch, cancelling the dialog unwinds every worker through
 * {@link TransferControl#checkpoint()}, and an interrupted pool never leaves a
 * thread behind.
 */
public final class ParallelTransfer {

    public static final int MIN_THREADS = 1;
    public static final int MAX_THREADS = 8;
    public static final int DEFAULT_THREADS = 4;

    /** One unit of independent work; usually the copy of one file or folder. */
    public interface Task {
        void run() throws Exception;
    }

    private ParallelTransfer() {
    }

    public static int clamp(int threads) {
        return Math.max(MIN_THREADS, Math.min(MAX_THREADS, threads));
    }

    /**
     * Runs every task, keeping at most {@code threads} in flight.
     *
     * <p>With one thread (or a single task) this is a plain loop, so the setting
     * at 1 behaves exactly like the code before this class existed.
     */
    public static void run(int threads, List<Task> tasks, TransferControl control) throws IOException {
        if (tasks == null || tasks.isEmpty()) return;
        int workers = clamp(threads);
        if (workers <= 1 || tasks.size() == 1) {
            for (Task task : tasks) {
                if (control != null) control.checkpoint();
                try {
                    task.run();
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException(e);
                }
            }
            return;
        }

        final AtomicInteger named = new AtomicInteger();
        ThreadFactory factory = r -> {
            Thread thread = new Thread(r, "mp-transfer-" + named.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(workers, tasks.size()), factory);
        final Object failureLock = new Object();
        final Throwable[] first = new Throwable[1];
        final AtomicBoolean stop = new AtomicBoolean();
        List<Future<?>> futures = new ArrayList<>(tasks.size());
        try {
            for (Task task : tasks) {
                futures.add(pool.submit(() -> {
                    if (stop.get() && first[0] != null) return null;
                    // A pause parks this worker; a cancel unwinds it.
                    if (control != null) control.checkpoint();
                    try {
                        task.run();
                    } catch (Throwable t) {
                        synchronized (failureLock) {
                            if (first[0] == null) first[0] = t;
                        }
                        stop.set(true);
                        // The pool needs a checked exception here; the real
                        // cause is kept in first[0] and rethrown below.
                        throw t instanceof Exception ? (Exception) t : new IllegalStateException(t);
                    }
                    return null;
                }));
            }
            pool.shutdown();
            boolean interrupted = false;
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (ExecutionException ignored) {
                    // The cause is already recorded in first[0].
                } catch (InterruptedException e) {
                    interrupted = true;
                    break;
                }
            }
            if (interrupted) Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }

        Throwable failure = first[0];
        if (failure == null) return;
        if (failure instanceof RuntimeException) throw (RuntimeException) failure;
        if (failure instanceof IOException) throw (IOException) failure;
        if (failure instanceof Exception) throw new IOException(failure);
        throw new IOException(failure);
    }
}
