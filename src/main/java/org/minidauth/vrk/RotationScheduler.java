package org.minidauth.vrk;

import org.midgard.models.WalletLifecycleState;
import org.minidauth.Log;
import org.minidauth.store.VendorKeyStore;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Drives the rotation switch on a timer.
 *
 * <p>A port of TideCloak's {@code SwitchToNextVRKTask} and {@code ScheduleNextSwitchTask}. Each run
 * is one-shot: it re-arms itself on failure (15 minutes later, within the grace window) and is
 * re-armed at the next billing boundary by a successful switch.
 */
public final class RotationScheduler implements AutoCloseable {
    private static final Log log = Log.of(RotationScheduler.class);

    /** How long to wait before retrying a switch that did not take. */
    private static final Duration RETRY_INTERVAL = Duration.ofMinutes(15);

    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "vrk-rotation");
                t.setDaemon(true);
                return t;
            });

    private final VrkLifecycle lifecycle;
    private final VendorKeyStore store;
    private ScheduledFuture<?> pending;

    public RotationScheduler(VrkLifecycle lifecycle) {
        this.lifecycle = lifecycle;
        this.store = lifecycle.store();
    }

    /**
     * Re-arm after a restart. The timer is in-memory only, so a process that boots with an already
     * created vendor key has to reschedule the switch the last run had planned, derived from the
     * same expiry, so a boot mid-cycle lands on the original boundary rather than shifting it.
     */
    public synchronized void rearm() {
        if (store.vendorKeyState() != VendorKeyState.Created) {
            log.info("Vendor key not created yet; rotation timer not armed");
            return;
        }
        Instant runAt = lifecycle.nextSwitchAt();
        if (runAt == null) {
            log.warn("No expiry on the active VRK, cannot arm the rotation timer");
            return;
        }
        scheduleAt(Duration.between(Instant.now(), runAt));
    }

    /** (Re)schedule the switch, replacing any existing schedule rather than stacking a second. */
    public synchronized void scheduleAt(Duration fromNow) {
        if (pending != null) pending.cancel(false);
        long delayMs = Math.max(1_000L, fromNow.toMillis());
        pending = executor.schedule(this::run, delayMs, TimeUnit.MILLISECONDS);
        log.info("Rotation switch scheduled in %d ms (at %s)", delayMs, Instant.now().plusMillis(delayMs));
    }

    /** Run the switch now, off the timer thread's schedule. Exposed for the manual endpoint. */
    public synchronized void runNow() {
        scheduleAt(Duration.ZERO);
    }

    private void run() {
        boolean switched = false;
        try {
            LicenseState licenseState = store.licenseState();
            switch (licenseState) {
                case NotCreated -> throw new IllegalStateException("Initial VRK not created yet");
                case NotCreated_AwaitingPayment -> throw new IllegalStateException("Initial VRK not paid yet");
                case Active, Active_NeedsAttention -> switched = attemptSwitch();
                default -> throw new IllegalStateException("Unknown license state " + licenseState);
            }
        } catch (Exception e) {
            store.logRotationError(e);
        } finally {
            if (!switched) {
                // Retry inside the grace window, while the current key is still valid.
                scheduleAt(RETRY_INTERVAL);
            }
        }
    }

    private boolean attemptSwitch() {
        try {
            WalletLifecycleState walletState = lifecycle.pendingWalletState();

            if (walletState.Status != WalletLifecycleState.StatusType.OK) {
                if (walletState.Status == WalletLifecycleState.StatusType.NO_CUSTOMER
                        || walletState.Status == WalletLifecycleState.StatusType.NO_SUBSCRIPTION) {
                    store.logRotationError("No billing customer or subscription was found for this vendor key. "
                            + "Rotation cannot proceed until billing is restored.");
                    return false;
                }
                throw new IllegalStateException("Could not determine wallet state. Status: " + walletState.Status);
            }

            if (walletState.WalletState != WalletLifecycleState.WalletStateType.ACTIVE) {
                store.logRotationError("The Tide network has not received payment for the next wallet yet. "
                        + "Keep billing up to date to avoid disruption.");
                return false;
            }

            return lifecycle.trySwitchToNextVRK();
        } catch (Exception e) {
            store.logRotationError(e);
            return false;
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
