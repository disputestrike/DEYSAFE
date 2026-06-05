"""Background ingest scheduler — turns the manual RSS pull into a real pipeline (DATA-01).

The audit register (FEEDBACK §I / DATA-01) flags that DeySafe has *no real-time
data pipeline*: live-signal ingestion only happens when an operator clicks
`/api/ingest-live`. This module is the missing periodic worker — a single daemon
thread that calls a caller-supplied ingest function every N minutes, so fresh
public-news signals keep flowing without a human in the loop.

DESIGN RULES (mirror response.py / reputation.py / metrics.py)
  - STDLIB ONLY. Pure `threading` (Timer-free loop on an Event) + datetime. No new
    deps, no pip, no framework. Safe to import anywhere.
  - DEFAULT OFF. The interval comes from env DEYSAFE_INGEST_MINUTES and defaults to
    0, which means "never start". With the default, importing this module and even
    calling start() is a no-op: no thread, no network, nothing non-deterministic.
    That is deliberate so validate.py / validate_security.py and any unit test stay
    fully deterministic and never reach out to the internet. A scheduler only runs
    when an operator explicitly opts in by setting the env var to a positive number.
  - ZERO COUPLING to api.py. start() takes a *callback* the caller provides (api.py
    will pass a closure that runs its shared `_ingest_live_once(db)` + recompute()).
    This module never imports ingest/db/api, never knows what "a pull" does, and
    never touches the network itself — it only decides *when* to call back. That
    keeps the file independently testable (the self-test passes a trivial counter
    callback) and keeps ownership clean (this file owns scheduling; api.py owns the
    ingest body).
  - FAIL-SOFT. A callback that raises is caught, recorded as a source-health error,
    and the loop keeps going — one bad pull (e.g. a feed timeout) must never kill
    the worker. The error is surfaced via health(), not swallowed silently.

BRIGHT LINES
  - This is a *timer*, not a decision-maker. It never verifies, escalates, alerts,
    dispatches, or writes anything itself — it only invokes the callback the
    operator wired. All bright-line policy stays in the code that callback runs.

USAGE (from api.py::main(), behind the env flag)
    import scheduler
    sched = scheduler.IngestScheduler(lambda: _ingest_live_once(DB(DB_PATH)),
                                      name="ingest")
    sched.start()          # no-op unless DEYSAFE_INGEST_MINUTES > 0
    ...                    # server runs
    sched.stop()           # on shutdown (daemon thread also dies with the process)

Source-health timestamps (for a future operator health panel / metrics) are kept
in-process and exposed via .health(): when the worker last ran, last succeeded,
last failed (+ the error), and how many times each.
"""
import os
import threading
import datetime


# ---------------------------------------------------------------------------
# 0. Config — interval is env-driven and OFF by default
# ---------------------------------------------------------------------------
# The one knob: how many minutes between pulls. 0 (the default) disables the
# scheduler entirely. The audit asks for "every 15-30 min" in production; the
# operator sets that explicitly. Anything <= 0 or unparseable -> OFF (0).
INTERVAL_ENV = "DEYSAFE_INGEST_MINUTES"
DEFAULT_MINUTES = 0          # OFF: tests/gates never start a thread or hit network

# Floor on the poll loop's wake granularity (seconds). The loop waits on an Event
# with this timeout so stop() is responsive even when the configured interval is
# long — we don't sleep for 20 minutes straight and then notice the stop flag.
_TICK_SECONDS = 1.0


def configured_minutes(env=None):
    """Resolve the configured interval in minutes from the environment.

    Reads DEYSAFE_INGEST_MINUTES (live, at call time, like broadcast.sim_enabled)
    and returns an int >= 0. A missing / empty / non-numeric / negative value all
    resolve to DEFAULT_MINUTES (0 = OFF), so a typo can never accidentally start a
    runaway pull loop — the failure mode is "stays off", never "spins".
    `env` is injectable for tests; defaults to os.environ.
    """
    raw = (env if env is not None else os.environ).get(INTERVAL_ENV, "")
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_MINUTES
    return n if n > 0 else DEFAULT_MINUTES


def enabled(env=None):
    """True when the scheduler is configured to run (interval > 0)."""
    return configured_minutes(env) > 0


def _now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# 1. The scheduler
# ---------------------------------------------------------------------------
class IngestScheduler:
    """A daemon thread that calls `callback` every configured-interval minutes.

    The callback takes no arguments and its return value is ignored (api.py will
    bind the db handle in a closure). Any exception it raises is caught and
    recorded; the loop continues. Construction never starts anything — call
    start(), which itself is a no-op unless the interval env is > 0.

    Lifecycle is idempotent and thread-safe: start()/stop() may be called more
    than once; a second start() while already running is ignored.
    """

    def __init__(self, callback, name="ingest", minutes=None, run_on_start=False):
        """
        callback     zero-arg callable performing one ingest pass. Required and
                     must be callable (asserted up front so a wiring mistake fails
                     loudly at construction, not silently at the first tick).
        name         label for the thread / health output (e.g. "ingest").
        minutes      override the interval (mainly for tests). When None, the
                     env value (DEYSAFE_INGEST_MINUTES) is read live at start().
        run_on_start when True, fire one pass immediately on start() instead of
                     waiting a full interval first. Default False so production
                     startup isn't blocked on a network pull.
        """
        assert callable(callback), "IngestScheduler needs a zero-arg callback"
        self._callback = callback
        self.name = name
        self._minutes_override = minutes
        self._run_on_start = run_on_start

        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        # --- source-health / observability (in-process; durable log is the db) ---
        self.started_at = None
        self.last_run_at = None        # last time a pass was attempted
        self.last_success_at = None    # last time a pass returned without raising
        self.last_error_at = None      # last time a pass raised
        self.last_error = None         # repr() of that exception (truncated)
        self.run_count = 0             # total passes attempted
        self.success_count = 0
        self.error_count = 0

    # -- introspection --------------------------------------------------------
    def interval_minutes(self):
        """Effective interval: explicit override if given, else the env value.

        A given override is kept as-is when positive (so tests can inject a
        sub-minute float); any non-positive override floors to OFF. The env path
        only ever yields whole-minute ints (configured_minutes()).
        """
        if self._minutes_override is not None:
            m = float(self._minutes_override)
            return m if m > 0 else DEFAULT_MINUTES
        return configured_minutes()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    # -- lifecycle ------------------------------------------------------------
    def start(self):
        """Start the worker thread if (a) an interval is configured (>0) and
        (b) it isn't already running. Returns True if a thread was started, else
        False (the common, default case — OFF). Safe to call repeatedly.
        """
        minutes = self.interval_minutes()
        if minutes <= 0:
            # OFF by configuration: the deliberate default. No thread, no network.
            return False
        with self._lock:
            if self.is_running():
                return False
            self._stop.clear()
            self.started_at = _now_iso()
            t = threading.Thread(target=self._loop, args=(minutes,),
                                 name="deysafe-sched-%s" % self.name, daemon=True)
            self._thread = t
            t.start()
            return True

    def stop(self, timeout=5.0):
        """Signal the worker to stop and join it (best-effort within `timeout`).

        Idempotent: a no-op when not running. The thread is a daemon, so even if
        a join times out the process can still exit; the join is courtesy so a
        clean shutdown waits for an in-flight tick to settle.
        """
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout)
        self._thread = None

    def wait(self, timeout=None):
        """Block until the worker stops (or `timeout` seconds elapse). Returns
        True if it stopped. Convenience for a foreground run / the self-test."""
        t = self._thread
        if t is None:
            return True
        t.join(timeout=timeout)
        return not t.is_alive()

    # -- the loop (runs on the daemon thread) ---------------------------------
    def _loop(self, minutes):
        """Run `callback` every `minutes`, waking every _TICK_SECONDS so stop() is
        responsive. Optionally fires once immediately when run_on_start=True.

        The wait() returns True the instant stop is set, so we break promptly; an
        in-flight callback always completes before the thread exits.
        """
        interval_seconds = minutes * 60.0
        # Time of the next scheduled pass. If run_on_start, due now; else one
        # interval out so we don't pull the moment the server boots.
        next_due = 0.0 if self._run_on_start else interval_seconds
        elapsed = 0.0
        while not self._stop.is_set():
            # Sleep in small slices so a long interval still stops quickly.
            if self._stop.wait(timeout=_TICK_SECONDS):
                break
            elapsed += _TICK_SECONDS
            if elapsed >= next_due:
                self._run_once()
                # Schedule the next pass a full interval after this one.
                elapsed = 0.0
                next_due = interval_seconds

    def _run_once(self):
        """Invoke the callback once, recording source-health. Never raises."""
        self.last_run_at = _now_iso()
        self.run_count += 1
        try:
            self._callback()
        except Exception as e:  # fail-soft: one bad pull must not kill the worker
            self.error_count += 1
            self.last_error_at = self.last_run_at
            self.last_error = repr(e)[:300]
            return False
        self.success_count += 1
        self.last_success_at = self.last_run_at
        # A clean run clears the stale error marker so health() reflects recovery.
        self.last_error = None
        return True

    # -- health ---------------------------------------------------------------
    def health(self):
        """Source-health snapshot for an operator panel / metrics (plain dict).

        Pure read of the in-process counters/timestamps; safe to call from any
        thread. `enabled` reflects the *current* config, `running` the live thread
        state — they can differ (e.g. configured but stop()'d, or running with a
        since-changed env).
        """
        return {
            "name": self.name,
            "enabled": self.interval_minutes() > 0,
            "running": self.is_running(),
            "interval_minutes": self.interval_minutes(),
            "started_at": self.started_at,
            "last_run_at": self.last_run_at,
            "last_success_at": self.last_success_at,
            "last_error_at": self.last_error_at,
            "last_error": self.last_error,
            "run_count": self.run_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
        }


# ---------------------------------------------------------------------------
# 2. Module-level convenience (a single optional shared scheduler)
# ---------------------------------------------------------------------------
# api.py can either construct its own IngestScheduler or use this one-liner. The
# singleton keeps a process to ONE ingest worker even if start_default() is called
# from more than one place (idempotent start()).
_default = None
_default_lock = threading.Lock()


def start_default(callback, name="ingest", minutes=None, run_on_start=False):
    """Create (once) and start the process-wide scheduler with `callback`.

    No-op-but-safe when DEYSAFE_INGEST_MINUTES isn't set (>0): returns the
    scheduler object whose .start() returned False, so callers can still inspect
    .health(). Subsequent calls reuse the same instance (the first callback wins).
    Returns the IngestScheduler.
    """
    global _default
    with _default_lock:
        if _default is None:
            _default = IngestScheduler(callback, name=name, minutes=minutes,
                                       run_on_start=run_on_start)
    _default.start()
    return _default


def stop_default(timeout=5.0):
    """Stop the process-wide scheduler if one was started. Safe always."""
    if _default is not None:
        _default.stop(timeout=timeout)


def default_health():
    """Health of the process-wide scheduler, or None if never created."""
    return _default.health() if _default is not None else None


# ===========================================================================
# 3. SELF-TEST  (python engine/scheduler.py)
# ===========================================================================
# Runs with a FAST interval and a trivial in-process callback — NO network, NO
# db, NO api import. Proves: default-OFF, env parsing, start/tick/stop, fail-soft
# on a raising callback, and the health snapshot. Deterministic and quick.
if __name__ == "__main__":
    import time

    # --- A. config parsing: default OFF, robust to junk ----------------------
    assert configured_minutes({}) == 0, "absent env -> OFF"
    assert configured_minutes({INTERVAL_ENV: ""}) == 0, "empty -> OFF"
    assert configured_minutes({INTERVAL_ENV: "0"}) == 0, "zero -> OFF"
    assert configured_minutes({INTERVAL_ENV: "-5"}) == 0, "negative -> OFF"
    assert configured_minutes({INTERVAL_ENV: "abc"}) == 0, "garbage -> OFF"
    assert configured_minutes({INTERVAL_ENV: "20"}) == 20, "positive -> that value"
    assert configured_minutes({INTERVAL_ENV: " 15 "}) == 15, "whitespace tolerated"
    assert enabled({INTERVAL_ENV: "15"}) is True
    assert enabled({}) is False

    # --- B. DEFAULT OFF: start() with no override + no env does nothing -------
    # (the env is not set in this self-test process, so this models a gate run)
    hits = {"n": 0}
    off = IngestScheduler(lambda: hits.__setitem__("n", hits["n"] + 1), name="off")
    assert off.start() is False, "must NOT start when interval is 0 (default OFF)"
    assert off.is_running() is False and hits["n"] == 0, "no thread, no callback"
    assert off.health()["enabled"] is False and off.health()["running"] is False

    # --- C. explicit override actually runs + ticks --------------------------
    # Smallest positive interval is 1 minute via env, but tests inject minutes via
    # a tiny override. We also shrink the tick so the test is sub-second.
    import scheduler as _self  # the module under test (for the tick monkeypatch)
    _self._TICK_SECONDS = 0.02   # speed the loop way up for the test only

    calls = {"n": 0}

    def _cb():
        calls["n"] += 1

    # Tiny sub-minute interval (0.02s expressed in minutes) so the test is fast;
    # with run_on_start it fires immediately, then again each interval after.
    sch = IngestScheduler(_cb, name="fast", minutes=0.02 / 60.0, run_on_start=True)
    assert sch.interval_minutes() > 0, "positive fractional override stays enabled"
    assert sch.start() is True, "must start with a positive override"
    assert sch.is_running() is True

    # wait for at least one successful pass (run_on_start => near-immediate)
    deadline = time.time() + 3.0
    while calls["n"] < 1 and time.time() < deadline:
        time.sleep(0.02)
    assert calls["n"] >= 1, "callback should have fired at least once"

    h = sch.health()
    assert h["running"] is True and h["run_count"] >= 1 and h["success_count"] >= 1
    assert h["error_count"] == 0 and h["last_error"] is None
    assert h["last_success_at"] is not None

    # idempotent start while running is a no-op
    assert sch.start() is False, "second start() while running -> False"

    sch.stop()
    assert sch.is_running() is False, "stop() must join the thread"
    n_after_stop = calls["n"]
    time.sleep(0.2)
    assert calls["n"] == n_after_stop, "no callbacks after stop()"

    # --- D. fail-soft: a raising callback is recorded, loop survives ---------
    boom = {"n": 0}

    def _bad():
        boom["n"] += 1
        raise RuntimeError("feed timeout")

    bad = IngestScheduler(_bad, name="bad", run_on_start=True)
    bad._minutes_override = 0.02 / 60.0
    assert bad.start() is True
    deadline = time.time() + 3.0
    while boom["n"] < 2 and time.time() < deadline:
        time.sleep(0.02)
    bad.stop()
    bh = bad.health()
    # it kept going past the first exception (>=2 attempts) and recorded the error
    assert boom["n"] >= 2, "loop must survive a raising callback"
    assert bh["error_count"] >= 1 and bh["success_count"] == 0
    assert bh["last_error"] and "feed timeout" in bh["last_error"]
    assert bh["last_error_at"] is not None

    # --- E. recovery clears the stale error marker ---------------------------
    flip = {"n": 0}

    def _flaky():
        flip["n"] += 1
        if flip["n"] == 1:
            raise ValueError("first one fails")
        # subsequent passes succeed

    flaky = IngestScheduler(_flaky, name="flaky", run_on_start=True)
    flaky._minutes_override = 0.02 / 60.0
    flaky.start()
    deadline = time.time() + 3.0
    while flip["n"] < 2 and time.time() < deadline:
        time.sleep(0.02)
    flaky.stop()
    fh = flaky.health()
    assert fh["error_count"] >= 1 and fh["success_count"] >= 1
    assert fh["last_error"] is None, "a later clean run clears the error marker"

    # --- F. module-level singleton convenience -------------------------------
    assert default_health() is None, "no default scheduler created yet"
    # default with no env -> OFF, but returns an inspectable object
    d = start_default(lambda: None, name="default-off")
    assert d.is_running() is False and default_health()["running"] is False
    stop_default()

    # restore the tick constant we monkeypatched (tidy, in case of re-import)
    _self._TICK_SECONDS = 1.0

    print("scheduler.py self-test OK")
