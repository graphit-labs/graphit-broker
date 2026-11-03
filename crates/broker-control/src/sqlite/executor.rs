use super::{
    Result, SqliteControlConfig, SqliteControlError, config, files::PrivateDatabase, schema,
};
use rusqlite::{Connection, InterruptHandle, OpenFlags, Transaction, TransactionBehavior};
use std::{
    sync::{
        Arc, Mutex as SyncMutex, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Instant,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const RUNNING: u8 = 1;
const COMMITTING: u8 = 2;
const COMMITTED: u8 = 3;
const CANCELLED: u8 = 4;

pub(crate) struct Work {
    end: Instant,
    closed: CancellationToken,
    stopped: AtomicBool,
    phase: AtomicU8,
    interrupt: SyncMutex<Option<InterruptHandle>>,
}
impl Work {
    fn new(end: Instant, closed: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            end,
            closed,
            stopped: AtomicBool::new(false),
            phase: AtomicU8::new(RUNNING),
            interrupt: SyncMutex::new(None),
        })
    }
    pub fn check(&self) -> Result<()> {
        if self.closed.is_cancelled() {
            return Err(SqliteControlError::Closed);
        }
        if self.stopped.load(Ordering::Acquire) || Instant::now() >= self.end {
            return Err(SqliteControlError::Deadline);
        }
        Ok(())
    }
    pub fn sql(&self, _: rusqlite::Error) -> SqliteControlError {
        self.check().err().unwrap_or(SqliteControlError::Storage)
    }
    fn cancel(&self) -> SqliteControlError {
        self.stopped.store(true, Ordering::Release);
        let previous = self
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                if phase == RUNNING {
                    Some(CANCELLED)
                } else {
                    None
                }
            })
            .unwrap_or_else(|phase| phase);
        // Handle clearing and interruption share this lock. The worker clears it
        // before releasing its connection owner, including during unwinding.
        // Thus a late cancellation cannot interrupt the next operation.
        if let Ok(handle) = self.interrupt.lock()
            && let Some(handle) = handle.as_ref()
        {
            handle.interrupt();
        }
        if matches!(previous, COMMITTING | COMMITTED) {
            SqliteControlError::OutcomeUncertain
        } else if self.closed.is_cancelled() {
            SqliteControlError::Closed
        } else {
            SqliteControlError::Deadline
        }
    }
    fn install(&self, connection: &Connection) -> Result<()> {
        *self
            .interrupt
            .lock()
            .map_err(|_| SqliteControlError::Storage)? = Some(connection.get_interrupt_handle());
        self.check()
    }
    /// Release a SELECT-only snapshot without entering the write-COMMIT phase.
    pub fn finish_read(&self, tx: Transaction<'_>) -> Result<()> {
        self.check()?;
        tx.rollback().map_err(|error| self.sql(error))?;
        self.check()
    }
    pub fn commit(&self, tx: Transaction<'_>) -> Result<()> {
        self.check()?;
        self.phase
            .compare_exchange(RUNNING, COMMITTING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SqliteControlError::Deadline)?;
        tx.commit()
            .map_err(|_| SqliteControlError::OutcomeUncertain)?;
        self.phase.store(COMMITTED, Ordering::Release);
        tracing::trace!(target: "broker_control::sqlite::commit_confirmed", "SQLite commit confirmed before caller acknowledgement");
        Ok(())
    }
}
struct ClearHandle(Arc<Work>);
impl Drop for ClearHandle {
    fn drop(&mut self) {
        if let Ok(mut handle) = self.0.interrupt.lock() {
            *handle = None;
        }
    }
}
struct Running<T> {
    work: Arc<Work>,
    job: JoinHandle<T>,
    armed: bool,
}
impl<T> Drop for Running<T> {
    fn drop(&mut self) {
        if self.armed {
            self.work.cancel();
        }
    }
}
impl<T: Send + 'static> Running<T> {
    async fn finish(mut self) -> Result<T> {
        let outcome = {
            let closed = self.work.closed.clone();
            let cancelled = std::pin::pin!(closed.cancelled());
            let selected = futures_util::future::select(&mut self.job, cancelled);
            match tokio::time::timeout_at(self.work.end.into(), selected).await {
                Ok(futures_util::future::Either::Left((result, _))) => Some(result),
                Ok(futures_util::future::Either::Right(_)) | Err(_) => None,
            }
        };
        match outcome {
            Some(result) => {
                self.armed = false;
                let result = result.map_err(|_| SqliteControlError::Storage)?;
                Ok(result)
            }
            None => Err(self.work.cancel()),
        }
    }
}

pub(crate) struct State {
    pub connection: Connection,
    pub files: PrivateDatabase,
    generation: i64,
}
impl State {
    fn close(self) -> Result<()> {
        let Self {
            connection,
            files,
            generation: _,
        } = self;
        let result = connection.close().map_err(|_| SqliteControlError::Storage);
        drop(files);
        result
    }
    pub fn begin(&mut self, work: &Work) -> Result<Transaction<'_>> {
        self.begin_with_behavior(work, TransactionBehavior::Immediate)
    }
    pub fn begin_read(&mut self, work: &Work) -> Result<Transaction<'_>> {
        self.begin_with_behavior(work, TransactionBehavior::Deferred)
    }
    fn begin_with_behavior(
        &mut self,
        work: &Work,
        behavior: TransactionBehavior,
    ) -> Result<Transaction<'_>> {
        work.check()?;
        self.files.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(behavior)
            .map_err(|error| work.sql(error))?;
        work.check()?;
        let version: i64 = tx
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .map_err(|error| work.sql(error))?;
        if version != self.generation {
            return Err(SqliteControlError::SchemaRejected);
        }
        Ok(tx)
    }
}

pub(crate) struct Executor {
    owner: Arc<Mutex<Option<State>>>,
    closed: CancellationToken,
    active: SyncMutex<Option<Weak<Work>>>,
    operation: std::time::Duration,
    shutdown: std::time::Duration,
}
impl Executor {
    pub(super) fn deadline(&self, caller: Instant) -> Result<Instant> {
        config::deadline(caller, self.operation)
    }
    pub async fn open(config: SqliteControlConfig, caller: Instant) -> Result<Self> {
        let end = config::deadline(caller, config.startup)?;
        let closed = CancellationToken::new();
        let work = Work::new(end, closed.clone());
        let task_work = work.clone();
        let operation = config.operation;
        let shutdown = config.shutdown;
        let job = tokio::task::spawn_blocking(move || {
            let _clear = ClearHandle(task_work.clone());
            task_work.check()?;
            let files = PrivateDatabase::prepare(&config.path)?;
            task_work.check()?;
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
            let mut connection = Connection::open_with_flags(&files.path, flags)
                .map_err(|_| SqliteControlError::Connection)?;
            task_work.install(&connection)?;
            connection
                .busy_timeout(std::time::Duration::from_millis(5000))
                .map_err(|error| task_work.sql(error))?;
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .map_err(|error| task_work.sql(error))?;
            connection
                .pragma_update(None, "trusted_schema", "OFF")
                .map_err(|error| task_work.sql(error))?;
            schema::initialize(&mut connection, &task_work)?;
            let mode: String = loop {
                task_work.check()?;
                match connection
                    .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                {
                    Ok(mode) => break mode,
                    // Simultaneous starters can contend for the journal-mode
                    // lock even after the schema transaction has committed.
                    // Retry this idempotent pragma only, never the transaction.
                    Err(error)
                        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) =>
                    {
                        std::thread::sleep(
                            end.saturating_duration_since(Instant::now())
                                .min(std::time::Duration::from_millis(10)),
                        );
                    }
                    Err(error) => return Err(task_work.sql(error)),
                }
            };
            let fk: i64 = connection
                .pragma_query_value(None, "foreign_keys", |row| row.get(0))
                .map_err(|error| task_work.sql(error))?;
            let busy: i64 = connection
                .pragma_query_value(None, "busy_timeout", |row| row.get(0))
                .map_err(|error| task_work.sql(error))?;
            if mode != "wal" || fk != 1 || busy != 5000 {
                return Err(SqliteControlError::Connection);
            }
            files.validate()?;
            let generation = connection
                .pragma_query_value(None, "schema_version", |row| row.get(0))
                .map_err(|error| task_work.sql(error))?;
            Ok(State {
                connection,
                files,
                generation,
            })
        });
        let state = Running {
            work,
            job,
            armed: true,
        }
        .finish()
        .await??;
        Ok(Self {
            owner: Arc::new(Mutex::new(Some(state))),
            closed,
            active: SyncMutex::new(None),
            operation,
            shutdown,
        })
    }
    pub async fn execute<T, F>(&self, caller: Instant, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut State, &Work) -> Result<T> + Send + 'static,
    {
        if self.closed.is_cancelled() {
            return Err(SqliteControlError::Closed);
        }
        let end = config::deadline(caller, self.operation)?;
        let acquisition = tokio::time::timeout_at(end.into(), self.owner.clone().lock_owned());
        let mut owner = match futures_util::future::select(
            std::pin::pin!(acquisition),
            std::pin::pin!(self.closed.cancelled()),
        )
        .await
        {
            futures_util::future::Either::Left((Ok(owner), _)) => owner,
            futures_util::future::Either::Left((Err(_), _)) => {
                return Err(SqliteControlError::Deadline);
            }
            futures_util::future::Either::Right(_) => return Err(SqliteControlError::Closed),
        };
        let work = Work::new(end, self.closed.clone());
        let state = owner.as_mut().ok_or(SqliteControlError::Closed)?;
        work.install(&state.connection)?;
        *self
            .active
            .lock()
            .map_err(|_| SqliteControlError::Storage)? = Some(Arc::downgrade(&work));
        let task_work = work.clone();
        let job = tokio::task::spawn_blocking(move || {
            let _clear = ClearHandle(task_work.clone());
            let result = match owner.as_mut() {
                Some(state) => task_work.check().and_then(|()| f(state, &task_work)),
                None => Err(SqliteControlError::Closed),
            };
            if owner
                .as_ref()
                .is_some_and(|state| !state.connection.is_autocommit())
            {
                // A failed rollback must never return an in-transaction owner.
                owner.take();
            }
            // Retain the owner in the result until the caller disarms cancel.
            (owner, result)
        });
        let (_owner, result) = Running {
            work,
            job,
            armed: true,
        }
        .finish()
        .await?;
        result
    }
    pub fn shutdown(
        &self,
        caller: Instant,
    ) -> impl std::future::Future<Output = Result<()>> + Send + '_ {
        self.stop();
        async move {
            let (end, mut expired) = match config::deadline(caller, self.shutdown) {
                Ok(end) => (end, None),
                Err(error) => (caller, Some(error)),
            };
            let acquire = self.owner.clone().lock_owned();
            tokio::pin!(acquire);
            let mut owner = if expired.is_some() {
                acquire.await
            } else {
                match tokio::time::timeout_at(end.into(), &mut acquire).await {
                    Ok(owner) => owner,
                    Err(_) => {
                        expired = Some(SqliteControlError::Deadline);
                        // Admission is closed. Retain the same acquisition until
                        // the active native worker releases the physical owner.
                        acquire.await
                    }
                }
            };
            let Some(state) = owner.take() else {
                return expired.map_or(Ok(()), Err);
            };
            // The blocking close retains the ownership guard. Borrow its join
            // in timeout_at so the expired operation cannot detach cleanup.
            let mut job = tokio::task::spawn_blocking(move || {
                let result = state.close();
                drop(owner);
                result
            });
            let result = match tokio::time::timeout_at(end.into(), &mut job).await {
                Ok(result) => result,
                Err(_) => {
                    expired.get_or_insert(SqliteControlError::Deadline);
                    job.await
                }
            };
            let result = result.map_err(|_| SqliteControlError::Storage)?;
            match expired {
                Some(error) => Err(error),
                None => result,
            }
        }
    }

    fn stop(&self) {
        self.closed.cancel();
        if let Ok(active) = self.active.lock()
            && let Some(work) = active.as_ref().and_then(Weak::upgrade)
        {
            work.cancel();
        }
    }
}
impl Drop for Executor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowLimits;
    use std::{num::NonZeroUsize, sync::mpsc, time::Duration};
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    async fn fixture() -> (tempfile::TempDir, Arc<Executor>) {
        let root = tempfile::tempdir().unwrap();
        let n = NonZeroUsize::new(128).unwrap();
        let cfg = SqliteControlConfig::new(
            root.path().join("private").join("broker.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n,
                request_bytes: n,
                continuation_bytes: NonZeroUsize::new(1024).unwrap(),
            },
        )
        .unwrap();
        let executor = Arc::new(Executor::open(cfg, end()).await.unwrap());
        (root, executor)
    }
    #[tokio::test]
    async fn sqlite_connection_pragmas_and_foreign_key_enforcement_are_real() {
        let (_root, executor) = fixture().await;
        executor.execute(end(), |owner,work| {
            assert_eq!(owner.connection.pragma_query_value::<i64,_>(None,"foreign_keys",|r|r.get(0)).unwrap(),1);
            assert_eq!(owner.connection.pragma_query_value::<i64,_>(None,"busy_timeout",|r|r.get(0)).unwrap(),5000);
            assert_eq!(owner.connection.pragma_query_value::<String,_>(None,"journal_mode",|r|r.get(0)).unwrap(),"wal");
            let tx=owner.begin(work)?;
            assert_eq!(tx.execute("INSERT INTO role_permissions(role,action) VALUES('not-a-role','users.write')",[]).unwrap_err().sqlite_error_code(),Some(rusqlite::ErrorCode::ConstraintViolation));
            work.commit(tx)
        }).await.unwrap();
        executor.shutdown(end()).await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_dropped_long_sql_rolls_back_before_owner_reuse() {
        let (_root, executor) = fixture().await;
        let started = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let executor = executor.clone();
            let started = started.clone();
            async move {
                executor.execute(end(),move|owner,work| {
                let tx=owner.begin(work)?;
                tx.execute("INSERT INTO roles(name,created_at) VALUES('cancelled-role',0)",[]).map_err(|e|work.sql(e))?;
                started.store(true,Ordering::Release);
                let _:i64=tx.query_row("WITH RECURSIVE numbers(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM numbers WHERE x<1000000000) SELECT sum(x) FROM numbers",[],|r|r.get(0)).map_err(|e|work.sql(e))?;
                work.commit(tx)
            }).await
            }
        });
        let wait = end();
        while !started.load(Ordering::Acquire) {
            assert!(Instant::now() < wait);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        let start = Instant::now();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        executor.execute(end(),|owner,work| {
            let tx=owner.begin(work)?;
            let count:i64=tx.query_row("SELECT COUNT(*) FROM roles WHERE name='cancelled-role'",[],|r|r.get(0)).map_err(|e|work.sql(e))?;
            assert_eq!(count,0);
            let sum:i64=tx.query_row("WITH RECURSIVE numbers(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM numbers WHERE x<10000) SELECT sum(x) FROM numbers",[],|r|r.get(0)).map_err(|e|work.sql(e))?;
            assert_eq!(sum,50005000);
            work.commit(tx)
        }).await.unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "native SQL interrupt must reap the actual worker"
        );
        executor.shutdown(end()).await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_deferred_read_keeps_snapshot_without_reserving_writer() {
        let (root, first) = fixture().await;
        let cap = NonZeroUsize::new(128).unwrap();
        let cfg = SqliteControlConfig::new(
            root.path().join("private/broker.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: cap,
                request_bytes: cap,
                continuation_bytes: NonZeroUsize::new(1024).unwrap(),
            },
        )
        .unwrap();
        let second = Executor::open(cfg, end()).await.unwrap();
        let (observed, seen) = mpsc::sync_channel(1);
        let (release, await_release) = mpsc::sync_channel(1);
        let read = tokio::spawn({
            let first = first.clone();
            async move {
                first
                    .execute(end(), move |owner, work| {
                        let tx = owner.begin_read(work)?;
                        let select = "SELECT COUNT(*) FROM roles WHERE name='after-read-snapshot'";
                        let before: i64 = tx
                            .query_row(select, [], |row| row.get(0))
                            .map_err(|error| work.sql(error))?;
                        assert_eq!(before, 0);
                        observed.send(()).unwrap();
                        await_release.recv_timeout(Duration::from_secs(10)).unwrap();
                        let during: i64 = tx
                            .query_row(select, [], |row| row.get(0))
                            .map_err(|error| work.sql(error))?;
                        assert_eq!(during, before);
                        work.finish_read(tx)
                    })
                    .await
            }
        });
        tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(2)).unwrap())
            .await
            .unwrap();
        second
            .execute(end(), |owner, work| {
                let tx = owner.begin(work)?;
                tx.execute(
                    "INSERT INTO roles(name,created_at) VALUES('after-read-snapshot',0)",
                    [],
                )
                .map_err(|error| work.sql(error))?;
                work.commit(tx)
            })
            .await
            .unwrap();
        release.send(()).unwrap();
        read.await.unwrap().unwrap();
        first
            .execute(end(), |owner, work| {
                let tx = owner.begin_read(work)?;
                let after: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM roles WHERE name='after-read-snapshot'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|error| work.sql(error))?;
                assert_eq!(after, 1);
                work.finish_read(tx)
            })
            .await
            .unwrap();
        second.shutdown(end()).await.unwrap();
        first.shutdown(end()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_read_without_ack_is_deadline_and_owner_reusable() {
        let (_root, executor) = fixture().await;
        let (observed, seen) = mpsc::sync_channel(1);
        let (release, await_release) = mpsc::sync_channel(1);
        let task = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(
                        Instant::now() + Duration::from_millis(500),
                        move |owner, work| {
                            let tx = owner.begin_read(work)?;
                            let count: i64 = tx
                                .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
                                .map_err(|error| work.sql(error))?;
                            work.finish_read(tx)?;
                            observed.send(count).unwrap();
                            await_release.recv_timeout(Duration::from_secs(3)).unwrap();
                            Ok(count)
                        },
                    )
                    .await
            }
        });
        let count =
            tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(2)).unwrap())
                .await
                .unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SqliteControlError::Deadline
        );
        release.send(()).unwrap();
        executor
            .execute(end(), move |owner, work| {
                let tx = owner.begin_read(work)?;
                let current: i64 = tx
                    .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
                    .map_err(|error| work.sql(error))?;
                assert_eq!(current, count);
                work.finish_read(tx)
            })
            .await
            .unwrap();
        executor.shutdown(end()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_read_without_ack_is_closed_and_shutdown_joins_owner() {
        use std::{future::Future, task::Poll};
        let (_root, executor) = fixture().await;
        let (observed, seen) = mpsc::sync_channel(1);
        let (release, await_release) = mpsc::sync_channel(1);
        let task = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(end(), move |owner, work| {
                        let tx = owner.begin_read(work)?;
                        let _: i64 = tx
                            .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
                            .map_err(|error| work.sql(error))?;
                        work.finish_read(tx)?;
                        observed.send(()).unwrap();
                        await_release.recv_timeout(Duration::from_secs(3)).unwrap();
                        Ok(())
                    })
                    .await
            }
        });
        tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(2)).unwrap())
            .await
            .unwrap();
        executor.stop();
        assert_eq!(task.await.unwrap().unwrap_err(), SqliteControlError::Closed);
        let mut close = std::pin::pin!(executor.shutdown(end()));
        std::future::poll_fn(|cx| {
            assert!(close.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        close.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_cancelled_read_rolls_back_before_owner_reuse() {
        let (_root, executor) = fixture().await;
        let (observed, seen) = mpsc::sync_channel(1);
        let (release, await_release) = mpsc::sync_channel(1);
        let task = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(end(), move |owner, work| {
                        let tx = owner.begin_read(work)?;
                        let _: i64 = tx
                            .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
                            .map_err(|error| work.sql(error))?;
                        observed.send(()).unwrap();
                        await_release.recv_timeout(Duration::from_secs(3)).unwrap();
                        work.finish_read(tx)
                    })
                    .await
            }
        });
        tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(2)).unwrap())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        executor
            .execute(end(), |owner, work| {
                let tx = owner.begin_read(work)?;
                let _: i64 = tx
                    .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
                    .map_err(|error| work.sql(error))?;
                work.finish_read(tx)
            })
            .await
            .unwrap();
        executor.shutdown(end()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_commit_without_ack_is_uncertain_and_shutdown_joins_owner() {
        let (_root, executor) = fixture().await;
        let (committed, seen) = mpsc::sync_channel(1);
        let (release, await_release) = mpsc::sync_channel(1);
        let task = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor.execute(Instant::now()+Duration::from_millis(150),move|owner,work| {
                let tx=owner.begin(work)?;
                tx.execute("INSERT INTO roles(name,created_at) VALUES('committed-before-ack',0)",[]).map_err(|e|work.sql(e))?;
                work.commit(tx)?;
                committed.send(()).unwrap();
                await_release.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok("withheld result")
            }).await
            }
        });
        tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(2)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SqliteControlError::OutcomeUncertain
        );
        {
            use std::{future::Future, task::Poll};
            let mut abandoned = std::pin::pin!(executor.shutdown(end()));
            std::future::poll_fn(|cx| {
                assert!(abandoned.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        let close = tokio::spawn({
            let executor = executor.clone();
            async move { executor.shutdown(end()).await }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !close.is_finished(),
            "close must join the still-owned worker"
        );
        release.send(()).unwrap();
        close.await.unwrap().unwrap();
        assert_eq!(
            executor.execute(end(), |_, _| Ok(())).await.unwrap_err(),
            SqliteControlError::Closed
        );
    }
    #[tokio::test]
    async fn sqlite_pending_transaction_is_quarantined_instead_of_reused() {
        let (_root, executor) = fixture().await;
        let result=executor.execute::<(),_>(end(),|owner,work| {
            owner.connection.execute_batch("BEGIN IMMEDIATE; INSERT INTO roles(name,created_at) VALUES('uncommitted',0)").map_err(|e|work.sql(e))?;
            Err(SqliteControlError::Storage)
        }).await;
        assert_eq!(result.unwrap_err(), SqliteControlError::Storage);
        assert_eq!(
            executor.execute(end(), |_, _| Ok(())).await.unwrap_err(),
            SqliteControlError::Closed
        );
        executor.shutdown(end()).await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_expired_shutdown_drains_active_owner_and_physically_reopens() {
        let (root, executor) = fixture().await;
        let (entered, seen) = mpsc::sync_channel(1);
        let (release, held) = mpsc::sync_channel(1);
        let operation = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(end(), move |owner, work| {
                        let tx = owner.begin(work)?;
                        tx.execute(
                            "INSERT INTO roles(name,created_at)VALUES('close-expired',0)",
                            [],
                        )
                        .map_err(|e| work.sql(e))?;
                        work.commit(tx)?;
                        entered.send(()).unwrap();
                        held.recv_timeout(Duration::from_secs(3)).unwrap();
                        Ok(())
                    })
                    .await
            }
        });
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        let original = Instant::now() - Duration::from_millis(1);
        let mut close = std::pin::pin!(executor.shutdown(original));
        std::future::poll_fn(|cx| {
            use std::future::Future;
            assert!(
                close.as_mut().poll(cx).is_pending(),
                "expired shutdown must retain actual SQL owner"
            );
            std::task::Poll::Ready(())
        })
        .await;
        assert!(executor.closed.is_cancelled());
        release.send(()).unwrap();
        assert_eq!(close.await.unwrap_err(), SqliteControlError::Deadline);
        let _ = operation.await.unwrap();
        assert!(
            executor.owner.lock().await.is_none(),
            "physical close consumed owner before returning Deadline"
        );
        let cap = NonZeroUsize::new(128).unwrap();
        let cfg = SqliteControlConfig::new(
            root.path().join("private/broker.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: cap,
                request_bytes: cap,
                continuation_bytes: NonZeroUsize::new(1024).unwrap(),
            },
        )
        .unwrap();
        let reopened = Executor::open(cfg, end()).await.unwrap();
        reopened
            .execute(end(), |owner, work| {
                let tx = owner.begin(work)?;
                assert_eq!(
                    tx.query_row(
                        "SELECT count(*) FROM roles WHERE name='close-expired'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .map_err(|e| work.sql(e))?,
                    1
                );
                work.commit(tx)
            })
            .await
            .unwrap();
        reopened.shutdown(end()).await.unwrap();
    }
    #[tokio::test]
    async fn sqlite_other_owner_and_peer_close_preserve_live_wal_and_fresh_reads() {
        let (root, first) = fixture().await;
        let path = root.path().join("private/broker.db");
        let cap = NonZeroUsize::new(128).unwrap();
        let cfg = SqliteControlConfig::new(
            path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: cap,
                request_bytes: cap,
                continuation_bytes: NonZeroUsize::new(1024).unwrap(),
            },
        )
        .unwrap();
        let second = Executor::open(cfg, end()).await.unwrap();
        first
            .execute(end(), |owner, work| {
                let tx = owner.begin(work)?;
                tx.execute(
                    "INSERT INTO roles(name,created_at)VALUES('live-cooperative',0)",
                    [],
                )
                .map_err(|e| work.sql(e))?;
                work.commit(tx)
            })
            .await
            .unwrap();
        #[cfg(unix)]
        let sidecars: Vec<_> = ["broker.db-wal", "broker.db-shm"]
            .iter()
            .map(|name| {
                use std::os::unix::fs::MetadataExt;
                let path = root.path().join("private").join(name);
                (path.clone(), std::fs::symlink_metadata(path).unwrap().ino())
            })
            .collect();
        second.shutdown(end()).await.unwrap();
        drop(second);
        first
            .execute(end(), |owner, work| {
                let tx = owner.begin(work)?;
                assert_eq!(
                    tx.query_row(
                        "SELECT count(*) FROM roles WHERE name='live-cooperative'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .map_err(|e| work.sql(e))?,
                    1
                );
                work.commit(tx)
            })
            .await
            .unwrap();
        let peer = Connection::open(&path).unwrap();
        assert_eq!(
            peer.execute("DELETE FROM roles WHERE name='live-cooperative'", [])
                .unwrap(),
            1
        );
        drop(peer);
        #[cfg(unix)]
        for (path, inode) in sidecars {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::symlink_metadata(path).ok().map(|m| m.ino()),
                Some(inode),
                "a live SQLite owner keeps its WAL/SHM after another owner and peer close"
            );
        }
        first
            .execute(end(), |owner, work| {
                let tx = owner.begin(work)?;
                assert_eq!(
                    tx.query_row(
                        "SELECT count(*) FROM roles WHERE name='live-cooperative'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .map_err(|e| work.sql(e))?,
                    0
                );
                work.commit(tx)
            })
            .await
            .unwrap();
        first.shutdown(end()).await.unwrap();
    }
    #[test]
    fn sqlite_shutdown_timeout_retains_queued_native_close_join() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_root, executor) = fixture().await;
            let (entered, seen) = mpsc::sync_channel(1);
            let (release, held) = mpsc::sync_channel(1);
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                held.recv_timeout(Duration::from_secs(3)).unwrap();
            });
            seen.recv_timeout(Duration::from_secs(2)).unwrap();
            let original = Instant::now() + Duration::from_millis(25);
            let mut close = std::pin::pin!(executor.shutdown(original));
            std::future::poll_fn(|cx| {
                use std::future::Future;
                assert!(close.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            tokio::time::sleep(Duration::from_millis(40)).await;
            std::future::poll_fn(|cx| {
                use std::future::Future;
                assert!(
                    close.as_mut().poll(cx).is_pending(),
                    "deadline must not detach queued physical close"
                );
                std::task::Poll::Ready(())
            })
            .await;
            assert!(
                executor.owner.try_lock().is_err(),
                "queued close retains owner guard"
            );
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert_eq!(close.await.unwrap_err(), SqliteControlError::Deadline);
            assert!(executor.owner.lock().await.is_none());
        });
    }
    #[tokio::test]
    async fn sqlite_known_commit_survives_later_clock_observation() {
        use std::{future::Future, task::Poll};
        let (_root, executor) = fixture().await;
        let (committed, seen) = mpsc::sync_channel(1);
        let caller = Instant::now() + Duration::from_millis(500);
        let mut operation = std::pin::pin!(executor.execute(caller, move |owner, work| {
            let tx = owner.begin(work)?;
            tx.execute(
                "INSERT INTO roles(name,created_at) VALUES('known-commit',0)",
                [],
            )
            .map_err(|e| work.sql(e))?;
            work.commit(tx)?;
            committed.send(()).unwrap();
            Ok(7)
        }));
        std::future::poll_fn(|cx| {
            assert!(operation.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Keep the single-thread async runtime from observing the result until
        // its clock is past the deadline. The real native job has committed.
        seen.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(
            caller.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert_eq!(operation.await.unwrap(), 7);
        let close = executor.shutdown(end());
        assert_eq!(
            executor.execute(end(), |_, _| Ok(())).await.unwrap_err(),
            SqliteControlError::Closed
        );
        close.await.unwrap();
    }
}
