//! Zone transfers, `AXFR` and `IXFR=SERIAL` (D212): over TCP, the records shown as they arrive, whatever the zone
//! is, as `kdig` does. What `dedens-net`'s transfer client (D210) refuses to load, a diagnosis shows: a primary that
//! breaks the protocol is the thing to see.
//!
//! The query and the connection are `dedens_net::transfer`'s; the end of the response, which a secondary finds by
//! checking the whole sequence, is found here by the SOA records alone (RFC 5936 §2.2, RFC 1995 §4).

use std::time::Instant;

use anyhow::{anyhow, bail};
use dedens_net::io::{Compio, Io as _};
use dedens_net::tcp::frame;
use dedens_net::transfer::stream::ixfr_soa;
use dedens_net::transfer::{Limit, Limits, Tcp, TransferError, after, draw_id, query, signed};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Rcode, Record, RecordType};
use dedens_scenario::{
    ExchangeReport, Id, RecordReport, Report, TransferReport, Transport, TsigReport,
};
use dedens_tsig::ResponseVerifier;

use super::{Endpoint, Job, Usage};
use crate::trace::Trail;

/// The most records kept to show: past it the transfer stops, as a zone that size is not one to read on a terminal
/// and memory is not the primary's to fill.
const MAX_RECORDS: usize = 1 << 21;

/// Whether `job` is a transfer.
pub(super) fn is(job: &Job) -> bool {
    matches!(job.qtype, RecordType::AXFR | RecordType::IXFR)
}

/// Refuses what a transfer cannot honour, before any query: it goes over TCP to a plain server, with the query a
/// transfer is (RFC 5936 §2.1: no EDNS, no recursion), of one zone.
///
/// # Errors
///
/// A [`Usage`] error naming what conflicts.
pub(super) fn check(job: &Job, endpoint: &Endpoint) -> Result<(), Usage> {
    if !is(job) {
        return Ok(());
    }
    let id = &job.id;
    let refuse = |what: &str| Err(Usage(anyhow!("{id}: a zone transfer goes with {what}")));
    if job.qtype == RecordType::IXFR && job.ixfr.is_none() {
        return Err(Usage(anyhow!(
            "{id}: IXFR needs the serial it asks from: IXFR=SERIAL"
        )));
    }
    if job.qclass != Class::IN {
        return refuse("class IN only");
    }
    if job.names.len() > 1 {
        return refuse("no +search");
    }
    if !endpoint.plain() {
        return refuse(
            "a plain @server, not tls://, quic://, https://, coap://, sdns:// or +odoh-proxy",
        );
    }
    if job.judge.is_some() || job.expect.is_some() {
        return refuse("no +validate and no expectation");
    }
    let allowed = dedens_scenario::Options {
        time: job.options.time,
        ..dedens_scenario::Options::default()
    };
    if job.options != allowed {
        return refuse("no query option but +time");
    }
    Ok(())
}

/// Transfers the zone of `job` from `endpoint`: what came, with the error that ended it early.
pub(super) async fn run(job: &Job, endpoint: &Endpoint, id: Id) -> Trail {
    let mut transfer = Transfer::default();
    let started = Instant::now();
    let result = fetch(job, endpoint, id, &mut transfer).await;
    let error = result.err();
    let report = transfer.report.take().map(|mut report| {
        report.exchange = Some(ExchangeReport {
            server: endpoint.server.addr,
            transport: Transport::Tcp,
            rtt_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            sends: 1,
            query_size: transfer.query_size,
            http: None,
            doc_path: None,
            dnscrypt: None,
            tsig: transfer.tsig.take(),
        });
        report.transfer = Some(TransferReport {
            messages: transfer.messages,
        });
        (report, std::mem::take(&mut transfer.wire))
    });
    (report.into_iter().collect(), error)
}

/// What came of a transfer, as far as it went.
#[derive(Default)]
struct Transfer {
    /// From the first message; the records of all are in its answer section.
    report: Option<Report>,
    /// The messages as they came, each with its length in front (RFC 1035 §4.2.2): what `--save-wire` writes.
    wire: Vec<u8>,
    query_size: usize,
    messages: usize,
    /// The serial of the first record, the SOA the response closes on.
    serial: Option<u32>,
    /// The SOA records seen: the one that closes the response comes at an odd count, as the others come in pairs
    /// (RFC 1995 §4).
    soas: usize,
    records: usize,
    /// What became of the TSIG of the stream, when signed.
    tsig: Option<TsigReport>,
}

/// Asks, then reads the response into `transfer`.
async fn fetch(
    job: &Job,
    endpoint: &Endpoint,
    id: Id,
    transfer: &mut Transfer,
) -> anyhow::Result<()> {
    let io = Compio;
    let limits = Limits::default();
    let zone = job.names[0].clone();
    let query_id = draw_id(&io)?;
    let authority = job.ixfr.map(|serial| ixfr_soa(&zone, serial));
    let (wire, mut verifier) = signed(
        &io,
        query(&zone, job.qtype, authority, query_id),
        job.key.as_ref(),
    )?;
    transfer.query_size = wire.len();
    let idle = job.options.exchange().timeout;
    let mut tcp = Tcp::open(
        &io,
        endpoint.server.addr,
        &wire,
        after(&io, limits.time),
        idle,
    )
    .await?;
    loop {
        let message = tcp.next().await?;
        let decoded = Message::decode(&message).map_err(|e| anyhow!("a malformed message: {e}"))?;
        let header = &decoded.message.header;
        if header.id != query_id || !header.flags.contains(Flags::QR) {
            bail!("a message that is not the response to the query");
        }
        transfer.messages += 1;
        transfer.wire.extend(frame(&message).unwrap_or_default());
        let first = transfer.messages == 1;
        let report = transfer.report.get_or_insert_with(|| {
            let mut report = Report::new(id.clone(), &decoded, 0);
            report.answer.clear();
            // The verdict of the stream is `exchange.tsig`; the record is a MAC, not data.
            report.additional.retain(|record| record.rtype != "TSIG");
            report
        });
        if !first {
            report
                .violations
                .extend(decoded.violations.iter().map(ToString::to_string));
        }
        report.size += message.len();
        // A message that does not verify is not shown, nor are those after it: the transfer ends there, failed.
        if let Some(Err(error)) = verifier
            .as_mut()
            .map(|verifier| verifier.verify(&message, io.unix_time()))
        {
            report.failures.push(format!("TSIG: {error}"));
            transfer.tsig = Some(TsigReport {
                verified: false,
                error: Some(error.to_string()),
            });
            return Ok(());
        }
        let rcode = decoded.message.rcode();
        if rcode != Rcode::NOERROR {
            if first {
                return Ok(());
            }
            bail!("message {} answers {rcode}", transfer.messages);
        }
        let ended = transfer.absorb(&decoded.message.answer, job.qtype)?;
        if transfer.records > MAX_RECORDS {
            bail!("past {MAX_RECORDS} records: not a zone to show");
        }
        if ended {
            transfer.tsig = verifier.map(ResponseVerifier::finish).map(|end| {
                if let Err(error) = &end
                    && let Some(report) = &mut transfer.report
                {
                    report.failures.push(format!("TSIG: {error}"));
                }
                TsigReport {
                    verified: end.is_ok(),
                    error: end.err().map(|error| error.to_string()),
                }
            });
            return Ok(());
        }
    }
}

impl Transfer {
    /// Adds the `answer` records of a message to the report, up to the closing SOA: whether the response ends
    /// there. Records after it are a violation, not shown.
    ///
    /// # Errors
    ///
    /// The first record is not an SOA.
    fn absorb(&mut self, answer: &[Record<'_>], qtype: RecordType) -> anyhow::Result<bool> {
        let first = self.records == 0;
        let Some(report) = &mut self.report else {
            return Ok(false);
        };
        for (index, record) in answer.iter().enumerate() {
            let soa = match record.data() {
                RData::Soa(soa) if record.rtype() == RecordType::SOA => Some(soa.serial),
                _ => None,
            };
            if self.records == 0 && soa.is_none() {
                bail!("the first record of the response is not an SOA");
            }
            report.answer.push(RecordReport::new(record));
            self.records += 1;
            let Some(serial) = soa else { continue };
            let closing = self.serial == Some(serial) && self.soas % 2 == 1;
            self.serial.get_or_insert(serial);
            self.soas += 1;
            if closing && self.soas > 1 {
                if index + 1 < answer.len() {
                    report
                        .violations
                        .push("records after the closing SOA".to_owned());
                }
                return Ok(true);
            }
        }
        // An IXFR answered by one SOA: the primary's serial is the client's (RFC 1995 §4).
        Ok(first && qtype == RecordType::IXFR && answer.len() == 1)
    }
}

/// Whether `error` is a primary that did not answer: its refusal, its silence, or the connection closed.
pub(super) fn silent(error: &TransferError) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, ConnectionReset};
    match error {
        TransferError::Connect(e) => matches!(e.kind(), ConnectionRefused | ConnectionReset),
        TransferError::Closed | TransferError::Limit(Limit::Time | Limit::Idle) => true,
        _ => false,
    }
}
